// ClassInformer.java
// Ghidra script mimicking IDA Pro's ClassInformer plugin.
// Fast MSVC RTTI recovery: vftables, class names, inheritance.
//
// INSTALL: Copy to <GhidraInstall>/Ghidra/Features/Base/ghidra_scripts/
// RUN    : Script Manager → ClassInformer → Run
//
//@author vsaint1
//@category C++
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.List;

public class ClassInformer extends GhidraScript {


    private boolean is64bit;
    private int     ptrSize;
    private long    imageBase;
    private DataTypeManager dtm;

    private final Map<Long, String>        tdToName  = new HashMap<>(8192);
    private final Map<Long, COLInfo>       colMap    = new LinkedHashMap<>(4096);
    private final Map<String, Set<String>> hierarchy = new LinkedHashMap<>(4096);
    private final List<Object[]>           tableRows = new ArrayList<>(4096);

    // absIndex: absolute ptr value → slots holding it  (vftable backptr lookup)
    // rvaIndex: 32-bit DWORD value → slots holding it  (64-bit RVA field lookup)
    private final Map<Long, List<Long>> absIndex = new HashMap<>(1 << 18);
    private final Map<Long, List<Long>> rvaIndex = new HashMap<>(1 << 18);

    private static final class COLInfo {
        final long   colAddr, vftableAddr;
        final String className;
        final int    offset;
        COLInfo(long c, long v, String n, int o) {
            colAddr = c; vftableAddr = v; className = n; offset = o;
        }
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------
    @Override
    public void run() throws Exception {
        dtm       = currentProgram.getDataTypeManager();
        is64bit   = currentProgram.getDefaultPointerSize() == 8;
        ptrSize   = is64bit ? 8 : 4;
        imageBase = currentProgram.getImageBase().getOffset();

        println("[ClassInformer] " + (is64bit ? "64" : "32")
                + "-bit  imageBase=0x" + Long.toHexString(imageBase));

        monitor.setMessage("ClassInformer [1/4]: sweeping memory...");
        sweepMemory();
        println("[ClassInformer] TypeDescriptors : " + tdToName.size());
        if (tdToName.isEmpty()) {
            println("[ClassInformer] No MSVC RTTI found.");
            return;
        }

        monitor.setMessage("ClassInformer [2/4]: finding COLs and vftables...");
        findCOLsAndVftables();
        println("[ClassInformer] vftables found  : " + colMap.size());
        if (colMap.isEmpty()) return;

        monitor.setMessage("ClassInformer [3/4]: parsing class hierarchy...");
        for (COLInfo col : colMap.values()) {
            if (monitor.isCancelled()) break;
            parseHierarchy(col);
        }

        monitor.setMessage("ClassInformer [4/4]: applying labels...");
        applyLabelsAndStructures();

        for (COLInfo col : colMap.values()) {
            Set<String> bases = hierarchy.getOrDefault(col.className, Collections.emptySet());
            tableRows.add(new Object[]{
                0,
                "0x" + Long.toHexString(col.vftableAddr),
                col.className,
                col.offset,
                0,   // vft entries — filled below
                String.join(", ", bases)
            });
        }
        tableRows.sort((a, b) -> ((String) a[2]).compareToIgnoreCase((String) b[2]));
        for (int i = 0; i < tableRows.size(); i++) {
            tableRows.get(i)[0] = i + 1;
            tableRows.get(i)[4] = countVftableEntries((String) tableRows.get(i)[1]);
        }

        println("[ClassInformer] Done – " + tableRows.size() + " vftables recovered.");
        SwingUtilities.invokeLater(this::showGui);
    }

    private void sweepMemory() throws Exception {
        Memory mem = currentProgram.getMemory();

        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || monitor.isCancelled()) continue;

            long blockBase = block.getStart().getOffset();
            int  blockLen  = (int) Math.min(block.getSize(), Integer.MAX_VALUE);
            if (blockLen < 8) continue;

            byte[] bytes = new byte[blockLen];
            try { mem.getBytes(block.getStart(), bytes); }
            catch (Exception e) { continue; }

            ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

            // 4-byte pass → rvaIndex
            for (int i = 0; i <= blockLen - 4; i += 4) {
                long rva = buf.getInt(i) & 0xFFFFFFFFL;
                if (rva != 0)
                    rvaIndex.computeIfAbsent(rva, k -> new ArrayList<>(2))
                            .add(blockBase + i);
            }

            // ptr-size pass → absIndex + TypeDescriptor detection
            for (int i = 0; i <= blockLen - ptrSize; i += ptrSize) {
                if (monitor.isCancelled()) return;
                long ptrVal   = readBufPtr(buf, i);
                long slotAddr = blockBase + i;
                if (ptrVal != 0)
                    absIndex.computeIfAbsent(ptrVal, k -> new ArrayList<>(2))
                            .add(slotAddr);

                // ".?A" at nameOffset = i + ptrSize*2
                int nameOff = i + ptrSize * 2;
                if (nameOff + 3 < blockLen
                        && bytes[nameOff]   == '.'
                        && bytes[nameOff+1] == '?'
                        && bytes[nameOff+2] == 'A'
                        && isValidAbsAddr(ptrVal)
                        && !tdToName.containsKey(slotAddr)) {
                    tdToName.put(slotAddr, extractName(bytes, nameOff));
                }
            }
        }
    }


    private void findCOLsAndVftables() throws Exception {
        for (Map.Entry<Long, String> tdEntry : tdToName.entrySet()) {
            if (monitor.isCancelled()) break;
            long   tdAddr    = tdEntry.getKey();
            String className = tdEntry.getValue();

            // Find all slots storing a reference to this TD
            List<Long> tdRefSlots;
            if (is64bit) {
                // COL stores TD as RVA = tdAddr - imageBase
                long rva = tdAddr - imageBase;
                tdRefSlots = rvaIndex.get(rva);
            } else {
                tdRefSlots = absIndex.get(tdAddr);
            }
            if (tdRefSlots == null) continue;

            for (long slotAddr : tdRefSlots) {
                // The TD field sits at COL+0x0C
                long colBase = slotAddr - 0x0C;
                if (colBase < 0 || colMap.containsKey(colBase)) continue;
                if (!validateCOLAt(colBase, tdAddr)) continue;

                int objOffset = readInt32At(colBase + 4);

                // vftable backptr: absIndex[colBase] → slot, vftable = slot + ptrSize
                List<Long> colBackSlots = absIndex.get(colBase);
                if (colBackSlots == null) continue;

                for (long backSlot : colBackSlots) {
                    long vftableAddr = backSlot + ptrSize;
                    if (!isValidAbsAddr(vftableAddr)) continue;
                    // Extra check: first entry of vftable should point to executable code
                    if (!firstEntryIsCode(vftableAddr)) continue;
                    colMap.put(colBase,
                            new COLInfo(colBase, vftableAddr, className, objOffset));
                    break;
                }
            }
        }
    }

    /** Returns true if the first slot of the vftable points into an executable block */
    private boolean firstEntryIsCode(long vftableAddr) {
        try {
            Memory mem = currentProgram.getMemory();
            Address slot = rawAddr(vftableAddr);
            if (slot == null || !mem.contains(slot)) return false;
            long fnPtr = is64bit
                    ? mem.getLong(slot)
                    : mem.getInt(slot) & 0xFFFFFFFFL;
            if (fnPtr == 0) return false;
            Address target = rawAddr(fnPtr);
            if (target == null) return false;
            MemoryBlock blk = mem.getBlock(target);
            return blk != null && blk.isExecute();
        } catch (Exception e) { return false; }
    }

    private boolean validateCOLAt(long colBase, long expectedTdAddr) {
        try {
            Memory mem = currentProgram.getMemory();
            Address a = rawAddr(colBase);
            if (a == null || !mem.contains(a)) return false;

            int sig = mem.getInt(a);
            // Accept both 0 and 1 — some compilers emit 0 even for 64-bit
            if (sig != 0 && sig != 1) return false;

            int off = mem.getInt(a.add(4));
            if (off < 0 || off > 0xFFFF) return false;

            int cd = mem.getInt(a.add(8));
            if (cd < -0xFFFF || cd > 0xFFFF) return false;

            // TD at +0x0C must resolve to expectedTdAddr
            long storedTD = is64bit
                    ? imageBase + (mem.getInt(a.add(0x0C)) & 0xFFFFFFFFL)
                    : mem.getInt(a.add(0x0C)) & 0xFFFFFFFFL;
            if (storedTD != expectedTdAddr) return false;

            // CHD at +0x10 must point somewhere valid
            long chdAddr = is64bit
                    ? imageBase + (mem.getInt(a.add(0x10)) & 0xFFFFFFFFL)
                    : mem.getInt(a.add(0x10)) & 0xFFFFFFFFL;
            return isValidAbsAddr(chdAddr);
        } catch (Exception e) { return false; }
    }


    private void parseHierarchy(COLInfo col) {
        try {
            Memory mem = currentProgram.getMemory();
            Address colAddr = rawAddr(col.colAddr);
            if (colAddr == null) return;

            long chdRaw = is64bit
                    ? imageBase + (mem.getInt(colAddr.add(0x10)) & 0xFFFFFFFFL)
                    : mem.getInt(colAddr.add(0x10)) & 0xFFFFFFFFL;
            Address chdAddr = rawAddr(chdRaw);
            if (chdAddr == null || !mem.contains(chdAddr)) return;
            if (mem.getInt(chdAddr) != 0) return;

            int numBases = mem.getInt(chdAddr.add(8));
            if (numBases <= 1 || numBases > 4096) return;

            long baRaw = is64bit
                    ? imageBase + (mem.getInt(chdAddr.add(0x0C)) & 0xFFFFFFFFL)
                    : mem.getInt(chdAddr.add(0x0C)) & 0xFFFFFFFFL;
            Address baAddr = rawAddr(baRaw);
            if (baAddr == null || !mem.contains(baAddr)) return;

            Set<String> bases = hierarchy.computeIfAbsent(
                    col.className, k -> new LinkedHashSet<>());

            for (int i = 1; i < numBases; i++) {
                long bcdRaw = is64bit
                        ? imageBase + (mem.getInt(baAddr.add((long) i * 4)) & 0xFFFFFFFFL)
                        : mem.getInt(baAddr.add((long) i * 4)) & 0xFFFFFFFFL;
                Address bcdAddr = rawAddr(bcdRaw);
                if (bcdAddr == null || !mem.contains(bcdAddr)) continue;

                long baseTDRaw = is64bit
                        ? imageBase + (mem.getInt(bcdAddr) & 0xFFFFFFFFL)
                        : mem.getInt(bcdAddr) & 0xFFFFFFFFL;
                String baseName = tdToName.get(baseTDRaw);
                if (baseName != null && !baseName.equals(col.className))
                    bases.add(baseName);
            }
        } catch (Exception ignored) {}
    }

 
    private void applyLabelsAndStructures() throws Exception {
        for (Map.Entry<Long, String> e : tdToName.entrySet()) {
            Address a = rawAddr(e.getKey());
            if (a == null) continue;
            safeLabel(a, "RTTI_TypeDescriptor", getOrCreateNamespace(e.getValue()));
            applyTypeDescriptorType(a);
        }
        for (COLInfo col : colMap.values()) {
            Namespace ns = getOrCreateNamespace(col.className);
            Address colAddr = rawAddr(col.colAddr);
            if (colAddr != null) {
                safeLabel(colAddr, "RTTI_CompleteObjectLocator", ns);
                applyCOLDataType(colAddr);
            }
            Address vftAddr = rawAddr(col.vftableAddr);
            if (vftAddr != null) {
                safeLabel(vftAddr, "vftable", ns);
                try { safeLabel(vftAddr.subtract(ptrSize), "RTTI_COL_ptr", ns); }
                catch (Exception ignored) {}
            }
        }
    }

   
    private int countVftableEntries(String addrStr) {
        try {
            long base = Long.parseUnsignedLong(addrStr.replace("0x", ""), 16);
            Memory mem = currentProgram.getMemory();
            int count = 0;
            for (int i = 0; i < 1024; i++) {
                Address slot = rawAddr(base + (long) i * ptrSize);
                if (slot == null || !mem.contains(slot)) break;
                long ptr = is64bit ? mem.getLong(slot) : mem.getInt(slot) & 0xFFFFFFFFL;
                if (ptr == 0) break;
                Address target = rawAddr(ptr);
                if (target == null) break;
                MemoryBlock blk = mem.getBlock(target);
                if (blk == null || !blk.isExecute()) break;
                count++;
            }
            return count;
        } catch (Exception e) { return 0; }
    }


    private void showGui() {
        // Use whatever L&F Ghidra already has installed — don't override it
        JFrame frame = new JFrame("ClassInformer  \u2014  " + currentProgram.getName());
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(1100, 650);
        frame.setLocationRelativeTo(null);

        // ── Toolbar ──────────────────────────────────────────────────────
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0,
                        UIManager.getColor("Separator.foreground")),
                new EmptyBorder(4, 6, 4, 6)));

        JLabel titleLbl = new JLabel("ClassInformer");
        titleLbl.setFont(titleLbl.getFont().deriveFont(Font.BOLD, 14f));
        toolbar.add(titleLbl);
        toolbar.addSeparator(new Dimension(12, 0));

        JLabel statsLbl = new JLabel(tableRows.size() + " vftables  \u00b7  "
                + hierarchy.size() + " classes");
        statsLbl.setFont(statsLbl.getFont().deriveFont(Font.PLAIN, 12f));
        statsLbl.setForeground(UIManager.getColor("Label.disabledForeground"));
        toolbar.add(statsLbl);
        toolbar.add(Box.createHorizontalGlue());

        toolbar.add(new JLabel("Filter: "));
        JTextField filterField = new JTextField(22);
        filterField.setMaximumSize(new Dimension(280, filterField.getPreferredSize().height));
        filterField.putClientProperty("JTextField.placeholderText", "class name or base…");
        toolbar.add(filterField);
        toolbar.addSeparator(new Dimension(6, 0));

        JButton clearBtn = new JButton("✕");
        clearBtn.setToolTipText("Clear filter");
        clearBtn.setMargin(new Insets(2, 6, 2, 6));
        clearBtn.addActionListener(e -> filterField.setText(""));
        toolbar.add(clearBtn);

        // ── Table ────────────────────────────────────────────────────────
        String[] cols = { "#", "vftable", "Class Name", "Offset", "Methods", "Base Classes" };
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) {
                return (c == 0 || c == 3 || c == 4) ? Integer.class : String.class;
            }
        };
        for (Object[] row : tableRows) model.addRow(row);

        JTable table = new JTable(model);
        table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        table.setRowHeight(20);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setGridColor(UIManager.getColor("Table.gridColor") != null
                ? UIManager.getColor("Table.gridColor")
                : new Color(220, 220, 220));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setFillsViewportHeight(true);

        // Column widths
        int[] cw = { 50, 150, 300, 65, 70, 0 };
        for (int i = 0; i < cw.length - 1; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(cw[i]);
            table.getColumnModel().getColumn(i).setMaxWidth(
                    i == 0 ? 60 : i == 4 ? 90 : 9999);
        }

        // Custom cell renderer – colour the address and class name columns
        // while inheriting all other colours from the current L&F
        DefaultTableCellRenderer addrRenderer = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                if (!sel) setForeground(new Color(0, 100, 180));
                setBorder(new EmptyBorder(0, 6, 0, 6));
                return this;
            }
        };
        DefaultTableCellRenderer classRenderer = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                if (!sel) setForeground(new Color(0, 130, 0));
                setBorder(new EmptyBorder(0, 6, 0, 6));
                return this;
            }
        };
        DefaultTableCellRenderer methodRenderer = new DefaultTableCellRenderer() {
            { setHorizontalAlignment(SwingConstants.RIGHT); }
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                setBorder(new EmptyBorder(0, 6, 0, 10));
                return this;
            }
        };
        DefaultTableCellRenderer paddedRenderer = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                setBorder(new EmptyBorder(0, 6, 0, 6));
                return this;
            }
        };
        table.getColumnModel().getColumn(1).setCellRenderer(addrRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(classRenderer);
        table.getColumnModel().getColumn(4).setCellRenderer(methodRenderer);
        table.getColumnModel().getColumn(0).setCellRenderer(paddedRenderer);
        table.getColumnModel().getColumn(3).setCellRenderer(paddedRenderer);
        table.getColumnModel().getColumn(5).setCellRenderer(paddedRenderer);
        table.setDefaultRenderer(Integer.class, paddedRenderer);

        // Sortable
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            void go() {
                String t = filterField.getText().trim();
                try { sorter.setRowFilter(t.isEmpty() ? null
                        : RowFilter.regexFilter("(?i)" + t, 2, 5)); }
                catch (Exception ignored) {}
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { go(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { go(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { go(); }
        });

        // Double-click → navigate
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2) return;
                int vr = table.getSelectedRow();
                if (vr < 0) return;
                String addrStr = (String) model.getValueAt(
                        table.convertRowIndexToModel(vr), 1);
                try { goTo(rawAddr(Long.parseUnsignedLong(
                        addrStr.replace("0x", ""), 16))); }
                catch (Exception ignored) {}
            }
        });

        // Right-click context menu
        JPopupMenu popup = new JPopupMenu();
        JMenuItem miGoto    = new JMenuItem("Go to vftable");
        JMenuItem miCopyAddr = new JMenuItem("Copy address");
        JMenuItem miCopyName = new JMenuItem("Copy class name");
        popup.add(miGoto);
        popup.add(miCopyAddr);
        popup.add(miCopyName);
        popup.addSeparator();
        JMenuItem miCopyAll = new JMenuItem("Copy row");
        popup.add(miCopyAll);

        miGoto.addActionListener(e -> {
            int vr = table.getSelectedRow();
            if (vr < 0) return;
            String addrStr = (String) model.getValueAt(table.convertRowIndexToModel(vr), 1);
            try { goTo(rawAddr(Long.parseUnsignedLong(addrStr.replace("0x",""), 16))); }
            catch (Exception ignored) {}
        });
        miCopyAddr.addActionListener(e -> copyCell(table, model, 1));
        miCopyName.addActionListener(e -> copyCell(table, model, 2));
        miCopyAll.addActionListener(e -> {
            int vr = table.getSelectedRow();
            if (vr < 0) return;
            int mr = table.convertRowIndexToModel(vr);
            StringBuilder sb = new StringBuilder();
            for (int c = 0; c < model.getColumnCount(); c++) {
                if (c > 0) sb.append("\t");
                sb.append(model.getValueAt(mr, c));
            }
            copyToClipboard(sb.toString());
        });

        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybePopup(e); }
            void maybePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0) table.setRowSelectionInterval(row, row);
                popup.show(table, e.getX(), e.getY());
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());

        // ── Hierarchy / Details panel ─────────────────────────────────────
        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);

        JTextArea hierText = new JTextArea();
        hierText.setEditable(false);
        hierText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        hierText.setBorder(new EmptyBorder(6, 10, 6, 10));
        tabs.addTab("Inheritance Tree", new JScrollPane(hierText));

        JTextArea detailText = new JTextArea();
        detailText.setEditable(false);
        detailText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailText.setBorder(new EmptyBorder(6, 10, 6, 10));
        tabs.addTab("Details", new JScrollPane(detailText));

        table.getSelectionModel().addListSelectionListener(ev -> {
            if (ev.getValueIsAdjusting()) return;
            int vr = table.getSelectedRow();
            if (vr < 0) return;
            int mr = table.convertRowIndexToModel(vr);
            String cls     = (String)  model.getValueAt(mr, 2);
            String addr    = (String)  model.getValueAt(mr, 1);
            int    methods = (Integer) model.getValueAt(mr, 4);
            int    offset  = (Integer) model.getValueAt(mr, 3);
            String bases   = (String)  model.getValueAt(mr, 5);

            hierText.setText(buildHierarchyText(cls));
            hierText.setCaretPosition(0);

            detailText.setText(
                "Class     : " + cls + "\n" +
                "vftable   : " + addr + "\n" +
                "Methods   : " + methods + "\n" +
                "Offset    : 0x" + Integer.toHexString(offset) + "\n" +
                "Bases     : " + (bases.isEmpty() ? "(none)" : bases) + "\n"
            );
            detailText.setCaretPosition(0);
        });

        // ── Status bar ────────────────────────────────────────────────────
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0,
                        UIManager.getColor("Separator.foreground")),
                new EmptyBorder(3, 8, 3, 8)));
        JLabel statusLeft = new JLabel(
                tableRows.size() + " vftables  \u00b7  "
                + hierarchy.size() + " classes  \u00b7  "
                + tdToName.size() + " TypeDescriptors");
        statusLeft.setFont(statusLeft.getFont().deriveFont(Font.PLAIN, 11f));
        JLabel statusRight = new JLabel("Double-click or Enter to navigate  \u00b7  Right-click for options   ");
        statusRight.setFont(statusRight.getFont().deriveFont(Font.PLAIN, 11f));
        statusRight.setForeground(UIManager.getColor("Label.disabledForeground"));
        statusBar.add(statusLeft,  BorderLayout.WEST);
        statusBar.add(statusRight, BorderLayout.EAST);

        // Keyboard navigation
        table.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "navigate");
        table.getActionMap().put("navigate", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                int vr = table.getSelectedRow();
                if (vr < 0) return;
                String addrStr = (String) model.getValueAt(
                        table.convertRowIndexToModel(vr), 1);
                try { goTo(rawAddr(Long.parseUnsignedLong(addrStr.replace("0x",""),16))); }
                catch (Exception ignored) {}
            }
        });

        // ── Layout ────────────────────────────────────────────────────────
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, tabs);
        split.setResizeWeight(0.70);
        split.setDividerSize(6);
        split.setBorder(BorderFactory.createEmptyBorder());

        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.add(toolbar,   BorderLayout.NORTH);
        root.add(split,     BorderLayout.CENTER);
        root.add(statusBar, BorderLayout.SOUTH);

        frame.setContentPane(root);
        frame.setVisible(true);
        // Select first row automatically
        if (table.getRowCount() > 0) table.setRowSelectionInterval(0, 0);
    }


    private String buildHierarchyText(String cls) {
        StringBuilder sb = new StringBuilder();
        buildTree(cls, 0, sb, new HashSet<>());
        return sb.toString();
    }

    private void buildTree(String cls, int depth, StringBuilder sb, Set<String> seen) {
        if (seen.contains(cls)) return;
        seen.add(cls);
        String indent = "    ".repeat(depth);
        sb.append(indent).append(depth == 0 ? "► " : "└─ ").append(cls).append("\n");
        for (String base : hierarchy.getOrDefault(cls, Collections.emptySet()))
            buildTree(base, depth + 1, sb, seen);
    }


    private void copyCell(JTable table, DefaultTableModel model, int col) {
        int vr = table.getSelectedRow();
        if (vr < 0) return;
        copyToClipboard(String.valueOf(model.getValueAt(table.convertRowIndexToModel(vr), col)));
    }

    private void copyToClipboard(String text) {
        java.awt.datatransfer.StringSelection sel =
                new java.awt.datatransfer.StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
    }

    
    private void applyTypeDescriptorType(Address addr) {
        try {
            Structure s = getOrMakeStruct("RTTI_TypeDescriptor", () -> {
                Structure ns = new StructureDataType("RTTI_TypeDescriptor", 0);
                ns.add(PointerDataType.dataType, ptrSize, "pVFTable", "type_info vftable");
                ns.add(PointerDataType.dataType, ptrSize, "spare",    "NULL at runtime");
                ns.add(new ArrayDataType(CharDataType.dataType, 64, 1), "name", "mangled name");
                return ns;
            });
            currentProgram.getListing().createData(addr, s);
        } catch (Exception ignored) {}
    }

    private void applyCOLDataType(Address addr) {
        try {
            String nm = is64bit ? "RTTI_COL64" : "RTTI_COL32";
            Structure s = getOrMakeStruct(nm, () -> {
                Structure ns = new StructureDataType(nm, 0);
                ns.add(DWordDataType.dataType, 4, "signature", "0=x86 1=x64");
                ns.add(DWordDataType.dataType, 4, "offset",    "vftable offset in object");
                ns.add(DWordDataType.dataType, 4, "cdOffset",  "ctor displacement");
                if (is64bit) {
                    ns.add(DWordDataType.dataType, 4, "pTypeDescriptor", "RVA");
                    ns.add(DWordDataType.dataType, 4, "pCHD",            "RVA");
                    ns.add(DWordDataType.dataType, 4, "pSelf",           "RVA");
                } else {
                    ns.add(PointerDataType.dataType, 4, "pTypeDescriptor", "");
                    ns.add(PointerDataType.dataType, 4, "pCHD",            "");
                }
                return ns;
            });
            currentProgram.getListing().createData(addr, s);
        } catch (Exception ignored) {}
    }

    @FunctionalInterface interface SF { Structure create(); }
    private Structure getOrMakeStruct(String name, SF f) {
        Structure e = (Structure) dtm.getDataType("/" + name);
        if (e != null) return e;
        return (Structure) dtm.addDataType(f.create(), DataTypeConflictHandler.KEEP_HANDLER);
    }

    
    private long readBufPtr(ByteBuffer buf, int off) {
        return is64bit ? buf.getLong(off) : buf.getInt(off) & 0xFFFFFFFFL;
    }

    private int readInt32At(long offset) throws Exception {
        Address a = rawAddr(offset);
        if (a == null) return 0;
        return currentProgram.getMemory().getInt(a);
    }

    private Address rawAddr(long offset) {
        try {
            return currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) { return null; }
    }

    private boolean isValidAbsAddr(long val) {
        if (val == 0) return false;
        Address a = rawAddr(val);
        return a != null && currentProgram.getMemory().contains(a);
    }

    private String extractName(byte[] bytes, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < bytes.length && bytes[i] != 0; i++)
            sb.append((char)(bytes[i] & 0xFF));
        String m = sb.toString();
        if (m.length() > 4 && m.startsWith(".?A")) m = m.substring(4);
        if (m.endsWith("@@")) m = m.substring(0, m.length() - 2);
        m = m.replace("@@", "::");
        return m.isEmpty() ? "Unknown" : m;
    }

    private Namespace getOrCreateNamespace(String name) throws Exception {
        Namespace cur = currentProgram.getGlobalNamespace();
        for (String part : name.split("::")) {
            if (part.isEmpty()) continue;
            Namespace ex = currentProgram.getSymbolTable().getNamespace(part, cur);
            cur = (ex != null) ? ex
                    : currentProgram.getSymbolTable()
                            .createNameSpace(cur, part, SourceType.ANALYSIS);
        }
        return cur;
    }

    private void safeLabel(Address addr, String name, Namespace ns) {
        try {
            Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(addr);
            if (sym == null || sym.getSource() == SourceType.DEFAULT)
                currentProgram.getSymbolTable()
                        .createLabel(addr, name, ns, SourceType.ANALYSIS);
        } catch (Exception ignored) {}
    }
}
