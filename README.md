# ClassInformer for Ghidra

A Ghidra script that replicates the functionality of the ClassInformer plugin for IDA Pro.
Recovers MSVC C++ RTTI information from 32-bit and 64-bit Windows binaries.

---

## What it does

- Finds all MSVC TypeDescriptors by scanning for the `.?A` mangled name signature
- Locates CompleteObjectLocators (COLs) and their associated vftables
- Reconstructs class inheritance hierarchies from ClassHierarchyDescriptors
- Applies labels and data types to all recovered structures in Ghidra
- Displays results in a sortable, filterable table window

---

## Requirements

- Ghidra 10.x or later
- A Windows PE binary compiled with MSVC and RTTI enabled (/GR)
- The binary should be analyzed (auto-analysis run) before running the script

---

## Installation

Copy `ClassInformer.java` to your Ghidra scripts directory:

    Windows : C:\Users\<user>\ghidra_scripts\
    Linux   : ~/ghidra_scripts/
    macOS   : ~/ghidra_scripts/

---

## Usage

1. Open your binary in Ghidra and run auto-analysis
2. Open the Script Manager: Window > Script Manager
3. Find ClassInformer in the list (category: C++)
4. Click Run

The script runs in four phases and prints progress to the console.
When complete, a results window opens automatically.

---

## Results window

Column    | Description
--------- | -------------------------------------------
#         | Row index
vftable   | Address of the virtual function table
Class Name| Demangled class name
Offset    | Offset of this vftable in the complete object (0 for primary)
Methods   | Number of virtual methods detected in the vftable
Base Classes | Direct base classes from the class hierarchy descriptor

- Type in the Filter box to search by class name or base class
- Double-click a row or press Enter to navigate to the vftable in the listing
- Right-click a row for copy options
- Select a row to see the full inheritance tree in the bottom panel

---

## Labels applied to the binary

    ClassName::vftable                   Virtual function table
    ClassName::RTTI_CompleteObjectLocator  COL structure
    ClassName::RTTI_TypeDescriptor         TypeDescriptor structure
    ClassName::RTTI_COL_ptr                Pointer slot before the vftable

---

## Limitations

- MSVC only. GCC and Clang use a different RTTI format and are not supported.
- RTTI must not be stripped. Binaries compiled with /GR- will not yield results.
- Obfuscated or packed binaries may produce partial or no results.
- Virtual inheritance and multiple inheritance hierarchies are detected but
  deep diamond hierarchies may not display perfectly in the tree view.

---

## How it works

The script avoids relying on Ghidra cross-references, which are often incomplete
for data-to-data pointer relationships in .rdata sections. Instead it performs a
single linear sweep of all initialized memory blocks and builds two in-memory indexes:

- absIndex: maps every native-width pointer value to the addresses that hold it
- rvaIndex: maps every 32-bit DWORD value to the addresses that hold it

For 64-bit binaries, COL fields store image-relative RVAs rather than absolute
pointers. The rvaIndex is used to resolve these efficiently. 
