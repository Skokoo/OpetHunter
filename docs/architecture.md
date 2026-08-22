# System Architecture Specification

An ultra-optimized, zero-bloat 64-bit cross-operating system binary analysis engine, architected to operate strictly within a 27MB RAM constraint.

## Core Component Pipeline (`FUNC/`)
The implementation within the `FUNC/` directory utilizes highly dense algorithmic structures. While computationally complex, this architecture eliminates abstraction layers to guarantee maximum execution velocity and predictable memory overhead.

---

## 1. Granular Component Specification

### A. FUNC/analyze.py
* **Role:** Engine backend for the `info` command subsystem.
* **Logic:** Extracts primary file size metrics, fingerprints compiler variants, maps binary linking topologies, and resolves minimum target system dependencies (e.g., `GLIBC` symbols). 

Output Example:

```
========================================================================
 [INFO] METADATA
========================================================================
 * Size   : 44571 bytes
 * Format : ELF (Linux)
 * Arch   : x86_64
 * Lang   : C / C++ or Native ASM
 * Comp   : GCC (GNU Compiler Collection)
 * Target : Linux Kernel (Requires GLIBC_2.2)
 * Linker : GNU ld (Standard Linux)

 [INFO] ALERTS & PROTECTIONS
 * Status : None (Clean ASM / No Packer Detected)
========================================================================
```                                                                                             
### B. FUNC/disasm.py
* **Role:** Engine backend for the `asmd` command blocks.
* **Logic:** Dynamically initializes the Capstone disassembly contexts using global runtime state properties. Manages the linear instruction formatting buffer and performs localized lambda map transformations into Pseudo-C structures.

Outpur example:
```
void entry_point_0x10000a5c() {
    [0x10000a5c]  rip + 0x2088a5 = rax;
    [0x10000a60]  sub_rax*8 + 0x609010();
    [0x10000a68]  rax = rip + 0x208897;
} // End of While Loop

[0x10000a6c]  rip + 0x208883 = 1;
return;

// Function detected at 0x10000a98 (x86_64)
void function_0x10000a98() {
    [0x10000a98]  rbp = rsp;
    return;
}
```

### C. FUNC/hexdump.py
* **Role:** Engine backend for the `px` command.
* **Logic:** Translates raw memory streams into standardized hexadecimal and ASCII layouts. Utilizes lightweight array slice iterators to stream dense hexadecimal matrices to the console without inducing memory fragmentation.

### D. FUNC/integrity.py
* **Role:** Engine backend for the `ai` command.
* **Logic:** Validates ELF magical structures (`7f 45 4c 46`) and machine class headers. Executes proactive integrity checks, monitors symbol table anomalies, scans for packers, and reports structural deviations within target sections.

### E. FUNC/seeker.py
* **Role:** Engine backend for cursor positioning synchronization (`s` command).
* **Logic:** Leverages optimized native substring search mechanisms to locate hardware function prologues (`0xb7` bitmask variants for ARM64 and standard `push rbp` byte sequences for x86_64). Employs `bisect_left` boundary evaluation to proactively extrapolate the nearest valid function entry point when the current cursor address resides inside padding regions.

### F. FUNC/shred.py
* **Role:** Engine backend for the `shred` command subsystem.
* **Logic:** Evaluates cyclomatic complexity within target function boundaries. Analyzes binary conditional branch density profiles utilizing architecture-specific bitmasks (`0x14`/`0x94` for AArch64 and standard conditional jump opcodes for Intel x86_64).

### G. FUNC/strings.py
* **Role:** Engine backend for the `iz` command.
* **Logic:** Scans specific binary segments to extract printable ASCII string tokens. Triggers automated localized decompiler heuristic injections adjacent to sensitive extracted symbols to provide context-aware binary clues.

---

## 2. Memory Preservation & Instance Isolation

To maintain a minimal memory footprint and enforce state isolation, all seven core components within the `FUNC/` directory implement a unified lifecycle dependency injection blueprint:

```python
def __init__(self, instance):   
    self.shell = instance
```