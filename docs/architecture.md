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

Output Example:
```
void entry_point_0x10000a5c() {
    rip + 0x2088a5 = rax;
    sub_rax*8 + 0x609010();
    rax = rip + 0x208897;
} // End of While Loop

rip + 0x208883 = 1;
return;

// Function detected at 0x10000a98 (x86_64)
void function_0x10000a98() {
    rbp = rsp;
    return;
}
```

### C. FUNC/hexdump.py
* **Role:** Engine backend for the `px` command.
* **Logic:** Translates raw memory streams into standardized hexadecimal and ASCII layouts. Utilizes lightweight array slice iterators to stream dense hexadecimal matrices to the console without inducing memory fragmentation.

Output Example:
```
 [INFO] Hex Dump at 0x10000a5c
===========================================================================
 Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII
---------------------------------------------------------------------------
 0x10000a5c  48 89 05 a5 88 20 00 ff  14 c5 10 90 60 00 48 8b  H.... ......`.H.
 0x10000a6c  05 97 88 20 00 48 39 d8  72 e2 c6 05 83 88 20 00  ... .H9.r..... .
 0x10000a7c  01 48 83 c4 08 5b c9 c3  66 66 66 2e 0f 1f 84 00  .H...[..fff.....
 0x10000a8c  00 00 00 00 48 83 3d 88  85 20 00 00 55 48 89 e5  ....H.=.. ..UH..
 0x10000a9c  74 12 b8 00 00 00 00 48  85 c0 74 08 bf 20 90 60  t......H..t.. .`
 0x10000aac  00 c9 ff e0 c9 c3 90 90  55 48 89 e5 41 54 53 48  ........UH..ATSH
 0x10000abc  81 ec 90 08 00 00 48 8d  85 b0 fe ff ff ba 0a 00  ......H.........
 0x10000acc  00 00 be 20 7c 40 00 48  89 c7 e8 75 fe ff ff 48  ... |@.H...u...H
---------------------------------------------------------------------------
```

### D. FUNC/integrity.py
* **Role:** Engine backend for the `ai` command.
* **Logic:** Validates ELF magical structures (`7f 45 4c 46`) and machine class headers. Executes proactive integrity checks, monitors symbol table anomalies, scans for packers, and reports structural deviations within target sections.

Output Example:
```
========================================================================
 [INFO] Anti-tamper & Binary Integrity
========================================================================
 * Target File Size : 44571 bytes
 * ELF Magic Status : Valid/ok (7f 45 4c 46)
 * Class / Encoding : 64-bit / Little-Endian
 * Hardware Target  : x86_64 (AMD64)
 * Binary ELF Type  : EXEC (Executable file)
 * Header Integrity : INTECT (Standard Linux Section Mapping)
 * Symbol Visibility: Debug symbols available
 * Threat Indicators: No malicious hook signatures found
 * Packer Signature : Native format templates layout unpacked
 * Final Verdict    : Binary template structures comply with standard runtime rules.
========================================================================
```

### E. FUNC/seeker.py
* **Role:** Engine backend for cursor positioning synchronization (`s` command).
* **Logic:** Leverages optimized native substring search mechanisms to locate hardware function prologues (`0xb7` bitmask variants for ARM64 and standard `push rbp` byte sequences for x86_64). Employs `bisect_left` boundary evaluation to proactively extrapolate the nearest valid function entry point when the current cursor address resides inside padding regions.

```
Cursor synchronized to: 0x10000a5c [WARNING: Inside Data/Padding]           
-> Nearest valid function entry point found at: 0x10000a20
```

### F. FUNC/shred.py
* **Role:** Engine backend for the `shred` command subsystem.
* **Logic:** Evaluates cyclomatic complexity within target function boundaries. Analyzes binary conditional branch density profiles utilizing architecture-specific bitmasks (`0x14`/`0x94` for AArch64 and standard conditional jump opcodes for Intel x86_64).

```text
[INFO] Executing binary shredding sequences.                                                              
[INFO] Scanning global execution mapping functions. 
                                                                                                                                                                [INFO*] Global binary analysis: Discovered 20 native function subroutines.
[INFO*] Smart-Target Lock     : Auto-selected nearest function cluster boundary.
[INFO*] Localized address cursor : 0x10000a5c                                                             
[INFO*] Shredder targeted code   : 0x10000a20                                                             
[INFO*] Control Flow Density  : Found 3 active branch conditions / block markers inside target.

[INFO] Binary layers shredded successfully.
```

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