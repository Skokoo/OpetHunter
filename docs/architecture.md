# Architecture
An ultra-optimized, zero-bloat 64-bit cross-OS binary analysis engine strictly bounded under a 27MB RAM constraint.

## FUNC/The code within this directory might be complex, but it pays off completely because the execution speed becomes fast.

## 1. Granular File & Specifications

### A. FUNC/analyze.py
* **Functionality:** Operates as the backend for the `info` command.
* **Logic Core:** Extracts primary file size parameters, detects compiler variants, maps binary linking layouts, and extracts target minimum system dependency parameters (such as GLIBC_2.2).

### B. FUNC/disasm.py
* **Functionality:** Operates as the engine backend for the `asmd` command blocks.
* **Logic Core:** Dynamically configures the Capstone disassembly context based on global runtime properties. It handles the linear instruction formatting buffer, and performs localized lambda map transformations into Pseudo-C structures.

### C. FUNC/hexdump.py
* **Functionality:** Operates as the engine backend for the `px` command.
* **Logic Core:** Translates raw memory streams into localized hex/ASCII layouts. It employs lightweight array slice iterators to stream dense hexadecimal columns over the console output without causing memory fragmentation.

### D. FUNC/integrity.py
* **Functionality:** Operates as the engine backend for the `ai` command.
* **Logic Core:** Validates ELF magical structures (`7f 45 4c 46`) and machine class headers. It performs proactive integrity checks, monitors symbol table anomalies, scans for packers, and reports anomalies on target sections.

### E. FUNC/seeker.py
* **Functionality:** Operates as the engine backend for the cursor positioning synchronization (`s` command).
* **Logic Core:** Leverages native `bytearray.find()` substring methods to seek real hardware function prologues (`0xb7` for ARM64 and standard `push rbp` variants for x86_64). Employs `bisect_left` bounds searching to proactively suggest the nearest function entry point if the current cursor lands inside padding regions.

### F. FUNC/shred.py
* **Functionality:** Operates as the engine backend for the `shred` block command.
* **Logic Core:** Dynamically counts execution complexity within a target function boundary. It screens active binary conditional branch density profiles based on the architecture flags (`0x14`/`0x94` bitmasks on AArch64 and standard jump bytes on Intel x86_64).

### G. FUNC/strings.py
* **Functionality:** Operates as the engine backend for the `iz` command.
* **Logic Core:** Parses the binary layout to extract printable ASCII string tokens. It triggers automated local decompiler routine injections right beneath sensitive extracted symbol parameters to provide high-fidelity automated binary context clues.

## 3. Memory Preservation & Instance Isolation
All seven components inside the `FUNC/` directory use a unified lifecycle injection blueprint:
```python
def __init__(self, instance):
    self.shell = instance
```