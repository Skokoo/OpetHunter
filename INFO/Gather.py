import os
import re

# Opet' v0.1.0
# Copyright 2026 Skokoo
# Licensed under the Apache License, Version 2.0

class BinaryGatherer:
    def __init__(self, data_bytes):
        self.raw = data_bytes
        self.sz = len(data_bytes)

    def get_strs(self):       
        m = re.finditer(b"[\x20-\x7E]{4,}", self.raw)
        return [x.group().decode('ascii', errors='ignore').lower() for x in m]

    def run_gather(self):
        strs = self.get_strs()
        flat = " ".join(strs)
        
        cc = "Unknown Compiler"
        ld = "Unknown Linker"
        fmt = "Raw Binary Data"
        arch = "x86_64"
        sec = []
        
        if self.sz > 4:
            mag = self.raw[:4]
            if mag.startswith(b"\x7fELF"):
                fmt = "ELF (Linux)"
            elif mag.startswith(b"MZ"):
                fmt = "PE (Windows / DOS)"
            elif mag.startswith(b"\xca\xfe\xba\xbe") or mag.startswith(b"\xcf\xfa\xed\xfe"):
                fmt = "Mach-O (Apple)"
        
        if "gcc" in flat:
            cc = "GCC (GNU Compiler Collection)"
        elif "clang" in flat:
            cc = "Clang / LLVM"
        elif "msvc" in flat or "microsoft visual c" in flat:
            cc = "MSVC (Microsoft Visual C++)"
        elif "mingw" in flat:
            cc = "MinGW (Windows)"
        elif "fpc" in flat or "free pascal" in flat:
            cc = "Free Pascal"
        elif "go.go" in flat or "runtime.gopanic" in flat:
            cc = "Go Language Compiler"        
        if "gold" in flat:
            ld = "GNU gold linker"
        elif "ld-linux" in flat:
            ld = "GNU ld (Standard Linux)"        
        
        if "__stack_chk_fail" in flat:
            sec.append("Stack Canary (Anti-Buffer Overflow)")
        if "upx!" in flat:
            sec.append("UPX Packing Detected (Compressed/Packed)")
        if "mprotect" in flat or "virtualprotect" in flat:
            sec.append("Dynamic Memory / Shellcode Potential")
       
        res = [
            "\n" + "="*60,
            f" [INFO] METADATA",
            "="*60,
            f"  * Size   : {self.sz} bytes",
            f"  * Format : {fmt}",
            f"  * Arch   : {arch}",
            f"  * Comp   : {cc}",
            f"  * Linker : {ld}"
        ]
        
        if sec:
            res.append("[WARNING] Alerts/Protections:")
            for x in sec:
                res.append(f"-> \033[1m{x}\033[0m")
        else:
            res.append("[INFO] Alerts/Protections: None (Clean ASM)")
            
        res.append("="*60 + "\n")
        return "\n".join(res)