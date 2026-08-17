#   Copyright 2026 Skokoo

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import re

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
        lang = "C / C++ or Native ASM"
        os_target = "Generic Environment"
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
            lang = "Go (Golang)"
        if "rustc" in flat or "core::panicking" in flat or "std::rt" in flat:
            lang = "Rust"
            cc = "rustc (LLVM Backend)"
        elif "pyi_rth_" in flat or "pydata" in flat or "libpython" in flat:
            lang = "Python (Frozen Binary)"

        glibc_match = re.findall(r'glibc_2\.[0-9]+', flat)
        if glibc_match:
            max_ver = max(tuple(glibc_match))
            os_target = f"Linux Kernel (Requires {max_ver.upper()})"
        elif "ld-linux" in flat:
            os_target = "Linux Environment (Standard libc)"
        elif "kernel32.dll" in flat or "ntdll.dll" in flat:
            os_target = "Windows OS Environment"

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
        if "ptrace" in flat:
            sec.append("Anti-Debug: ptrace (Linux Trace Trap)")
        if "isdebuggerpresent" in flat or "checkremotedebuggerpresent" in flat:
            sec.append("Anti-Debug: Windows Debugger API")

        res = [
            "\n" + "="*60,
            f" [INFO] METADATA",
            "="*60,
            f"  * Size   : {self.sz} bytes",
            f"  * Format : {fmt}",
            f"  * Arch   : {arch}",
            f"  * Lang   : {lang}",
            f"  * Comp   : {cc}",
            f"  * Target : {os_target}",
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