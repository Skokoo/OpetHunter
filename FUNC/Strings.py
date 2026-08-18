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

import re

class StringsEngine:
    def __init__(self, shell_instance):
        self.shell = shell_instance

    def run(self, args):
        filter_keyword = None
        if args and isinstance(args, list) and len(args) > 0:
            first_arg = str(args[0]).strip()           
            if not first_arg.startswith("-"):
                filter_keyword = first_arg.lower()

        GREEN = self.shell.GREEN
        RED   = self.shell.RED
        CYAN  = self.shell.CYAN
        RESET = self.shell.RESET
        BOLD  = self.shell.BOLD

        aask = input("Bypass Data Sanitization? (y: As-is Output / n: Filter Junk code): ").strip().lower()       

        if aask == 'y':
            bad_signals = ()
            print("[\033[1mINFO\033[0m] Sensor Disabled. Output raw emulation bytes.")
        else:
            bad_signals = ("fs:", "gs:", "ss:", "ch", "dh", "bh", "ah", "al", "bl", "cl", "dl")
            print("[\033[1mINFO\033[0m] Sensor Enabled. Fidelity code filter active. \033[1mPlease note that this potentially lead to No Decompiling.\033[0m")

        lines = [f"\n[\033[1mINFO\033[0m] Extracting Static Strings & Decompiling Associated Code..."]      

        matches = re.finditer(b"[\x20-\x7E]{5,}", self.shell.binary_data)
        elf_sections = (".fini_array", ".init_array", ".text", ".data", ".rodata", 
                        ".comment", ".note", ".got", ".rela", ".dynstr", ".dynsym", 
                        ".eh_frame", ".gnu", ".symtab", ".strtab", ".shstrtab")

        for match in matches:
            raw_str = match.group().decode('ascii', errors='ignore')
            if raw_str.startswith(".") or any(raw_str.startswith(sec) for sec in elf_sections):
                continue

            if len(set(raw_str)) <= 1: 
                continue                            

            alphabetic_count = sum(1 for char in raw_str if char.isalpha())
            if len(raw_str) > 0 and (alphabetic_count / len(raw_str)) < 0.40:               
                continue

            if filter_keyword and filter_keyword not in raw_str.lower(): 
                continue

            offset = match.start()
            vaddr = self.shell.base_address + offset            
            color = GREEN
            if any(x in raw_str.lower() for x in tuple(("http", ".exe", "select", "cmd", "password", "flag{"))): 
                color = RED
            elif any(x in raw_str.lower() for x in tuple(("debug", "assert", "gcc", "main"))): 
                color = CYAN

            local_offset = offset + len(match.group())
            pseudo_c = ""

            if local_offset + 64 <= self.shell.file_size:
                code_chunk = self.shell.binary_data[local_offset : local_offset + 64]
                raw_c = self.shell.translate_bytes_to_c(code_chunk, vaddr + len(match.group()))

                if raw_c and "{" in raw_c:
                    if not bad_signals or not any(sig in raw_c.lower() for sig in bad_signals):
                        pseudo_c = raw_c

            lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> {color}{raw_str}{RESET}")
            if pseudo_c and "{" in pseudo_c and len(pseudo_c.strip().split("\n")) > 2:
                lines.append(pseudo_c)

        lines.append("")
        self.shell.check_and_print("\n".join(lines))

        if aask == 'y':
            print(f"\n{BOLD}[TIPS]{RESET}")
            print("[i] Don't forget to check the output, \033[1mdon't get fooled by null bytes.\033[0m")
            print("[i] Most of the data above is padding noise (+= ch/al).")
            print("[i] But, just keep scrolling and don't be lazy to scan... \033[1myou might encounteted a 'gold'.\033[0m\n")
            print(f"{BOLD}[Example of Null Bytes]{RESET}")
            print(f"    // Loop recovery or code block containing constant junk:")
            print(f"    {{")
            print(f"        byte ptr [arg2] += ch;  <-- Monoton repetition")
            print(f"        byte ptr [arg4] += al;  <-- 00 00 padding byte")
            print(f"    }}\n")

            print(f"{BOLD}[Example of active code]{RESET}")
            print(f"    // Real program logic or encryption functions found:")
            print(f"    {{")
            print(f"        eax ^= 0x34327800;      <-- Real cryptographic XOR key")
            print(f"        if (!(param_1 == eax))  <-- Control flow conditional check")
            print(f"    }}\n")
        
        return None