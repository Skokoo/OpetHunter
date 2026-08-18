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

import sys
import os
import re
import math
try:
    from capstone import *
except Exception:
    print("[ERROR] The Package capstone not installed on your terminal, please install it by using pip install capstone.")
    sys.exit(1) 

current_dir = os.path.dirname(os.path.abspath(__file__))
dec_folder_path = os.path.join(current_dir, "DEC")

if dec_folder_path not in sys.path:
    sys.path.insert(0, dec_folder_path)
try:
    from CDec import CapstoneDecompiler
except ImportError:
    print(f"[ERROR] The file 'CDec.py' NOT found IN dir: {dec_folder_path}")
    sys.exit(1)

info_folder_path = os.path.join(current_dir, "INFO")
if info_folder_path not in sys.path:
    sys.path.insert(0, info_folder_path)
try:
    from Info import InfoValidator
except ImportError:
    print(f"[ERROR] The file 'Info.py' NOT found IN dir: {info_folder_path}")
    sys.exit(1)

func_map = {
            "pd": ("Disasm", "Disasm),
            "px": ("HexDump", "Hexdump"),
            "iz": ("Strings", "StringsExtract"),
            "ax": ("Analyze", "Analyze"),
            "ae": ("Analyze", "EntropyMap")
        }

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[34m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

class Runnow:
    def __init__(self, filepath):
        self.filepath = filepath
        self.cursor = 0x0
        self.base_address = 0x10000000
        self.last_args = None

        try:
            with open(filepath, "rb") as f:
                self.binary_data = bytearray(f.read())
            self.file_size = len(self.binary_data)
        except Exception as e:
            print(f"[\033[1mWARNING*\033[0m] Error reading file: \033[1m{e}\033[0m")
            sys.exit(1)
        
        self.arch_type = "x86_64"
        if self.file_size > 0x12:           
            if self.binary_data[0x12] == 0x28:
                self.arch_type = "aarch64"
       
        if self.arch_type == "aarch64":
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM) 
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)    

        self.cs.detail = True               
        idx = self.binary_data.find(b"\x55\x48\x89\xE5")
        self.cursor = idx if idx != -1 else 0x0   
       
    def auto_detect_entry_point(self):
        pattern = b"\x55\x48\x89\xE5"
        idx = self.binary_data.find(pattern)
        self.cursor = idx if idx != -1 else 0x0

    def calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count == 0: continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def check_and_print(self, out_str):
        if out_str is None or not isinstance(out_str, str):
            print("[\033[1mWARNING\033[0m] Decompiler returned no text or empty block.")
            return

        lines = out_str.split("\n")
        outfile = None
        cut_val = None
        
        if hasattr(self, 'last_args') and self.last_args:
            arg_str = " ".join(self.last_args)
                       
            cut_match = re.search(r'-cut\s+(\d+)', arg_str)
            if cut_match:
                cut_val = int(cut_match.group(1))
                lines = lines[:cut_val]
                out_str = "\n".join(lines)
            
            out_match = re.search(r'-o\s+(\S+)', arg_str)
            if out_match:
                outfile = out_match.group(1)
        
        if outfile:
            if os.path.exists(outfile):
                print(f"[\033[1mWARNING\033[0m] File '{outfile}' \033[1malready exists.\033[0m")
                confirm = input("Overwrite? (y: Overwrite / n: Cancel / p: Print): ").strip().lower()
                
                if confirm == 'p':
                    print("\n[\033[1mINFO\033[0m] Redirecting output to screen layout.\n")
                    outfile = None
                elif confirm != 'y':
                    print("[\033[1mINFO\033[0m] Export canceled.")
                    return
            
            if outfile:
                try:
                    clean_text = re.sub(r'\033\[[0-9;]*m', '', out_str)
                    with open(outfile, "w", encoding="utf-8") as f:
                        f.write(clean_text)
                    print(f"[\033[1mINFO\033[0m] Exported \033[1m{len(lines)}\033[0m lines to: {outfile}")
                    return
                except Exception as e:
                    print(f"[\033[1mWARNING\033[0m] Failed to write file: \033[1m{e}\033[0m")
        
        char_count = len(out_str)
        lines_count = len(lines)
        if char_count > 1500:
            ask = input(f"Do you want to print \033[1m{char_count}\033[0m chars (\033[1m{lines_count}\033[0m lines)? (y/n)").strip().lower()
            whitelist_print = tuple(("y"))
            if ask not in whitelist_print:
                print("[\033[1mWARNING\033[0m] Printing canceled.")
                return              
        print(out_str)    
    # ==== FLAG TO DEL ====               
    def print_disasm(self, args):
        count = 15
        if args:
            try: count = int(args[0])
            except: pass

        chunk = self.binary_data[self.cursor : self.cursor + (count * 15)]
        vaddr_start = self.base_address + self.cursor

        lines = [f"\n[\033[1mINFO\033[0m] Disassembly at {hex(vaddr_start)}", f"{BOLD}Address\t\tHex Bytes\t\tFlow\tInstruction{RESET}", "-" * 85]
        for insn in self.cs.disasm(chunk, vaddr_start):
            hex_bytes = "".join(f"{b:02x}" for b in insn.bytes).ljust(18)

            op_str_colored = insn.op_str
            op_str_colored = re.sub(r'\b(r[a-d]x|e[a-d]x|rsp|rbp|esp|ebp|rsi|rdi|r\d+)\b', f"{BOLD}\\1{RESET}", op_str_colored)
            op_str_colored = re.sub(r'(0x[0-9a-fA-F]+)', f"{BOLD}\\1{RESET}", op_str_colored)

            mnemonic_colored = insn.mnemonic
            flow_line = f"{WHITE}│{RESET}"

            if insn.mnemonic.startswith('j'):
                mnemonic_colored = f"{RED}{BOLD}{insn.mnemonic}{RESET}"
                flow_line = f"{BOLD}├── [JMP]{RESET}"
            elif insn.mnemonic == 'call':
                mnemonic_colored = f"{MAGENTA}{BOLD}{insn.mnemonic}{RESET}"
                flow_line = f"{MAGENTA}├── [CALL]{RESET}"
            elif insn.mnemonic in ['ret', 'hlt']:
                mnemonic_colored = f"{YELLOW}{BOLD}{insn.mnemonic}{RESET}"
                flow_line = f"{YELLOW}└── [END]{RESET}"
            elif insn.mnemonic in ['xor', 'sub', 'add', 'cmp']:
                mnemonic_colored = f"{GREEN}{insn.mnemonic}{RESET}"

            lines.append(f"  {WHITE}{hex(insn.address)}{RESET}\t{hex_bytes}\t{flow_line}\t{mnemonic_colored} {op_str_colored}")
        lines.append("-" * 85 + "\n")
        self.check_and_print("\n".join(lines))    

    def print_hex_dump(self, args):
        size = 128
        if args:
            try: size = int(args[0])
            except: pass

        chunk = self.binary_data[self.cursor : self.cursor + size]
        vaddr_start = self.base_address + self.cursor

        lines = [f"\n[\033[1mINFO\033[0m] Hex Dump at {hex(vaddr_start)}", f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII", "-" * 75]
        for i in range(0, len(chunk), 16):
            sub_chunk = chunk[i:i+16]
            hex_str = ""
            ascii_str = ""

            for idx, b in enumerate(sub_chunk):
                if idx == 8: hex_str += " "
                if b == 0x00:
                    hex_str += f"{WHITE}{b:02x}{RESET} "
                    ascii_str += f"{WHITE}.{RESET}"
                elif 0x20 <= b <= 0x7E:
                    hex_str += f"{GREEN}{b:02x}{RESET} "
                    ascii_str += f"{GREEN}{chr(b)}{RESET}"
                else:
                    hex_str += f"{RED}{b:02x}{RESET} "
                    ascii_str += f"{RED}.{RESET}"

            line_vaddr = vaddr_start + i
            lines.append(f"  {hex(line_vaddr)}  {hex_str.ljust(60)}  {ascii_str}")
        lines.append("-" * 75 + "\n")
        self.check_and_print("\n".join(lines))

    def translate_bytes_to_c(self, chunk, start_vaddr):
        c_lines = [f"    // Auto-Decompile Code Block at {hex(start_vaddr)} ", "    {"]
        last_cmp = ""      
        
        if hasattr(self, 'arch_type') and self.arch_type == "aarch64":
            reg_map = {"x0": "arg1", "x1": "arg2", "x2": "arg3", "x3": "arg4", "w0": "arg1_32"}
        else:
            reg_map = {"rdi": "arg1", "rsi": "arg2", "rdx": "arg3", "rcx": "arg4", "rax": "local_res"}

        for insn in self.cs.disasm(chunk, start_vaddr):
            op = insn.op_str
            for r, v in reg_map.items():
                op = re.sub(rf'\b{r}\b', v, op)          
            if insn.mnemonic in ["mov", "ldr", "str", "movz"]:
                parts = op.split(",")
                if len(parts) == 2: c_lines.append(f"        {parts[0].strip()} = {parts[1].strip()};")
            elif insn.mnemonic == "add":
                parts = op.split(",")
                if len(parts) == 2: c_lines.append(f"        {parts[0].strip()} += {parts[1].strip()};")
            elif insn.mnemonic in ["sub", "subs"]:
                parts = op.split(",")
                if len(parts) == 2: c_lines.append(f"        {parts[0].strip()} -= {parts[1].strip()};")           
            elif insn.mnemonic in ["xor", "eor"]:
                parts = op.split(",")
                if len(parts) == 2:
                    if parts[0].strip() == parts[1].strip(): c_lines.append(f"        {parts[0].strip()} = 0;")
                    else: c_lines.append(f"        {parts[0].strip()} ^= {parts[1].strip()};")
            elif insn.mnemonic == "cmp":
                last_cmp = op.replace(",", " == ")           
            elif insn.mnemonic in ["je", "b.eq"] and last_cmp:
                c_lines.append(f"        if ({last_cmp}) {{ // branch")
            elif insn.mnemonic in ["jne", "b.ne"] and last_cmp:
                c_lines.append(f"        if (!({last_cmp})) {{ // branch")            
            elif insn.mnemonic in ["call", "bl", "blr"]:
                c_lines.append(f"        sub_{insn.op_str.strip()}();")
            elif insn.mnemonic in ["ret", "hlt"]:               
                ret_val = "arg1" if (hasattr(self, 'arch_type') and self.arch_type == "aarch64") else "local_res"
                c_lines.append(f"        return {ret_val};")
                break
                
        c_lines.append("    }")
        return "\n".join(c_lines)

    def print_strings(self, args):        
        filter_keyword = None
        if args and isinstance(args, list) and len(args) > 0:
            first_arg = str(args[0]).strip()           
            if not first_arg.startswith("-"):
                filter_keyword = first_arg.lower()
        
        aask = input("Bypass Data Sanitization? (y: As-is Output / n: Filter Junk code): ").strip().lower()       
        
        if aask == 'y':
            bad_signals = ()
            print("[\033[1mINFO\033[0m] Sensor Disabled. Output raw emulation bytes.")
        else:
            bad_signals = ("fs:", "gs:", "ss:", "ch", "dh", "bh", "ah", "al", "bl", "cl", "dl")
            print("[\033[1mINFO\033[0m] Sensor Enabled. Fidelity code filter active. \033[1mPlease note that this potentially lead to No Decompiling.\033[0m")

        lines = [f"\n[\033[1mINFO\033[0m] Extracting Static Strings & Decompiling Associated Code..."]      

        matches = re.finditer(b"[\x20-\x7E]{5,}", self.binary_data)
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
            vaddr = self.base_address + offset            
            color = GREEN
            if any(x in raw_str.lower() for x in tuple(("http", ".exe", "select", "cmd", "password", "flag{"))): 
                color = RED
            elif any(x in raw_str.lower() for x in tuple(("debug", "assert", "gcc", "main"))): 
                color = CYAN

            local_offset = offset + len(match.group())
            pseudo_c = ""
            
            if local_offset + 64 <= self.file_size:
                code_chunk = self.binary_data[local_offset : local_offset + 64]
                raw_c = self.translate_bytes_to_c(code_chunk, vaddr + len(match.group()))
                
                if raw_c and "{" in raw_c:
                    if not bad_signals or not any(sig in raw_c.lower() for sig in bad_signals):
                        pseudo_c = raw_c

            lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> {color}{raw_str}{RESET}")
            if pseudo_c and "{" in pseudo_c and len(pseudo_c.strip().split("\n")) > 2:
                lines.append(pseudo_c)

        lines.append("")
        self.check_and_print("\n".join(lines))

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

    def find_xrefs(self):
        target_vaddr = self.base_address + self.cursor
        lines = [f"\n[\033[1mINFO\033[0m] Scanning XREFs for address: {hex(target_vaddr)}..."]
        found_xrefs = 0

        for insn in self.cs.disasm(self.binary_data, self.base_address):
            if insn.mnemonic.startswith('j') or insn.mnemonic == 'call':
                if hex(target_vaddr) in insn.op_str:
                    lines.append(f"  [XREF] Found at {hex(insn.address)} -> ({insn.mnemonic} {insn.op_str})")
                    found_xrefs += 1

        if found_xrefs == 0:
            lines.append("[\033[1mERROR\033[0m] No external XREFs found for this address.")
        lines.append("")
        self.check_and_print("\n".join(lines))

    def analyze_entropy_map(self):
        lines = [f"\n[\033[1mINFO\033[0m] Shannon Entropy Analysis", "Block\tVirtual Addr\tScore\t\tStatus / Graph", "-" * 75]
        block_size = 512

        for i in range(0, self.file_size, block_size):
            block = self.binary_data[i:i+block_size]
            entropy = self.calculate_entropy(block)
            bar_len = int(entropy * 4)
            chart = "█" * bar_len
            vaddr = self.base_address + i
            
            if entropy > 6.5:   
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{RED}{BOLD}[PACKED] {RESET} {RED}{chart}{RESET}")
            elif entropy > 4.5: 
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{YELLOW}[CODE]   {RESET} {YELLOW}{chart}{RESET}")
            else:               
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{GREEN}[DATA]   {RESET} {GREEN}{chart}{RESET}")
        lines.append("")
        self.check_and_print("\n".join(lines))

    def run_shell(self):
        filename = os.path.basename(self.filepath)
        print(f"[\033[1mINFO\033[0m] Loaded: \033[1m{filename}\033[0m ({self.file_size} bytes)")

        while True:
            try:
                prompt = f"{BOLD}opet@{hex(self.cursor)}>{RESET} "
                raw_input = input(prompt).strip()
                if not raw_input: continue

                if raw_input.startswith("!"):
                    os.system(raw_input[1:])
                    continue

                cmd_input = raw_input.split()
                cmd = cmd_input[0].lower()
                args = cmd_input[1:] if len(cmd_input) > 1 else None
                self.last_args = args

                if cmd in ["q", "exit"]: 
                    break
                elif cmd in ["h", "help", "?"]:
                    help_text = (f"\n{BOLD}Available Commands:{RESET}\n"
                                 f"  pd [lines]  : Disassembly view (Default: 15 lines) [Supports -o, -cut]\n"
                                 f"  px [bytes]  : Hex-Dump view (Default: 128 bytes) [Supports -o, -cut]\n"
                                 f"  ax          : Scan external XREFs call references [Supports -o, -cut]\n"
                                 f"  ae          : Check file encryption using Shannon Entropy [Supports -o, -cut]\n"
                                 f"  iz [filter] : Extract static ASCII strings from binary + Enterprise Auto-C [Supports -o, -cut]\n"
                                 f"  asmd [size] : Decompile assembly block at cursor to Pseudo-C [Supports -o, -cut]\n"
                                 f"  s <offset>  : Seek cursor to target virtual address\n"
                                 f"  info        : Execute file signature evaluation & false positive filter [Supports -o, -cut]\n"
                                 f"  !<command>  : Execute system shell command (e.g. !ls, !clear)\n"
                                 f"  h, help     : Show this commands list\n"
                                 f"  q, exit     : Close the program\n")                                                       
                    self.check_and_print(help_text)                
                elif cmd == "pd": self.print_disasm(args)
                elif cmd == "px": self.print_hex_dump(args)
                elif cmd == "ax": self.find_xrefs()
                elif cmd == "asmd":
                    chunk_size = 64
                    if args:
                        try:
                            chunk_size = int(args)
                        except:
                            pass
                    if self.cursor + chunk_size <= self.file_size:
                        code_chunk = self.binary_data[self.cursor : self.cursor + chunk_size]
                        vaddr_start = self.base_address + self.cursor
                        decompiler = CapstoneDecompiler(code_chunk, vaddr_start)
                        pseudo_c = decompiler.run_decompile()
                                                
                        if pseudo_c is not None:
                            self.check_and_print(pseudo_c)
                        else:
                            print("[\033[1mERROR\033[0m] Decompiler returned empty data.")
                    else:
                        print("[\033[1mWARNING\033[0m] Cursor position near EOF. Cannot decompile out of bounds.")
                elif cmd == "ae": self.analyze_entropy_map()
                elif cmd == "iz": self.print_strings(args)
                elif cmd == "info":                     
                    engine = InfoValidator(self.binary_data)
                    rep = engine.run_pipeline()
                    self.check_and_print(rep)
                elif cmd == "s" and args:
                    try:
                        target = args[0]
                        val = int(target, 16) if target.startswith("0x") else int(target)
                        if 0 <= (val - self.base_address) <= self.file_size:
                            self.cursor = val - self.base_address
                        else:
                            print("[\033[1mWARNING\033[0m] Address out of bounds.")
                    except ValueError:
                        print("[\033[1mWARNING\033[0m] Invalid address format.")
                else:
                    print("[\033[1mWARNING\033[0m] Unknown command. Type \033[1m'help'\033[0m for options.")
            except (KeyboardInterrupt, EOFError):                
                break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: \033[1mpython {sys.argv[0]} <binary_path>\033[0m")
        sys.exit(1)

    engine = Runnow(sys.argv[1])
    engine.run_shell()

               
        