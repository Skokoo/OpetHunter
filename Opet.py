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

#  The code in this file might still be sane,
#  but brace yourself for the others.

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

func_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FUNC")

modules = {}

if not os.path.exists(func_dir):
    print(f"[\033[1mERROR\033[0m] The directory 'FUNC' not found in path: {func_dir}")
else:
    import inspect
    import importlib           

    import_targets = [
        ("Disasm", "Disasm"),
        ("HexDump", "Hexdump"),
        ("Strings", "StringsExtract"),
        ("Analyze", "Analyze"),
        ("Seeker", "Seeker"),
        ("Integrity", "Integrity")
    ]            

    for file_name, class_name in import_targets:
        try:
            mod = importlib.import_module(f"FUNC.{file_name}")
            cls = getattr(mod, class_name)
            modules[class_name] = cls
        except Exception as e:
            print(f"[\033[1mERROR\033[0m] Failed to import: {file_name}.{class_name}: {e}")
            sys.exit(1)

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
        self.modules = modules        
        self.GREEN = GREEN
        self.RED = RED
        self.CYAN = CYAN
        self.RESET = RESET
        self.MAGENTA = MAGENTA
        self.BOLD = BOLD
        self.WHITE = WHITE
        self.YELLOW = YELLOW
        self.BLUE = BLUE

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
        # Trik pencarian hibrida sekali tebas untuk epilog x86 dan penanda fungsi ARM64
        idx = self.binary_data.find(b"\x55\x48\x89\xE5")
        self.cursor = idx if idx != -1 else (self.binary_data.find(b"\xFF\x43\x00\xD1") if self.binary_data.find(b"\xFF\x43\x00\xD1") != -1 else 0x0)

    def calculate_entropy(self, data):
        if not data: return 0
        length = len(data)               
        return -sum((count / length) * math.log2(count / length) for count in [data.count(byte) for byte in set(data)])

    def check_and_print(self, out_str):
        if out_str is None or not isinstance(out_str, str):
            print("[\033[1mWARNING\033[0m] Decompiler returned no text or empty block.")
            return

        lines = out_str.split("\n")
        argument = " ".join(self.last_args) if hasattr(self, 'last_args') and self.last_args else ""
        
        cut_match = re.search(r'-cut\s+(\d+)', argument)
        lines = lines[:int(cut_match.group(1))] if cut_match else lines
        out_str = "\n".join(lines) if cut_match else out_str

        out_match = re.search(r'-o\s+(\S+)', argument)
        outfile = out_match.group(1) if out_match else None
        
        if outfile and os.path.exists(outfile):
            print(f"[\033[1mWARNING\033[0m] File '{outfile}' \033[1malready exists.\033[0m")
            choice = input("Overwrite? (y: Overwrite / n: Cancel / p: Print): ").strip().lower()
            outfile = None if choice == 'p' else (outfile if choice == 'y' else "CANCEL")
            if outfile == "CANCEL":
                print("[\033[1mINFO\033[0m] Export canceled.")
                return
        
        if outfile:
            try:
                with open(outfile, "w", encoding="utf-8") as stream:
                    stream.write(re.sub(r'\033\[[0-9;]*m', '', out_str))
                print(f"[\033[1mINFO\033[0m] Exported \033[1m{len(lines)}\033[0m lines to: {outfile}")
                return
            except Exception as failure:
                print(f"[\033[1mWARNING\033[0m] Failed to write file: \033[1m{failure}\033[0m")
        
        if len(out_str) > 1500 and input(f"Do you want to print \033[1m{len(out_str)}\033[0m chars (\033[1m{len(lines)}\033[0m lines)? (y/n)").strip().lower() != 'y':
            print("[\033[1mWARNING\033[0m] Printing canceled.")
            return            

        print(out_str)

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
                elif cmd == "pd":
                    if "Disasm" in self.modules:
                        self.check_and_print(self.modules["Disasm"](self).run(args))

                elif cmd == "px":
                    if "Hexdump" in self.modules:
                        self.check_and_print(self.modules["Hexdump"](self).run(args))

                elif cmd == "ai":
                    if "Integrity" in self.modules:
                        self.check_and_print(self.modules["Integrity"](self).run(args))

                elif cmd == "iz":
                    if "StringsExtract" in self.modules:                      
                        self.modules["StringsExtract"](self).run(args)
              
                elif cmd == "ax":
                    if "Analyze" in self.modules:
                        self.check_and_print(self.modules["Analyze"](self).runXREF(args))

                elif cmd == "ae":
                    if "Analyze" in self.modules:
                        self.check_and_print(self.modules["Analyze"](self).EntropyMap())

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
                        decompiler = CapstoneDecompiler(code_chunk, vaddr_start, self.binary_data)
                        pseudo_c = decompiler.run_decompile()

                        if pseudo_c is not None:
                            self.check_and_print(pseudo_c)
                        else:
                            print("[\033[1mERROR\033[0m] Decompiler returned empty data.")
                    else:
                        print("[\033[1mWARNING\033[0m] Cursor position near EOF. Cannot decompile out of bounds.")
                elif cmd == "info":                     
                    engine = InfoValidator(self.binary_data)
                    rep = engine.run_pipeline()
                    self.check_and_print(rep)
                elif cmd == "s" and args:
                    if "Seeker" in self.modules:
                        self.check_and_print(self.modules["Seeker"](self).run(args))

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

               
        