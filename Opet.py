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

        self.modules = {}
        func_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FUNC")
        
        if not os.path.exists(func_dir):
            print(f"[\033[1mERROR\033[0m] The directory 'FUNC' not found in path: {func_dir}")
        else:
            import inspect
            import importlib           
            
            import_targets = [
                ("Disasm", "Disasm"),
                ("HexDump", "Hexdump"),
                ("Strings", "StringsExtract"),
                ("Analyze", "Analyze")
            ]            
            
            for file_name, class_name in import_targets:
                try:
                    mod = importlib.import_module(f"FUNC.{file_name}")
                    cls = getattr(mod, class_name)
                    self.modules[class_name] = cls
                except Exception as e:
                    print(f"[\033[1mERROR\033[0m] Failed to import: {file_name}.{class_name}: {e}")

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

               
        