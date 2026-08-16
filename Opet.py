import sys
import os
import re
import math
from capstone import *

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[34m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

# Opet' v0.1.0
# Copyright 2026 Skokoo
# Licensed under the Apache License, Version 2.0

class Runnow:
    def __init__(self, filepath):
        self.filepath = filepath
        self.cursor = 0x0
        self.base_address = 0x10000000

        try:
            with open(filepath, "rb") as f:
                self.binary_data = bytearray(f.read())
            self.file_size = len(self.binary_data)
        except Exception as e:
            print(f"[WARNING*] Error reading file: {e}")
            sys.exit(1)

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.auto_detect_entry_point()

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
        char_count = len(out_str)
        if char_count > 1500:
            ask = input(f"Do you want to print {char_count} characters? (y/n): ").strip().lower()
            if ask != 'y':
                print("[INFO] Printing canceled.")
                return
        print(out_str)
    def print_disasm(self, args):
        count = 15
        if args:
            try: count = int(args[0])
            except: pass

        chunk = self.binary_data[self.cursor : self.cursor + (count * 15)]
        vaddr_start = self.base_address + self.cursor

        lines = [f"\n[INFO*] Disassembly at {hex(vaddr_start)}", f"{BOLD}Address\t\tHex Bytes\t\tFlow\tInstruction{RESET}", "-" * 85]
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

        lines = [f"\n[INFO] Hex Dump at {hex(vaddr_start)}", f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII", "-" * 75]
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
    def find_xrefs(self):
        target_vaddr = self.base_address + self.cursor
        lines = [f"\n[INFO] Scanning XREFs for address: {hex(target_vaddr)}..."]
        found_xrefs = 0

        for insn in self.cs.disasm(self.binary_data, self.base_address):
            if insn.mnemonic.startswith('j') or insn.mnemonic == 'call':
                if hex(target_vaddr) in insn.op_str:
                    lines.append(f"  {GREEN}[XREF]{RESET} Found at {hex(insn.address)} -> ({insn.mnemonic} {insn.op_str})")
                    found_xrefs += 1

        if found_xrefs == 0:
            lines.append("[ERROR] No external XREFs found for this address.")
        lines.append("")
        self.check_and_print("\n".join(lines))

    def analyze_entropy_map(self):
        lines = [f"\n[INFO] Shannon Entropy Analysis", "Block\tVirtual Addr\tScore\t\tStatus / Graph", "-" * 75]
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

    def print_strings(self, args):
        filter_keyword = args[0].lower() if args else None
        lines = [f"\n[INFO] Extracting ASCII strings (Min length: 5)..."]
        matches = re.finditer(b"[\\x20-\\x7E]{5,}", self.binary_data)

        for match in matches:
            raw_str = match.group().decode('ascii', errors='ignore')
            if filter_keyword and filter_keyword not in raw_str.lower(): continue
            offset = match.start()
            vaddr = self.base_address + offset

            if any(x in raw_str.lower() for x in ["http", ".exe", "select", "cmd", "password"]): 
                lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> {RED}{raw_str}{RESET}")
            elif any(x in raw_str.lower() for x in ["debug", "assert", "gcc"]): 
                lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> {CYAN}{raw_str}{RESET}")
            else:
                lines.append(f"  {hex(offset)}\t{hex(vaddr)}\t-> {GREEN}{raw_str}{RESET}")
        lines.append("")
        self.check_and_print("\n".join(lines))

    def run_shell(self):
        filename = os.path.basename(self.filepath)
        print(f"[INFO] Loaded: {filename} ({self.file_size} bytes)")

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

                if cmd in ["q", "exit"]: 
                    break
                elif cmd in ["h", "help", "?"]:
                    help_text = (f"\n{BOLD}Available Commands:{RESET}\n"
                                 f"  pd [lines] : Disassembly view (Default: 15 lines)\n"
                                 f"  px [bytes] : Hex-Dump view (Default: 128 bytes)\n"
                                 f"  ax         : Scan external XREFs call references\n"
                                 f"  ae         : Check file encryption using Shannon Entropy\n"
                                 f"  iz [filter]: Extract static ASCII strings from binary\n"
                                 f"  s <offset> : Seek cursor to target virtual address\n"
                                 f"  !<command> : Execute system shell command (e.g. !ls, !clear)\n"
                                 f"  h, help    : Show this commands list\n"
                                 f"  q, exit    : Close the program\n")
                    self.check_and_print(help_text)
                elif cmd == "pd": self.print_disasm(args)
                elif cmd == "px": self.print_hex_dump(args)
                elif cmd == "ax": self.find_xrefs()
                elif cmd == "ae": self.analyze_entropy_map()
                elif cmd == "iz": self.print_strings(args)
                elif cmd == "s" and args:
                    try:
                        target = args[0]
                        val = int(target, 16) if target.startswith("0x") else int(target)
                        if 0 <= (val - self.base_address) <= self.file_size:
                            self.cursor = val - self.base_address
                        else:
                            print("[WARNING] Address out of bounds.")
                    except ValueError:
                        print("[WARNING] Invalid address format.")
                else:
                    print("[WARNING] Unknown command. Type 'help' for options.")
            except (KeyboardInterrupt, EOFError):
                print("\n[INFO] Exiting...")
                break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <binary_path>")
        sys.exit(1)

    engine = Runnow(sys.argv[1])
    engine.run_shell()
                        