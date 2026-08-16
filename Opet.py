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
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BG_RED  = "\033[41m"

class PyR2GodMode:
    def __init__(self, filepath):
        self.filepath = filepath
        self.cursor = 0x0
        self.base_address = 0x10000000
        
        try:
            with open(filepath, "rb") as f:
                self.binary_data = bytearray(f.read())
            self.file_size = len(self.binary_data)
        except Exception as e:
            print(f"[WARNING] Faild to read file: {e}")
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

    def print_disasm(self, args):       
        count = 15
        if args:
            try: count = int(args[0])
            except: pass

        chunk = self.binary_data[self.cursor : self.cursor + (count * 15)]
        vaddr_start = self.base_address + self.cursor
        
        print(f"[INFO] View AT {hex(vaddr_start)} {RESET}")
        print(f"{BOLD}Address\tHex Bytes\t\tFlow\tInstruction{RESET}")
        print("  " + "="*85)
        
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

            print(f"  {WHITE}{hex(insn.address)}{RESET}\t{hex_bytes}\t{flow_line}\t{mnemonic_colored} {op_str_colored}")
        print("  " + "="*85 + "\n")

    def print_hex_dump(self, args):
        size = 128
        if args:
            try: size = int(args[0])
            except: pass
            
        chunk = self.binary_data[self.cursor : self.cursor + size]
        vaddr_start = self.base_address + self.cursor
        
        print(f"\n{BOLD}{YELLOW}[+-- Hex Dump matrix AT {hex(vaddr_start)} --+]{RESET}")
        print(f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII Text")
        print("  " + "-"*75)
        
        for i in range(0, len(chunk), 16):
            sub_chunk = chunk[i:i+16]
            hex_str = ""
            ascii_str = ""
            
            for idx, b in enumerate(sub_chunk):
                if idx == 8: hex_str += " "               
                if b == 0x00: color = WHITE
                elif 0x20 <= b <= 0x7E: color = GREEN
                else: color = RED
                
                hex_str += f"{color}{b:02x}{RESET} "
                ascii_str += f"{color}{chr(b)}{RESET}" if 0x20 <= b <= 0x7E else f"{WHITE}.{RESET}"
                
            line_vaddr = vaddr_start + i
            print(f"  {hex(line_vaddr)}  {hex_str.ljust(60)}  {ascii_str}")
        print("  " + "-"*75 + "\n")

    def find_xrefs(self):        
        target_vaddr = self.base_address + self.cursor
        print(f"\n[*] Memulai Scanning XREFs menuju alamat virtual: {BOLD}{YELLOW}{hex(target_vaddr)}{RESET}...")
        found_xrefs = 0
            
        for insn in self.cs.disasm(self.binary_data, self.base_address):            
            if insn.mnemonic.startswith('j') or insn.mnemonic == 'call':
                if hex(target_vaddr) in insn.op_str:
                    print(f"{GREEN}[XREF FOUND]{RESET} Called by {BOLD}{CYAN}{hex(insn.address)}{RESET} ➔ ({insn.mnemonic} {insn.op_str})")
                    found_xrefs += 1
                    
        if found_xrefs == 0:
            print("[WARNING] No reference call (XREF) external targgeting to this address.")
        print()

    def analyze_entropy_map(self):      
        print(f"\n{BOLD}[INFO] Mapping File Encryption Analysis (Shannon Entropy Tracker){RESET}")
        block_size = 512
        print("Block Index\tVirtual Address\tEntropy Score\tVisual Density Chart")
        print("  " + "-"*75)
        
        for i in range(0, self.file_size, block_size):
            block = self.binary_data[i:i+block_size]
            entropy = self.calculate_entropy(block)           
            
            bar_len = int(entropy * 4)
            chart = "█" * bar_len
            
            if entropy > 6.5:   color = f"{RED}{BOLD}[ENCRYPTED/PACKED]{RESET} {RED}"
            elif entropy > 4.5: color = f"{YELLOW}[CODE SECTION]   {RESET} {BOLD}"
            else:               color = f"{GREEN}[TEXT/DATA]      {RESET} {BOLD}"
            
            vaddr = self.base_address + i
            print(f"Block #{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{color}{chart}{RESET}")
        print()

    def print_strings(self, args):        
        filter_keyword = args[0].lower() if args else None
        print(f"\n[INFO] Statc Strings extraction matrix keyword filter: {filter_keyword}) ---")
        matches = re.finditer(b"[\\x20-\\x7E]{5,}", self.binary_data)
        
        for match in matches:
            raw_str = match.group().decode('ascii', errors='ignore')
            if filter_keyword and filter_keyword not in raw_str.lower(): continue
            
            offset = match.start()
            vaddr = self.base_address + offset
                        
            color = GREEN
            if any(x in raw_str.lower() for x in ["http", ".exe", "select", "cmd", "password"]): color = RED
            elif any(x in raw_str.lower() for x in ["debug", "assert", "gcc"]): color = CYAN
            
            print(f"  {hex(offset)}\t{hex(vaddr)}\t➔ {color}{raw_str}{RESET}")
        print()

    def run_shell(self):
        filename = os.path.basename(self.filepath)        
        print(f"[INFO] Target Loaded: {BOLD}{YELLOW}{filename}{RESET} ({self.file_size} bytes)")
        print(f"[INFO] Commands: [{BOLD}pd (Disasm), px (Hex-Dump), ax (XREFs), ae (Entropy Map), iz (Strings), s (Seek), q (Exit){RESET}]\n")
        
        while True:
            try:
                cmd_input = input(f"{BOLD}{WHITE}pyr2-god@{RESET}{RED}{hex(self.cursor)}{RESET}> ").strip().split()
                if not cmd_input: continue
                
                cmd = cmd_input[0]
                args = cmd_input[1:] if len(cmd_input) > 1 else None
                
                if cmd in ["q", "exit"]: break
                elif cmd == "pd": self.print_disasm(args)
                elif cmd == "px": self.print_hex_dump(args)
                elif cmd == "ax": self.find_xrefs()
                elif cmd == "ae": self.analyze_entropy_map()
                elif cmd == "iz": self.print_strings(args)
                elif cmd == "s" and args:
                    target = args[0]
                    if target.startswith("0x"): self.cursor = int(target, 16)
                    else: self.cursor = int(target)
                else:
                    print("[ERROR] Command nout found. Available Commands: pd [lines], px [bytes], ax (XREFs), ae (Entropy), iz [filter], s <off>, q")
            except KeyboardInterrupt:
                print("\nUse 'q' to exit.")
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{BOLD}Usage: python [YOUR FILE NAME].py <bin_file>{RESET}")
        sys.exit(1)  
    target_filepath = sys.argv[1]    
    app = PyR2GodMode(target_filepath)
    app.run_shell()
