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

   def print_disasm(self, args):
        count = 15
        if args:
            try: count = int(args[0])
            except: pass

        chunk = self.binary_data[self.cursor : self.cursor + (count * 15)]
        vaddr_start = self.base_address + self.cursor

        lines = [f"\n[INFO] Disassembly at {hex(vaddr_start)}", f"{BOLD}Address\t\tHex Bytes\t\tFlow\tInstruction{RESET}", "-" * 85]
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