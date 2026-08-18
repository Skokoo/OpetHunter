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

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"

class Disasm:
    def __init__(self, shell_instance):
        self.shell = shell_instance

    def run(self, args):
        count = 15
        if args and isinstance(args, list) and len(args) > 0:
            try: count = int(args[0])
            except: pass

        chunk = self.shell.binary_data[self.shell.cursor : self.shell.cursor + (count * 15)]
        vaddr_start = self.shell.base_address + self.shell.cursor

        lines = [f"\n[\033[1mINFO\033[0m] Disassembly at {hex(vaddr_start)}", f"{self.shell.BOLD}Address\t\tHex Bytes\t\tFlow\tInstruction{self.shell.RESET}", "-" * 85]
        for insn in self.shell.cs.disasm(chunk, vaddr_start):
            hex_bytes = "".join(f"{b:02x}" for b in insn.bytes).ljust(18)

            op_str_colored = insn.op_str
            op_str_colored = re.sub(r'\b(r[a-d]x|e[a-d]x|rsp|rbp|esp|ebp|rsi|rdi|r\d+)\b', f"{self.shell.BOLD}\\1{self.shell.RESET}", op_str_colored)
            op_str_colored = re.sub(r'(0x[0-9a-fA-F]+)', f"{self.shell.BOLD}\\1{self.shell.RESET}", op_str_colored)

            mnemonic_colored = insn.mnemonic
            flow_line = f"{self.shell.WHITE}│{self.shell.RESET}"

            if insn.mnemonic.startswith('j'):
                mnemonic_colored = f"{self.shell.RED}{self.shell.BOLD}{insn.mnemonic}{self.shell.RESET}"
                flow_line = f"{self.shell.BOLD}├── [JMP]{self.shell.RESET}"
            elif insn.mnemonic == 'call':
                mnemonic_colored = f"{self.shell.MAGENTA}{self.shell.BOLD}{insn.mnemonic}{self.shell.RESET}"
                flow_line = f"{self.shell.MAGENTA}├── [CALL]{self.shell.RESET}"
            elif insn.mnemonic in ['ret', 'hlt']:
                mnemonic_colored = f"{self.shell.YELLOW}{self.shell.BOLD}{insn.mnemonic}{self.shell.RESET}"
                flow_line = f"{self.shell.YELLOW}└── [END]{self.shell.RESET}"
            elif insn.mnemonic in ['xor', 'sub', 'add', 'cmp']:
                mnemonic_colored = f"{self.shell.GREEN}{insn.mnemonic}{self.shell.RESET}"

            lines.append(f"  {self.shell.WHITE}{hex(insn.address)}{RESET if not hasattr(self.shell, 'RESET') else self.shell.RESET}\t{hex_bytes}\t{flow_line}\t{mnemonic_colored} {op_str_colored}")
        lines.append("-" * 85 + "\n")
        return "\n".join(lines)