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

class Disasm:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        count = 15
        if args and isinstance(args, list) and len(args) > 0:
            try: count = int(args[0])
            except: pass

        cursor = self.shell.cursor
        binary = self.shell.binary_data            
        architecture = "arm" if len(binary) >= 20 and binary[18] == 0xb7 else "x86"     
        chunk = binary[cursor : cursor + (count * 4 if architecture == "arm" else count * 15)]
        vaddr = self.shell.base_address + cursor

        bold, reset, white = self.shell.BOLD, self.shell.RESET, self.shell.WHITE
        red, magenta, yellow, green = self.shell.RED, self.shell.MAGENTA, self.shell.YELLOW, self.shell.GREEN

        lines = [
            f"\n[\033[1mINFO\033[0m] Disassembly at {hex(vaddr)} ({'ARM64' if architecture == 'arm' else 'x86_64'})", 
            f"{bold}Address\t\tHex Bytes\t\tFlow\tInstruction{reset}", 
            "-" * 85
        ]       
        
        if architecture == "arm":
            pattern = r'\b(x\d+|w\d+|sp|wsp|pc|lr|xzr|wzr|q\d+|v\d+|d\d+|s\d+)\b'
        else:
            pattern = r'\b(r[a-d]x|e[a-d]x|rsp|rbp|esp|ebp|rsi|rdi|r\d+|al|bl|cl|dl|ah|bh|ch|dh)\b'

        index = 0
        for insn in self.shell.cs.disasm(chunk, vaddr):
            if index >= count: 
                break

            bytes_str = "".join(f"{b:02x}" for b in insn.bytes).ljust(18)
            operands = insn.op_str

            operands = re.sub(pattern, f"{bold}\\1{reset}", operands)
            operands = re.sub(r'(0x[0-9a-fA-F]+)', f"{bold}\\1{reset}", operands)

            mnemonic = insn.mnemonic
            flow = f"{white}│{reset}"

            if mnemonic.startswith('j') or (architecture == "arm" and mnemonic in ['b', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz']):
                mnemonic = f"{red}{bold}{mnemonic}{reset}"
                flow = f"{bold}├── [JMP]{reset}"
            elif mnemonic == 'call' or (architecture == "arm" and mnemonic == 'bl'):
                mnemonic = f"{magenta}{bold}{mnemonic}{reset}"
                flow = f"{magenta}├── [CALL]{reset}"
            elif mnemonic in ['ret', 'hlt']:
                mnemonic = f"{yellow}{bold}{mnemonic}{reset}"
                flow = f"{yellow}└── [END]{reset}"
            elif mnemonic in ['xor', 'sub', 'add', 'cmp', 'eor', 'subs', 'adds', 'and', 'ands', 'orr', 'eon']:
                mnemonic = f"{green}{mnemonic}{reset}"

            lines.append(f"  {white}{hex(insn.address)}{reset}\t{bytes_str}\t{flow}\t{mnemonic} {operands}")
            index += 1

        lines.append("-" * 85 + "\n")
        return "\n".join(lines)

        