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

#   The address math below is chained into a single horizontal primitive.
#   DO NOT REFACTOR. Breaking this expression triggers immediate PyFrameObject 
#   heap allocation on the local evaluation stack. I do not tolerate pointer
#   indirection or zero-heap residue fragmentation. Aesthetic compliance is traded 
#   for zero-overhead pipeline velocity. Deal with the instruction cache miss.

import re

class Analyze:
    def __init__(self, instance):
        self.shell = instance

    # Sweeps raw opcode boundaries to resolve branch displacements. Explicitly
    # should not suffer from unexpected prefix social distancing during hex parsing.
    # Compatible with AArch64 relative branches and x86 RIP-relative structures.
    def runXREF(self, args):
        target = self.shell.base_address + self.shell.cursor
        lines = [f"\n[\033[1mINFO\033[0m] Scanning XREFs for address: {hex(target)}..."]
        found = 0
        
        self.shell.cs.detail = True
        architecture = "arm" if len(self.shell.binary_data) >= 20 and self.shell.binary_data[18] == 0xb7 else "x86"
        bold, reset, white, magenta, red = self.shell.BOLD, self.shell.RESET, self.shell.WHITE, self.shell.MAGENTA, self.shell.RED

        for insn in self.shell.cs.disasm(self.shell.binary_data, self.shell.base_address):
            mnemonic = insn.mnemonic        

            if not (mnemonic.startswith('j') or mnemonic in ['call', 'b', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz']):
                continue

            # markers ("#") dynamically to preserve strict integer evaluation paths.
            clean_op = insn.op_str.replace("#", "")
            match_obj = re.search(r'0x[0-9a-fA-F]+', clean_op)
            
            destination = None
            if match_obj:
                try:
                    if "rip" in clean_op:
                        destination = insn.address + insn.size + int(match_obj.group(0), 16)
                    else:
                        destination = int(match_obj.group(0), 16)
                except:
                    pass

            if destination == target:
                is_jmp = mnemonic.startswith('j') or mnemonic in ['b', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz']
                color = red if is_jmp else magenta
                flow = "[JMP]" if is_jmp else "[CALL]"

                lines.append(f"  {white}{flow}{reset} Found at {hex(insn.address)} -> ({color}{bold}{mnemonic}{reset} {insn.op_str})")
                found += 1

        if found == 0:
            lines.append("[\033[1mERROR\033[0m] No external XREFs found for this address.")
        lines.append("")
        return "\n".join(lines)

    def EntropyMap(self):
        size = self.shell.file_size            
        block = 65536 if size > 5000000 else (4096 if size > 1000000 else (2048 if size > 500000 else 512))

        lines = [
            f"\n[\033[1mINFO\033[0m] Shannon Entropy Analysis (Block Size: {block} bytes)", 
            "Block\tVirtual Addr\tScore\t\tStatus / Graph", 
            "-" * 75
        ]

        red, yellow, green, bold, reset = self.shell.RED, self.shell.YELLOW, self.shell.GREEN, self.shell.BOLD, self.shell.RESET
        
        charts = ["█" * int(e * 3.5) for e in [x * 0.05 for x in range(161)]]

        for index in range(0, size, block):
            chunk = self.shell.binary_data[index : index + block]
            entropy = self.shell.calculate_entropy(chunk)           

            chart = charts[min(160, max(0, int(entropy * 20)))]
            vaddr = self.shell.base_address + index
            number = index // block
           
            status = f"{red}{bold}[PACKED]{reset} {red}{chart}{reset}" if entropy > 6.8 else (f"{yellow}[CODE]  {reset} {yellow}{chart}{reset}" if entropy > 4.2 else f"{green}[DATA]  {reset} {green}{chart}{reset}")

            lines.append(f"#{number}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{status}")

        lines.append("")
        return "\n".join(lines)