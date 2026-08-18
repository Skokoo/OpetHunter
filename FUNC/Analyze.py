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

class Analyze:
    def __init__(self, instance):
        self.shell = instance

    def runXREF(self, args):
        target = self.shell.base_address + self.shell.cursor
        lines = [f"\n[\033[1mINFO\033[0m] Scanning XREFs for address: {hex(target)}..."]
        found = 0
       
        architecture = "x86"
        if len(self.shell.binary_data) >= 20:
            if self.shell.binary_data[18] == 0xb7:
                architecture = "arm"

        bold = self.shell.BOLD
        reset = self.shell.RESET
        white = self.shell.WHITE
        magenta = self.shell.MAGENTA
        red = self.shell.RED

        for insn in self.shell.cs.disasm(self.shell.binary_data, self.shell.base_address):
            mnemonic = insn.mnemonic        
            
            is_branch = mnemonic.startswith('j') or mnemonic in ['call', 'b', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz']
            if not is_branch:
                continue

            destination = None
            
            if len(insn.operands) > 0:
                operand = insn.operands[0]
                if hasattr(operand, 'imm'):
                    destination = operand.imm
            
            if destination is None:
                match = re.search(r'0x[0-9a-fA-F]+', insn.op_str)
                if match:
                    destination = int(match.group(0), 16)
            
            if destination is None and "rip" in insn.op_str:
                match = re.search(r'0x[0-9a-fA-F]+', insn.op_str)
                if match:
                    offset = int(match.group(0), 16)                   
                    destination = insn.address + insn.size + offset
           
            if destination == target:
                color = red if mnemonic.startswith('j') or mnemonic in ['b', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz'] else magenta
                flow = "[JMP]" if mnemonic.startswith('j') or mnemonic in ['b', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz'] else "[CALL]"
                
                lines.append(f"  {white}{flow}{reset} Found at {hex(insn.address)} -> ({color}{bold}{mnemonic}{reset} {insn.op_str})")
                found += 1

        if found == 0:
            lines.append("[\033[1mERROR\033[0m] No external XREFs found for this address.")
        lines.append("")
        return "\n".join(lines)

    def EntropyMap(self):
        size = self.shell.file_size
        block = 512
        if size > 5000000:
            block = 65536
        elif size > 1000000:
            block = 4096
        elif size > 500000:
            block = 2048

        lines = [
            f"\n[\033[1mINFO\033[0m] Shannon Entropy Analysis (Block Size: {block} bytes)", 
            "Block\tVirtual Addr\tScore\t\tStatus / Graph", 
            "-" * 75
        ]

        red = self.shell.RED
        yellow = self.shell.YELLOW
        green = self.shell.GREEN
        bold = self.shell.BOLD
        reset = self.shell.RESET
        
        charts = ["█" * int(e * 3.5) for e in [x * 0.05 for x in range(161)]]
        
        for index in range(0, size, block):
            chunk = self.shell.binary_data[index : index + block]
            entropy = self.shell.calculate_entropy(chunk)           
            
            chart = charts[min(160, max(0, int(entropy * 20)))]
            vaddr = self.shell.base_address + index
            number = index // block
            
            if entropy > 6.8:   
                status = f"{red}{bold}[PACKED]{reset} {red}{chart}{reset}"
            elif entropy > 4.2: 
                status = f"{yellow}[CODE]  {reset} {yellow}{chart}{reset}"
            else:               
                status = f"{green}[DATA]  {reset} {green}{chart}{reset}"

            lines.append(f"#{number}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{status}")
            
        lines.append("")
        return "\n".join(lines)