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
    def __init__(self, shell_instance):
        self.shell = shell_instance

    def run(self, args):
        target_vaddr = self.shell.base_address + self.shell.cursor
        lines = [f"\n[\033[1mINFO\033[0m] Scanning XREFs for address: {hex(target_vaddr)}..."]
        found_xrefs = 0

        for insn in self.shell.cs.disasm(self.shell.binary_data, self.shell.base_address):
            if insn.mnemonic.startswith('j') or insn.mnemonic == 'call':
                if hex(target_vaddr) in insn.op_str:
                    lines.append(f"  [XREF] Found at {hex(insn.address)} -> ({insn.mnemonic} {insn.op_str})")
                    found_xrefs += 1

        if found_xrefs == 0:
            lines.append("[\033[1mERROR\033[0m] No external XREFs found for this address.")
        lines.append("")
        return "\n".join(lines)

    def analyze_entropy_map(self):
        lines = [f"\n[\033[1mINFO\033[0m] Shannon Entropy Analysis", "Block\tVirtual Addr\tScore\t\tStatus / Graph", "-" * 75]
        block_size = 512

        RED = self.shell.RED
        YELLOW = self.shell.YELLOW
        GREEN = self.shell.GREEN
        BOLD = self.shell.BOLD
        RESET = self.shell.RESET

        for i in range(0, self.shell.file_size, block_size):
            block = self.shell.binary_data[i:i+block_size]
            entropy = self.shell.calculate_entropy(block)
            bar_len = int(entropy * 4)
            chart = "█" * bar_len
            vaddr = self.shell.base_address + i

            if entropy > 6.5:   
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{RED}{BOLD}[PACKED] {RESET} {RED}{chart}{RESET}")
            elif entropy > 4.5: 
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{YELLOW}[CODE]   {RESET} {YELLOW}{chart}{RESET}")
            else:               
                lines.append(f"#{i//block_size}\t{hex(vaddr)}\t{entropy:.2f}/8.0\t{GREEN}[DATA]   {RESET} {GREEN}{chart}{RESET}")
        lines.append("")
        return "\n".join(lines)