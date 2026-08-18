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

class AnalyzeEngine:
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