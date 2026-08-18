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

class HexdumpEngine:
    def __init__(self, shell_instance):
        self.shell = shell_instance

    def run(self, args):
        size = 128
        if args and isinstance(args, list) and len(args) > 0:
            try: size = int(args[0])
            except: pass

        chunk = self.shell.binary_data[self.shell.cursor : self.shell.cursor + size]
        vaddr_start = self.shell.base_address + self.shell.cursor

        WHITE = self.shell.WHITE
        GREEN = self.shell.GREEN
        RED   = self.shell.RED
        RESET = self.shell.RESET

        lines = [f"\n[\033[1mINFO\033[0m] Hex Dump at {hex(vaddr_start)}", f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII", "-" * 75]
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
        return "\n".join(lines)