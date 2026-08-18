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

class Hexdump:
    def __init__(self, s):
        self.shell = s

    def run(self, args):
        sz = 128
        if args and isinstance(args, list) and len(args) > 0:
            try: sz = int(args[0])
            except: pass

        cur = self.shell.cursor
        base = self.shell.base_address
        dat = self.shell.binary_data
        
        chk = dat[cur : cur + sz]
        va = base + cur

        W = self.shell.WHITE
        G = self.shell.GREEN
        R = self.shell.RED
        RST = self.shell.RESET      
        c_fmt = ["" for _ in range(256)]
        a_fmt = ["" for _ in range(256)]
        for b in range(256):
            if b == 0x00:
                c_fmt[b] = f"{W}00{RST} "
                a_fmt[b] = f"{W}.{RST}"
            elif 0x20 <= b <= 0x7E:
                c_fmt[b] = f"{G}{b:02x}{RST} "
                a_fmt[b] = f"{G}{chr(b)}{RST}"
            else:
                c_fmt[b] = f"{R}{b:02x}{RST} "
                a_fmt[b] = f"{R}.{RST}"

        out = [
            f"\n[\033[1mINFO\033[0m] Hex Dump at {hex(va)}", 
            f"  Offset      00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ASCII", 
            "-" * 75
        ]        
        
        for i in range(0, len(chk), 16):
            sub = chk[i:i+16]
            
            if len(sub) == 16:
                h_str = "".join(c_fmt[b] if idx != 8 else " " + c_fmt[b] for idx, b in enumerate(sub))
                a_str = "".join(a_fmt[b] for b in sub)
            else:                
                h_str = "".join(c_fmt[b] if idx != 8 else " " + c_fmt[b] for idx, b in enumerate(sub))
                a_str = "".join(a_fmt[b] for b in sub)
                rem = 16 - len(sub)
                spc = rem * 3
                if len(sub) <= 8:
                    spc += 1
                h_str += " " * spc

            out.append(f"  {hex(va + i)}  {h_str.rstrip()}  {a_str}")
            
        out.append("-" * 75 + "\n")
        return "\n".join(out)