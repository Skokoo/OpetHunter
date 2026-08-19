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
import os
import json
from capstone import *

class CapstoneDecompiler:
    def __init__(self, binary, base):
        self.binary_data = binary
        self.base_address = base
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True       
        self.reg_cleaner = {}
        try:
            folder = os.path.dirname(os.path.abspath(__file__))
            config = os.path.join(folder, "reg_map.json")
            with open(config, "r") as stream:
                data = json.load(stream)
            self.reg_cleaner = {key: val["clean_name"] for key, val in data["registers"].items()}
        except:           
            pass

    def clean_operand(self, op_str):        
        clean = op_str.replace("qword ptr", "").replace("dword ptr", "")
        clean = clean.replace("byte ptr", "").replace("word ptr", "").strip()       
        match = re.search(r'\[(rbp|rsp)\s*([-+])\s*(0x[0-9a-fA-F]+|[0-9]+)\]', clean)
        if match:
            return f"local_var_{match.group(3)}h"            
        for reg, var in self.reg_cleaner.items():
            clean = re.sub(rf'\b{reg}\b', var, clean)
        return clean

    def resolve_inline_string(self, insn):        
        try:            
            if insn.mnemonic == "lea" and "rip" in insn.op_str:
                match = re.search(r'0x[0-9a-fA-F]+', insn.op_str)
                if match:
                    target = (insn.address + insn.size + int(match.group(), 16)) - self.base_address
                    if 0 <= target < len(self.binary_data):                        
                        chunk = self.binary_data[target : target + 32]
                        regex = re.match(b"[\x20-\x7E]{4,}", chunk)
                        if regex:
                            return f'"{regex.group().decode("ascii", errors="ignore")}"'
        except:
            pass
        return None 

    def run_decompile(self):       
        active = False
        indent = "        "
        lines = []
        try:
            instructions = list(self.cs.disasm(self.binary_data, self.base_address))
        except:
            return "    // disassembly critical failure."
        if not instructions:
            return "    // No valid execution to decompile."
        
        loops = {int(ins.op_str, 16) if ins.op_str.startswith("0x") else int(ins.op_str) for ins in instructions if (ins.mnemonic == "jmp" or ins.mnemonic.startswith("j")) and (lambda t: t < ins.address)(int(ins.op_str, 16) if ins.op_str.startswith("0x") else int(ins.op_str) if ins.op_str.isdigit() else 0)}
        
        math_signs = {"add": "+=", "sub": "-=", "imul": "*=", "and": "&=", "or": "|=", "shl": "<<=", "shr": ">>="}
        comp_signs = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!=", "jl": "<", "jg": ">", "jle": "<=", "jge": ">="}
        
        handlers = {
            "lea": lambda ops, ins, res, ind: f"{ind}{ops[0]} = {res if res else f'&({ops[1]})'};",
            "mov": lambda ops, ins, res, ind: f"{ind}{ops[0]} = {ops[1]};",
            "xor": lambda ops, ins, res, ind: f"{ind}{ops[0]} = 0;" if ops[0] == ops[1] else f"{ind}{ops[0]} ^= {ops[1]};",
            "call": lambda ops, ins, res, ind: f"{ind}sub_{','.join(ops)}();"
        }

        for index, insn in enumerate(instructions):                       
            if insn.address in loops:                
                lines.append(f"{indent}while (status_flag) {{ // Loop Recovery Triggered")
                indent += "    "

            if insn.mnemonic == "push" and "rbp" in insn.op_str:
                active = True
                lines.append(f"    // Function detected at {hex(insn.address)}\n    void function_{hex(insn.address)}() {{")
                continue

            if not active and index == 0:
                active = True                
                lines.append(f"    void entry_point_{hex(insn.address)}() {{")

            clean = self.clean_operand(insn.op_str)
            ops = [part.strip() for part in clean.split(",")] if "," in clean else [clean]
            resolved = self.resolve_inline_string(insn)
            mnemonic = insn.mnemonic
            
            if mnemonic in handlers and len(ops) >= 2 if mnemonic != "call" else len(ops) >= 1:
                lines.append(handlers[mnemonic](ops, insn, resolved, indent))
            elif mnemonic in math_signs and len(ops) == 2:
                lines.append(f"{indent}{ops[0]} {math_signs[mnemonic]} {ops[1]};")
            elif mnemonic.startswith("j") or mnemonic == "jmp":
                try:
                    target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                    if target < insn.address:
                        indent = indent[:-4] if len(indent) > 8 else "        "
                        lines.append(f"{indent}}} // End of While Loop")
                        continue
                except:
                    pass

                if mnemonic == "jmp":
                    lines.append(f"{indent}goto block_{clean};")
                else:
                    condition = "status_flag"
                    if index > 0 and instructions[index - 1].mnemonic == "cmp":
                        prev_ops = [p.strip() for p in self.clean_operand(instructions[index - 1].op_str).split(",")]
                        if len(prev_ops) == 2:
                            condition = f"{prev_ops[0]} {comp_signs.get(mnemonic, '==')} {prev_ops[1]}"
                    lines.append(f"{indent}if ({condition}) {{ goto block_{clean}; }}")
            elif mnemonic in ["ret", "hlt"]:
                lines.append(f"{indent}return;\n    }}")
                active = False

        if active:
            lines.append(f"{indent}return;\n    }}")                   

        return "\n".join(lines) if lines else "    // disassembly block."
                        