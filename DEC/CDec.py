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
    def __init__(self, binary_bytes, base_address):
        self.binary_data = binary_bytes
        self.base_address = base_address
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True       
        
        self.reg_cleaner = {}
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            json_path = os.path.join(current_dir, "reg_map.json")
            with open(json_path, "r") as f:
                config = json.load(f)
            self.reg_cleaner = {k: v["clean_name"] for k, v in config["registers"].items()}
        except:           
            pass

    def clean_operand(self, op_str):        
        clean = op_str.replace("qword ptr", "").replace("dword ptr", "")
        clean = clean.replace("byte ptr", "").replace("word ptr", "").strip()       

        stack_match = re.search(r'\[(rbp|rsp)\s*([-+])\s*(0x[0-9a-fA-F]+|[0-9]+)\]', clean)
        if stack_match:
            offset = stack_match.group(3)
            return f"local_var_{offset}h"            

        for reg, var in self.reg_cleaner.items():
            clean = re.sub(rf'\b{reg}\b', var, clean)
        return clean

    def resolve_inline_string(self, insn):        
        try:            
            if insn.mnemonic == "lea" and "rip" in insn.op_str:
                match = re.search(r'0x[0-9a-fA-F]+', insn.op_str)
                if match:
                    offset = int(match.group(), 16)                    
                    target_offset = (insn.address + insn.size + offset) - self.base_address
                    if 0 <= target_offset < len(self.binary_data):                        
                        chunk = self.binary_data[target_offset : target_offset + 32]
                        str_match = re.match(b"[\x20-\x7E]{4,}", chunk)
                        if str_match:
                            clean_str = str_match.group().decode('ascii', errors='ignore')
                            return f'"{clean_str}"'
        except:
            pass
        return None 
    def run_decompile(self):       
        in_function = False
        func_counter = 0
        indent = "        "
        output_lines = []

        try:
            instructions = list(self.cs.disasm(self.binary_data, self.base_address))
        except:
            return "    // disassembly critical failure."

        if not instructions:
            return "    // No valid execution to decompile."

        loop_starts = set()
        for insn in instructions:
            if insn.mnemonic == "jmp" or insn.mnemonic.startswith("j"):
                try:
                    target_addr = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)                   
                    if target_addr < insn.address:
                        loop_starts.add(target_addr)
                except:
                    pass

        for i, insn in enumerate(instructions):                       
            if insn.address in loop_starts:                
                output_lines.append(f"{indent}while (status_flag) {{ // Loop Recovery Triggered")
                indent += "    "

            if insn.mnemonic == "push" and "rbp" in insn.op_str:
                func_counter += 1
                in_function = True
                output_lines.append(f"    // Function detected at {hex(insn.address)}")
                output_lines.append(f"    void function_{hex(insn.address)}() {{")
                continue

            if not in_function and i == 0:
                in_function = True                
                output_lines.append(f"    void entry_point_{hex(insn.address)}() {{")

            clean_op = self.clean_operand(insn.op_str)
            ops = [o.strip() for o in clean_op.split(",")] if "," in clean_op else [clean_op]
            resolved_str = self.resolve_inline_string(insn)

            if insn.mnemonic == "lea" and len(ops) == 2:
                val = resolved_str if resolved_str else f"&({ops[1]})"
                output_lines.append(f"{indent}{ops[0]} = {val};")
            elif insn.mnemonic == "mov" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} = {ops[1]};")
            elif insn.mnemonic == "xor" and len(ops) == 2:
                if ops[0] == ops[1]: output_lines.append(f"{indent}{ops[0]} = 0;")
                else: output_lines.append(f"{indent}{ops[0]} ^= {ops[1]};")
            elif insn.mnemonic in ["add", "sub", "imul", "and", "or", "shl", "shr"] and len(ops) == 2:
                sign_map = {"add": "+=", "sub": "-=", "imul": "*=", "and": "&=", "or": "|=", "shl": "<<=", "shr": ">>="}
                output_lines.append(f"{indent}{ops[0]} {sign_map[insn.mnemonic]} {ops[1]};")
            elif insn.mnemonic == "call":
                output_lines.append(f"{indent}sub_{clean_op}();")

            elif insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                condition = "status_flag"                
                if i > 0 and instructions[i-1].mnemonic == "cmp":
                    prev_clean = self.clean_operand(instructions[i-1].op_str)
                    prev_ops = [o.strip() for o in prev_clean.split(",")]
                    if len(prev_ops) == 2:                        
                        signs = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!=", "jl": "<", "jg": ">", "jle": "<=", "jge": ">="}
                        op_sign = signs.get(insn.mnemonic, "==")
                        condition = f"{prev_ops[0]} {op_sign} {prev_ops[1]}"

                try:
                    target_addr = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                    if target_addr < insn.address:
                        indent = indent[:-4] if len(indent) > 8 else "        "
                        output_lines.append(f"{indent}}} // End of While Loop")
                        continue
                except:
                    pass
                output_lines.append(f"{indent}if ({condition}) {{ goto block_{clean_op}; }}")

            elif insn.mnemonic == "jmp":
                try:
                    target_addr = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                    if target_addr < insn.address:
                        indent = indent[:-4] if len(indent) > 8 else "        "
                        output_lines.append(f"{indent}}} // End of While Loop")
                        continue
                except:
                    pass
                output_lines.append(f"{indent}goto block_{clean_op};")
            elif insn.mnemonic in ["ret", "hlt"]:
                output_lines.append(f"{indent}return;")
                output_lines.append("    }")
                in_function = False

        if in_function:
            output_lines.append(f"{indent}return;")
            output_lines.append("    }")                   

        return "\n".join(output_lines) if output_lines else "    // disassembly block."