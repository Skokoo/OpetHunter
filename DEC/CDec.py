import re
from capstone import *

# Opet' v0.1.0
# Copyright 2026 Skokoo
# Licensed under the Apache License, Version 2.0

class CapstoneDecompiler:
    def __init__(self, binary_bytes, base_address):
        self.binary_data = binary_bytes
        self.base_address = base_address
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True       
        
        self.reg_cleaner = {
            "rax": "local_res", "eax": "local_res_32",
            "rdi": "param_1", "edi": "param_1_32",
            "rsi": "param_2", "esi": "param_2_32",
            "rdx": "param_3", "edx": "param_3_32",
            "rcx": "param_4", "ecx": "param_4_32",
            "r8": "param_5", "r9": "param_6"
        }

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

    def run_decompile(self):       
        in_function = False
        func_counter = 0
        indent = "        "
        output_lines = []

        try:
            instructions = list(self.cs.disasm(self.binary_data, self.base_address))
        except:
            return "    // Capstone disassembly critical failure."

        if not instructions:
            return "    // No valid execution vectors to decompile."
        for i, insn in enumerate(instructions):           
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

            if insn.mnemonic == "lea" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} = &({ops[1]});")
            elif insn.mnemonic == "mov" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} = {ops[1]};")
            elif insn.mnemonic == "xor" and len(ops) == 2:
                if ops[0] == ops[1]: output_lines.append(f"{indent}{ops[0]} = 0;")
                else: output_lines.append(f"{indent}{ops[0]} ^= {ops[1]};")
            elif insn.mnemonic == "add" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} += {ops[1]};")
            elif insn.mnemonic == "sub" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} -= {ops[1]};")
            elif insn.mnemonic == "imul" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} *= {ops[1]};")
            elif insn.mnemonic == "and" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} &= {ops[1]};")
            elif insn.mnemonic == "or" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} |= {ops[1]};")
            elif insn.mnemonic == "shl" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} <<= {ops[1]};")
            elif insn.mnemonic == "shr" and len(ops) == 2:
                output_lines.append(f"{indent}{ops[0]} >>= {ops[1]};")
            elif insn.mnemonic == "call":
                output_lines.append(f"{indent}sub_{clean_op}();")

            elif insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                condition = "status_flag"                
                if i > 0 and instructions[i-1].mnemonic == "cmp":
                    prev_clean = self.clean_operand(instructions[i-1].op_str)
                    prev_ops = [o.strip() for o in prev_clean.split(",")]
                    if len(prev_ops) == 2:                        
                        if insn.mnemonic in ["je", "jz"]: op_sign = "=="
                        elif insn.mnemonic in ["jne", "jnz"]: op_sign = "!="
                        elif insn.mnemonic in ["jl", "jnge"]: op_sign = "<"
                        elif insn.mnemonic in ["jg", "jnle"]: op_sign = ">"
                        elif insn.mnemonic in ["jle", "jng"]: op_sign = "<="
                        elif insn.mnemonic in ["jge", "jnl"]: op_sign = ">="
                        else: op_sign = "=="
                        condition = f"{prev_ops[0]} {op_sign} {prev_ops[1]}"
                output_lines.append(f"{indent}if ({condition}) {{ goto block_{clean_op}; }}")

            elif insn.mnemonic == "jmp":
                output_lines.append(f"{indent}goto block_{clean_op};")
            elif insn.mnemonic in ["ret", "hlt"]:
                output_lines.append(f"{indent}return;")
                output_lines.append("    }")
                in_function = False

        if in_function:
            output_lines.append(f"{indent}return;")
            output_lines.append("    }")                   

        return "\n".join(output_lines)      