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

    def run_decompile(self):       
        in_function = False
        func_counter = 0
        indent = "    "

        instructions = list(self.cs.disasm(self.binary_data, self.base_address))

        if not instructions:
            print("[ERROR] No valid binary instructions found to decompile.")
            return

        for i, insn in enumerate(instructions):           
            if insn.mnemonic == "push" and "rbp" in insn.op_str:
                func_counter += 1
                in_function = True
                print(f"\n// Function_{func_counter} Detected in address {hex(insn.address)}")
                print(f"void function_{func_counter}() {{")
                continue

            if not in_function and i == 0:
                func_counter += 1
                in_function = True                
                print(f"void entry_point() {{")

            clean_op = insn.op_str.replace("qword ptr", "").replace("dword ptr", "").replace("byte ptr", "").strip()
            ops = [o.strip() for o in clean_op.split(",")] if "," in clean_op else [clean_op]

            if insn.mnemonic == "lea" and len(ops) == 2:
                inner_addr = ops[1].replace("[", "").replace("]", "")
                print(f"{indent}{ops[0]} = &({inner_addr});")

            elif insn.mnemonic == "mov" and len(ops) == 2:
                dest, src = ops[0], ops[1]                
                if dest.startswith("[") and dest.endswith("]"):
                    dest = f"*{dest}"
                if src.startswith("[") and src.endswith("]"):
                    src = f"*{src}"
                print(f"{indent}{dest} = {src};")

            elif insn.mnemonic == "xor" and len(ops) == 2:
                if ops[0] == ops[1]:
                    print(f"{indent}{ops[0]} = 0; // Pembersihan register")
                else:
                    print(f"{indent}{ops[0]} = {ops[0]} ^ {ops[1]};")

            elif insn.mnemonic == "add" and len(ops) == 2:
                print(f"{indent}{ops[0]} += {ops[1]};")
            elif insn.mnemonic == "sub" and len(ops) == 2:
                print(f"{indent}{ops[0]} -= {ops[1]};")
            elif insn.mnemonic == "imul" and len(ops) == 2:
                print(f"{indent}{ops[0]} *= {ops[1]};")

            elif insn.mnemonic == "call":
                print(f"{indent}call_subroutine({clean_op});")

            elif insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                condition = "status_flag"                
                if i > 0 and instructions[i-1].mnemonic == "cmp":
                    prev_clean = instructions[i-1].op_str.replace("qword ptr", "").replace("dword ptr", "").strip()
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

                print(f"{indent}if ({condition}) {{ goto {clean_op}; }}")

            elif insn.mnemonic == "jmp":
                print(f"{indent}goto {clean_op};")

            if insn.mnemonic in ["ret", "hlt"]:
                print(f"{indent}return;")
                print("} // End Of Block\n")
                in_function = False

        if in_function:
            print(f"{indent}return;")
            print("}")                   