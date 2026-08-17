import os
import sys

# Opet' v0.1.0
# Copyright 2026 Skokoo
# Licensed under the Apache License, Version 2.0

try:
    from Gather import BinaryGatherer
except ImportError:
    print("[ERROR*] Gather.py cannot be imported inside INFO folder.")

class InfoValidator:
    def __init__(self, data_bytes):
        self.raw = data_bytes
        self.sz = len(data_bytes)

    def eval_report(self, raw_rep):       
        is_text = False
        try:            
            sample = self.raw[:500]
            printable = sum(1 for x in sample if 32 <= x <= 126 or x in)
            if len(sample) > 0 and (printable / len(sample)) > 0.9:
                is_text = True
        except:
            pass

        lines = raw_rep.split("\n")
        buffed = []

        for line in lines:           
            if "Format :" in line and is_text:
                line = "* Format : Plain Text File (False Binary Mask Detected!)"
            if "Comp   :" in line and is_text:
                line = "* Comp   : None (Text match only, not compiled)"
            if "Linker :" in line and is_text:
                line = "* Linker : None"                
            
            if "UPX" in line and not is_text:
                line = line.replace("UPX", "\033[1m[WARNING**] UPX\033[0m")

            buffed.append(line)

        return "\n".join(buffed)
