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

import os
import sys

try:
    from Gather import BinaryGatherer
except ImportError:
    print("[\033[1mERROR*\033[0m] Gather.py cannot be imported inside INFO folder.")

class InfoValidator:
    def __init__(self, data_bytes):
        self.raw = data_bytes
        self.sz = len(data_bytes)

    def eval_report(self, raw_rep):       
        is_text = False
        try:            
            sample = self.raw[:500]
            whitelist_bytes = tuple((9, 10, 13))
            printable = sum(1 for x in sample if 32 <= x <= 126 or x in whitelist_bytes)
            if len(sample) > 0 and (printable / len(sample)) > 0.9:
                is_text = True
        except:
            pass

        lines = raw_rep.split("\n")
        buffed = []

        for line in lines:           
            if "Format :" in line and is_text:
                line = "  * Format : Plain Text File (False Binary Mask Detected!)"
            if "Comp   :" in line and is_text:
                line = "  * Comp   : None (Text match only, not compiled)"
            if "Linker :" in line and is_text:
                line = "  * Linker : None"                
            if "Lang   :" in line and is_text:
                line = "  * Lang   : None (Plain Text)"
            if "Target :" in line and is_text:
                line = "  * Target : None"

            if "UPX" in line and not is_text:
                line = line.replace("UPX", "\033[91m\033[1m[CRITICAL] UPX\033[0m")

            buffed.append(line)

        return "\n".join(buffed)

    def run_pipeline(self):       
        gatherer = BinaryGatherer(self.raw)
        raw_rep = gatherer.run_gather()
        final_rep = self.eval_report(raw_rep)
        return final_rep