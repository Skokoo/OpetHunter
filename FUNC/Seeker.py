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

#   Binary Search Boundary Tracker, powered by native "C" bisect logic.
#   If your navigation engine triggers virtual memory page faults just to step back 
#   4 bytes to find 'push rbp', go back to writing CSS animations.

import bisect

class Seeker:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):        
        binary = self.shell.binary_data
        base = self.shell.base_address
        size = self.shell.file_size
        
        target = str(args[0]).strip()
        try:
            val = int(target, 16) if target.startswith("0x") else int(target)
        except ValueError:
            return "\n[\033[1mWARNING\033[0m] Invalid address format.\n"
        
        if not (0 <= (val - base) <= size):
            return "\n[\033[1mWARNING\033[0m] Address out of bounds.\n"
        
        points = [base + idx for idx, byte in enumerate(binary) if byte in (0x55, 0xc3)]        
        
        index = bisect.bisect_left(points, val)
        suggest = points[min(len(points) - 1, max(0, index if index < len(points) and points[index] == val else index - 1))] if points else base
        
        self.shell.cursor = val - base

        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        yellow = getattr(self.shell, 'YELLOW', '\033[93m')
        cyan = getattr(self.shell, 'CYAN', '\033[96m')

        return f"Cursor synchronized to: {hex(val)}" if val == suggest else f"\nCursor synchronized to: {hex(val)} {yellow}{bold}[WARNING: Inside Data/Padding]{reset}\n-> {bold}Nearest valid function entry point found at: {hex(suggest)}{reset}\n"