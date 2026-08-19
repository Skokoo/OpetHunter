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

        return f"Cursor synchronized to: {hex(val)}" if val == suggest else f"\n  Cursor synchronized to: {hex(val)} {yellow}{bold}[WARNING: Inside Data/Padding]{reset}\n-> {bold}Nearest valid function entry point found at: {hex(suggest)}{reset}\n"