import os
import sys

class Shred:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(current_dir)
        dec_path = os.path.join(root_dir, "DEC")

        if dec_path not in sys.path:
            sys.path.insert(0, dec_path)
        
        try:
            from CDec import CapstoneDecompiler
        except ImportError:
            return f"[\033[1mERROR\033[0m] Importing error: {e}"
 
        binary = self.shell.binary_data
        base = self.shell.base_address
        size = self.shell.file_size
        
        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        cyan = getattr(self.shell, 'CYAN', '\033[96m')

        lines = [
            f"\n[{bold}INFO{reset}] Executing advanced binary shredding sequences.",
            f"[{bold}INFO{reset}] Shredding 1: Triggering integrity forensics mapping pipelines."
        ]

        if "Integrity" in self.shell.modules:
            lines.append(self.shell.modules["Integrity"](self.shell).run(args))
        else:
            lines.append(f"[{bold}WARNING{reset}] Integrity forensics modules bypassed.")

        lines.append(f"[{bold}INFO{reset}] Shredding 2: Scanning global execution matrix and mapping functions.")
        
        points_x86 = [idx for idx in range(len(binary) - 3) if binary[idx:idx+4] == b"\x55\x48\x89\xE5"]
        points_arm = [idx for idx in range(len(binary) - 3) if binary[idx:idx+4] == b"\xFF\x43\x00\xD1"]
        all_funcs = sorted(list(set(points_x86 + points_arm)))

        lines.append(f"[INFO*] Global binary analysis: Discovered {bold}{len(all_funcs)}{reset} native function subroutines.")

        if all_funcs:           
            closest_offset = min(all_funcs, key=lambda x: abs(x - self.shell.cursor))
            target_vaddr = base + closest_offset
            lines.append(f"[INFO*] Smart-Target Lock     : Auto-selected nearest function cluster boundary.")
        else:
            target_vaddr = base + self.shell.cursor
            lines.append(f"[INFO*] Smart-Target Lock     : No distinct signatures found. Falling back to cursor.")
        
        lines.append(f"[INFO*] Localized address cursor : {hex(base + self.shell.cursor)}")
        lines.append(f"[INFO*] Shredder targeted code   : {cyan}{hex(target_vaddr)}{reset}")
        lines.append(f"[{bold}INFO{reset}] Shredding 3: Extracting underlying code structures directly to pseudo-C.")
        
        actual_offset = target_vaddr - base
        chunk_size = 64
        
        if actual_offset + chunk_size <= size:
            code_chunk = binary[actual_offset : actual_offset + chunk_size]
            decompiler = CapstoneDecompiler(code_chunk, target_vaddr, binary)
            pseudo_c = decompiler.run_decompile()
            lines.append(pseudo_c if pseudo_c else "    // Empty decompiler execution stack.")
        else:
            lines.append("    // Targeted offset reaches EOF. Decompilation aborted.")

        lines.append(f"[{bold}INFO{reset}] Binary layers shredded successfully. All execution boundaries exposed.\n")
        return "\n".join(lines)