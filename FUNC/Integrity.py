class Integrity:
    def __init__(self, instance):
        self.shell = instance

    def run(self, args):
        binary = self.shell.binary_data
        size = self.shell.file_size
        base = self.shell.base_address

        if size < 64:
            return "[\033[1mERROR\033[0m] Binary file too small to be a valid ELF structure."

        bold = getattr(self.shell, 'BOLD', '\033[1m')
        reset = getattr(self.shell, 'RESET', '\033[0m')
        white = getattr(self.shell, 'WHITE', '\033[97m')

        lines = [
            f"\n============================================================",
            f" [INFO] Anti-tamper & Binary integrity",
            f"============================================================",
            f"  * Target File Size : {size} bytes"
        ]
        
        if len(binary) < 4 or list(binary[:4]) != [0x7f, 0x45, 0x4c, 0x46]:           
            return f"[\033[1mWARNING\033[0m] Command 'ai' is optimized for ELF/Native .so binaries. Format mismatched."

        lines.append(f"  * ELF Magic Status : {bold}Valid/ok (7f 45 4c 46){reset}")
     
        # Offset 0x28 (40): Start of section headers (e_shoff)
        # Offset 0x3a (58): Number of section headers (e_shnum)
        shoff = int.from_bytes(binary[40:48], "little")
        shnum = int.from_bytes(binary[58:60], "little")
        
        corrupted = shoff >= size or (shoff + (shnum * 64) > size) if shnum > 0 else False       
        
        status_table = f"[{bold}INFO{reset}] Section Header Table points to invalid EOF bounds.{reset}" if corrupted else f"{bold}INTECT (Standard Linux Section Mapping){reset}"
        lines.append(f"  * Header Integrity : {status_table}")
        
        flat_str = binary.lower()
        is_stripped = b".symtab" not in flat_str and b".strtab" not in flat_str
        status_symbols = f"[{bold}INFO{reset}] Function names hidden by developer" if is_stripped else f"[{bold}INFO{reset}] Debug symbols available"
        lines.append(f"  * Symbol Visibility: {status_symbols}")
        
        has_rwx = b"mprotect" in flat_str or b"ptrace" in flat_str
        status_rwx = f"[{bold}WARNING{reset}] Contains dynamic injection or trace hooks primitives." if has_rwx else f"[{bold}INFO{reset}] No malicious hook signatures found"
        lines.append(f"  * Threat Indicators: {status_rwx}")
        
        verdict = f"[{bold}ALERT{reset}] This file shows anti analysis or tampering characteristics." if (corrupted or has_rwx) else f"{green}{bold}[{bold}INFO{reset}] Binary template structures comply with standard runtime rules."
        
     
        lines.append(f"  * Final verdict    : {verdict}"\n)       

        return "\n".join(lines)