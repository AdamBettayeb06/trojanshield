"""
scanners/static.py - Stage 1: Static Analysis
==============================================
- Magic byte / file type identification
- PE structure parsing (sections, imports, exports)
- String extraction + IOC matching
- Entropy analysis (detect packed/encrypted payloads)
- Fuzzy hashing
- Import table analysis
- Control flow suspicious pattern detection
"""

import os
import re
import struct
from pathlib import Path
from core.utils import (Colors, entropy, section_entropy, fuzzy_hash,
                         extract_strings, sha256, md5, sha1)

# -- Known malicious import combinations --------------------------------------
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx":       (9, "Allocate memory in remote process - code injection"),
    "WriteProcessMemory":   (9, "Write to remote process memory - code injection"),
    "CreateRemoteThread":   (9, "Execute code in remote process - classic trojan TTP"),
    "NtUnmapViewOfSection": (8, "Process hollowing technique"),
    "SetWindowsHookEx":     (8, "Keyboard/mouse hook - potential keylogger"),
    "GetAsyncKeyState":     (8, "Keystate polling - keylogger indicator"),
    "InternetOpenUrl":      (6, "HTTP network connection capability"),
    "URLDownloadToFile":    (7, "Download file from internet"),
    "WinExec":              (7, "Execute arbitrary commands"),
    "ShellExecute":         (6, "Shell execution capability"),
    "RegSetValueEx":        (6, "Registry persistence mechanism"),
    "RegCreateKeyEx":       (5, "Registry key creation - persistence"),
    "CryptEncrypt":         (5, "Cryptographic encryption (C2 traffic?)"),
    "CryptDecrypt":         (6, "Cryptographic decryption (payload unpacking?)"),
    "IsDebuggerPresent":    (7, "Anti-debugging check"),
    "CheckRemoteDebugger":  (7, "Anti-debugging check"),
    "NtQueryInformationProcess": (7, "Anti-analysis - sandbox/debugger detection"),
    "GetTickCount":         (4, "Timing check - possible anti-sandbox"),
    "Sleep":                (3, "Sleep call - possible sandbox evasion delay"),
    "CreateMutex":          (4, "Mutex creation - infection marker"),
    "FindWindow":           (5, "Looking for analysis tool windows"),
    "OpenProcess":          (6, "Open handle to another process"),
    "TerminateProcess":     (5, "Process termination capability"),
    "LoadLibraryA":         (3, "Dynamic library loading"),
    "GetProcAddress":       (4, "Dynamic function resolution - obfuscation indicator"),
}

# -- Suspicious string patterns (regex) ---------------------------------------
STRING_PATTERNS = [
    (r"cmd\.exe\s*/c",                    9, "Command shell execution"),
    (r"powershell.*-enc",                  9, "Encoded PowerShell command"),
    (r"powershell.*-nop",                  8, "PowerShell no-profile (stealth)"),
    (r"\\AppData\\Roaming\\",              6, "AppData persistence location"),
    (r"CurrentVersion\\Run",               8, "Registry autorun key - persistence"),
    (r"CurrentVersion\\RunOnce",           8, "Registry RunOnce - persistence"),
    (r"schtasks.*\/create",                8, "Scheduled task creation - persistence"),
    (r"net user.*\/add",                   9, "Creating backdoor user account"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 8, "Hardcoded IP address (C2)"),
    (r"https?://[a-z0-9\-\.]+\.(xyz|top|tk|ml|ga|cf|gq|pw)", 8, "Suspicious TLD domain"),
    (r"/gate\.php",                        8, "Classic C2 endpoint pattern"),
    (r"Mozilla/\d\.\d \(Windows",          6, "Fake browser User-Agent string"),
    (r"SELECT.*FROM.*WHERE",               5, "SQL query - data exfiltration?"),
    (r"DELETE FROM",                       7, "SQL DELETE - destructive payload?"),
    (r"\bkeylog\b",                        9, "Keylogger reference"),
    (r"\bpassword\b",                      5, "Password string present"),
    (r"\btoken\b.*\bsteal\b",              9, "Token theft reference"),
    (r"\\\\\.\\pipe\\",                    7, "Named pipe - lateral movement"),
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){8,}", 7, "Hex shellcode pattern"),
    (r"[A-Za-z0-9+/]{50,}={0,2}",         5, "Long Base64 string - encoded payload?"),
]

# -- Known malware fuzzy hashes (simulated database) --------------------------
KNOWN_MALWARE_DB = [
    {"name": "Emotet.Gen",         "hash": "a3f4b2c1d5e6f708192a3b4c5d6e7f80", "family": "Banking Trojan"},
    {"name": "AgentTesla.B",       "hash": "b4c5d6e7f8091a2b3c4d5e6f70819203", "family": "InfoStealer"},
    {"name": "RemcosRAT.C",        "hash": "c5d6e7f809192a3b4c5d6e7f8091a2b3", "family": "RAT"},
    {"name": "NjRAT.E",            "hash": "d6e7f8091a2b3c4d5e6f70819203b4c5", "family": "RAT"},
    {"name": "FormBook.A",         "hash": "e7f8091a2b3c4d5e6f70819203b4c5d6", "family": "InfoStealer"},
    {"name": "AsyncRAT.F",         "hash": "f8091a2b3c4d5e6f70819203b4c5d6e7", "family": "RAT"},
]

# -- Magic bytes for file identification ---------------------------------------
MAGIC_SIGNATURES = {
    b"\x4d\x5a":         "PE Executable (Windows .exe/.dll)",
    b"\x7f\x45\x4c\x46": "ELF Executable (Linux/Unix)",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\x50\x4b\x03\x04": "ZIP Archive (possibly Office doc)",
    b"\xd0\xcf\x11\xe0": "OLE2 Compound (Office 97-2003)",
    b"\x4d\x5a\x90\x00": "PE Executable (standard MZ header)",
    b"\x23\x21":         "Script (shebang)",
    b"\xca\xfe\xba\xbe": "Mach-O Universal Binary (macOS)",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
}


class StaticAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def analyze(self, filepath: Path) -> dict:
        print(f"\n{Colors.BOLD}{'-'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}[STAGE 1]{Colors.RESET} Static Analysis")
        print(f"{'-'*60}")

        data = filepath.read_bytes()
        results = {
            "stage": "Static Analysis",
            "score": 0,
            "flags": [],
            "metadata": {},
            "strings": [],
            "imports": [],
            "sections": [],
            "hashes": {},
            "c2_indicators": [],
        }

        # 1. Hashes
        results["hashes"] = {
            "md5":    md5(data),
            "sha1":   sha1(data),
            "sha256": sha256(data),
            "fuzzy":  fuzzy_hash(data),
        }
        self._log(f"MD5:    {results['hashes']['md5']}")
        self._log(f"SHA256: {results['hashes']['sha256']}")

        # 2. File type
        file_type = self._identify_file_type(data)
        results["metadata"]["file_type"] = file_type
        self._log(f"Type:   {file_type}")

        # 3. Overall entropy
        ent = entropy(data)
        results["metadata"]["entropy"] = round(ent, 3)
        self._log(f"Entropy: {ent:.3f}/8.0")
        if ent > 7.2:
            self._flag(results, 9, "Critical entropy (>7.2) - likely encrypted/packed payload")
        elif ent > 6.5:
            self._flag(results, 6, f"High entropy ({ent:.2f}) - possible obfuscation or packing")

        # 4. Fuzzy hash database check
        self._check_fuzzy_db(results, data)

        # 5. PE analysis
        if data[:2] == b"\x4d\x5a":
            self._analyze_pe(results, data)

        # 6. String extraction + IOC matching
        self._analyze_strings(results, data)

        # 7. Section entropy analysis
        self._analyze_section_entropy(results, data)

        # Score calculation
        results["score"] = self._calculate_score(results["flags"])

        status = "SUSPICIOUS" if results["score"] >= 50 else ("MODERATE" if results["score"] >= 25 else "CLEAN")
        print(f"\n  Result: {status}  |  Score: {results['score']}/100  |  Flags: {len(results['flags'])}")
        return results

    def _identify_file_type(self, data: bytes) -> str:
        for magic, name in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return name
        # Check for text/script
        try:
            sample = data[:512].decode("utf-8", errors="strict")
            if "import " in sample or "def " in sample:
                return "Python Script"
            if "<?php" in sample:
                return "PHP Script"
            if "<html" in sample.lower():
                return "HTML Document"
            return "Text/Script"
        except:
            return "Unknown Binary"

    def _check_fuzzy_db(self, results, data):
        fhash = results["hashes"]["fuzzy"]
        for entry in KNOWN_MALWARE_DB:
            sim = self._simple_similarity(fhash, entry["hash"])
            if sim > 70:
                self._flag(results, 10, f"FUZZY MATCH {sim:.0f}% - {entry['name']} ({entry['family']})")
                results["metadata"]["malware_family"] = entry["name"]
            elif sim > 50:
                self._flag(results, 6, f"Partial fuzzy match {sim:.0f}% - possible {entry['family']} variant")

    def _simple_similarity(self, h1, h2):
        if not h1 or not h2:
            return 0
        length = min(len(h1), len(h2))
        matches = sum(a == b for a, b in zip(h1[:length], h2[:length]))
        return (matches / length) * 100

    def _analyze_pe(self, results, data):
        self._log("Detected PE executable - parsing structure...")
        try:
            import pefile
            pe = pefile.PE(data=data)

            # Compilation timestamp
            ts = pe.FILE_HEADER.TimeDateStamp
            import datetime
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            results["metadata"]["compile_time"] = str(dt)

            if ts == 0:
                self._flag(results, 7, "Compile timestamp zeroed out - anti-forensics")
            elif ts > 1800000000:  # Future timestamp
                self._flag(results, 6, "Suspicious future compile timestamp")

            # Sections
            suspicious_section_names = [".upx", "UPX0", "UPX1", ".aspack", ".themida"]
            for section in pe.sections:
                name = section.Name.decode(errors="replace").strip("\x00").strip()
                vsize = section.Misc_VirtualSize
                rsize = section.SizeOfRawData
                sect_ent = entropy(section.get_data())
                sect_info = {"name": name, "entropy": round(sect_ent, 3), "vsize": vsize, "rsize": rsize}
                results["sections"].append(sect_info)

                if name.lower() in [s.lower() for s in suspicious_section_names]:
                    self._flag(results, 8, f"Known packer section '{name}' - UPX/ASPack detected")
                if sect_ent > 7.5:
                    self._flag(results, 8, f"Section '{name}' entropy {sect_ent:.2f} - encrypted payload")
                if vsize > 0 and rsize == 0:
                    self._flag(results, 6, f"Section '{name}' has virtual size but no raw data - injector pattern")

                if self.verbose:
                    sc = Colors.RED if sect_ent > 7.0 else Colors.RESET
                    print(f"    Section {name:<12} entropy={sc}{sect_ent:.3f}{Colors.RESET}")

            # Imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                    lib_name = lib.dll.decode(errors="replace")
                    for imp in lib.imports:
                        if imp.name:
                            func = imp.name.decode(errors="replace")
                            results["imports"].append(f"{lib_name}!{func}")
                            if func in SUSPICIOUS_IMPORTS:
                                sev, desc = SUSPICIOUS_IMPORTS[func]
                                self._flag(results, sev, f"Import: {func} - {desc}")

            # Suspicious import combinations (injection triad)
            imp_names = [i.split("!")[-1] for i in results["imports"]]
            injection_triad = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
            if injection_triad.issubset(set(imp_names)):
                self._flag(results, 10, "INJECTION TRIAD detected - classic process injection toolkit")

            anti_debug = {"IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformationProcess"}
            if len(anti_debug.intersection(set(imp_names))) >= 2:
                self._flag(results, 8, "Multiple anti-debugging imports - evasion-aware binary")

        except ImportError:
            self._log("pefile not available - skipping PE parsing")
        except Exception as e:
            self._log(f"PE parse error: {e}")

    def _analyze_strings(self, results, data):
        strings = extract_strings(data, min_len=5)
        results["metadata"]["string_count"] = len(strings)

        # Check each string against IOC patterns
        for pattern, severity, desc in STRING_PATTERNS:
            for s in strings:
                if re.search(pattern, s, re.IGNORECASE):
                    self._flag(results, severity, f"String IOC: {desc} - '{s[:60]}'")
                    # C2 indicator extraction
                    if any(x in desc.lower() for x in ["c2", "ip", "domain", "endpoint", "http"]):
                        results["c2_indicators"].append(s[:80])
                    break  # One flag per pattern

        # Base64 detection - look for long encoded strings
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
        b64_matches = b64_pattern.findall(data.decode("latin-1", errors="replace"))
        if b64_matches:
            self._flag(results, 6, f"Large Base64 blob detected ({len(b64_matches)} - encoded payload?)")

        # XOR decryption attempt
        encrypted_regions = [data[i:i+256] for i in range(0, min(len(data), 4096), 256)
                              if entropy(data[i:i+256]) > 7.0]
        if encrypted_regions:
            for region in encrypted_regions[:3]:
                candidates = self._try_xor(region)
                for c in candidates:
                    self._flag(results, 7, f"XOR-decrypted string: '{c}' (key auto-detected)")
                    results["c2_indicators"].append(c)

        # Interesting strings to report
        interesting = [s for s in strings if len(s) > 8 and any(
            p in s.lower() for p in ["http", "exe", "dll", "cmd", "shell", "inject",
                                       "password", "token", "crypt", "connect"])]
        results["strings"] = interesting[:30]

    def _try_xor(self, data: bytes) -> list:
        found = []
        for key in range(1, 256):
            dec = bytes(b ^ key for b in data)
            strings = extract_strings(dec, min_len=7)
            for s in strings:
                if any(p in s.lower() for p in ["http://", "https://", "cmd.exe", "gate.php", ".exe"]):
                    found.append(s[:60])
        return found[:2]

    def _analyze_section_entropy(self, results, data):
        """Block-level entropy to find hidden encrypted regions"""
        blocks = section_entropy(data, block_size=512)
        high_entropy_blocks = sum(1 for e in blocks if e > 7.2)
        if high_entropy_blocks > len(blocks) * 0.3 and blocks:
            self._flag(results, 7, f"{high_entropy_blocks}/{len(blocks)} blocks have high entropy - large encrypted region")

    def _flag(self, results, severity, description):
        results["flags"].append({"severity": severity, "description": description})
        color = Colors.RED if severity >= 8 else (Colors.YELLOW if severity >= 5 else Colors.DIM)
        print(f"  {color}[{severity:2d}]{Colors.RESET} {description}")

    def _log(self, msg):
        if self.verbose:
            print(f"  {Colors.DIM}... {msg}{Colors.RESET}")

    def _calculate_score(self, flags) -> int:
        if not flags:
            return 0
        total = sum(f["severity"] for f in flags)
        # Normalize: 10 flags * severity 10 = 100
        score = min(100, int((total / (len(flags) * 10)) * 100 + len(flags) * 2))
        return min(100, score)
