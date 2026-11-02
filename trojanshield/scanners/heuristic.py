"""
scanners/heuristic.py - Stage 3: Heuristic Scanning
=====================================================
- Behavioral pattern scoring
- Anti-analysis evasion detection
- C2 config decryption attempts
- Database comparison via signature rules
- CPUID / timing / sandbox probe detection
"""

import re
import math
import struct
from pathlib import Path
from core.utils import Colors, extract_strings, entropy, xor_decrypt


# -- Heuristic rule database --------------------------------------------------
HEURISTIC_RULES = [
    # Anti-analysis
    {
        "id": "ANTI_001",
        "name": "CPUID Sandbox Probe",
        "description": "Binary queries CPUID and branches - VM fingerprinting",
        "byte_patterns": [b"\x0f\xa2", b"\x0f\xa2\x3d"],  # CPUID instruction
        "string_patterns": [r"VMware", r"VirtualBox", r"VBOX", r"QEMU", r"KVM", r"Hyper-V"],
        "severity": 9,
        "category": "anti_analysis",
    },
    {
        "id": "ANTI_002",
        "name": "Timing Attack / RDTSC",
        "description": "Reads timestamp counter - sandbox speed detection",
        "byte_patterns": [b"\x0f\x31"],  # RDTSC
        "string_patterns": [r"GetTickCount", r"QueryPerformanceCounter"],
        "severity": 7,
        "category": "anti_analysis",
    },
    {
        "id": "ANTI_003",
        "name": "Anti-Debug via PEB",
        "description": "Checks Process Environment Block debug flag",
        "byte_patterns": [b"\x64\xa1\x30", b"\x64\x8b\x0d\x30"],  # FS:[30h] PEB access
        "string_patterns": [r"IsDebuggerPresent", r"NtQueryInformationProcess", r"CheckRemoteDebugger"],
        "severity": 8,
        "category": "anti_analysis",
    },
    {
        "id": "ANTI_004",
        "name": "Window Enumeration (Analysis Tool Check)",
        "description": "Enumerates windows looking for analysis tool names",
        "byte_patterns": [],
        "string_patterns": [r"OllyDbg", r"x64dbg", r"WireShark", r"Wireshark",
                             r"Process\s*Hacker", r"ProcessMonitor", r"IDA\s*Pro"],
        "severity": 9,
        "category": "anti_analysis",
    },
    {
        "id": "ANTI_005",
        "name": "Sleep-Based Sandbox Evasion",
        "description": "Long sleep call to outlast sandbox timeout",
        "byte_patterns": [],
        "string_patterns": [r"Sleep\b", r"SleepEx\b"],
        "severity": 5,
        "category": "anti_analysis",
    },
    # Persistence
    {
        "id": "PERS_001",
        "name": "Registry Autorun Persistence",
        "description": "Writes to Run/RunOnce registry keys",
        "byte_patterns": [],
        "string_patterns": [r"CurrentVersion\\Run", r"CurrentVersion\\RunOnce",
                             r"CurrentVersion\\RunServices"],
        "severity": 8,
        "category": "persistence",
    },
    {
        "id": "PERS_002",
        "name": "Startup Folder Persistence",
        "description": "Drops file in Windows Startup folder",
        "byte_patterns": [],
        "string_patterns": [r"\\Startup\\", r"\\Start Menu\\Programs\\Startup"],
        "severity": 8,
        "category": "persistence",
    },
    {
        "id": "PERS_003",
        "name": "Scheduled Task Persistence",
        "description": "Creates scheduled task for persistence",
        "byte_patterns": [],
        "string_patterns": [r"schtasks", r"ITaskScheduler", r"Task Scheduler"],
        "severity": 8,
        "category": "persistence",
    },
    # Injection
    {
        "id": "INJ_001",
        "name": "Process Hollowing Pattern",
        "description": "CreateProcess + NtUnmapViewOfSection - process hollowing",
        "byte_patterns": [],
        "string_patterns": [r"NtUnmapViewOfSection", r"ZwUnmapViewOfSection"],
        "severity": 10,
        "category": "injection",
    },
    {
        "id": "INJ_002",
        "name": "Reflective DLL Injection",
        "description": "Reflective loader pattern detected",
        "byte_patterns": [b"ReflectiveLoader", b"\x52\x65\x66\x6c\x65\x63\x74"],
        "string_patterns": [r"ReflectiveLoader", r"reflective_loader"],
        "severity": 10,
        "category": "injection",
    },
    {
        "id": "INJ_003",
        "name": "APC Queue Injection",
        "description": "QueueUserAPC used for code injection",
        "byte_patterns": [],
        "string_patterns": [r"QueueUserAPC", r"NtQueueApcThread"],
        "severity": 9,
        "category": "injection",
    },
    # Network / C2
    {
        "id": "NET_001",
        "name": "Hardcoded C2 Domain",
        "description": "Suspicious domain hardcoded in binary",
        "byte_patterns": [],
        "string_patterns": [r"https?://[a-zA-Z0-9\-\.]+\.(xyz|top|tk|ml|ga|cf|gq|pw|cc|su)/"],
        "severity": 9,
        "category": "c2",
    },
    {
        "id": "NET_002",
        "name": "Hardcoded IP Address",
        "description": "Non-RFC1918 IP hardcoded - potential C2",
        "byte_patterns": [],
        "string_patterns": [r"\b(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"],
        "severity": 8,
        "category": "c2",
    },
    {
        "id": "NET_003",
        "name": "DNS Beaconing Pattern",
        "description": "DGA-like domain generation pattern in code",
        "byte_patterns": [],
        "string_patterns": [r"[a-z]{8,16}\.(com|net|org|info)\b"],
        "severity": 5,
        "category": "c2",
    },
    # Payload
    {
        "id": "PAY_001",
        "name": "Shellcode Signature",
        "description": "NOP sled or shellcode pattern detected",
        "byte_patterns": [b"\x90\x90\x90\x90\x90\x90\x90\x90",  # NOP sled
                           b"\xfc\xe8\x82\x00\x00\x00",             # Metasploit stub
                           b"\xfc\xe8\x89\x00\x00\x00"],            # Metasploit alt
        "string_patterns": [],
        "severity": 10,
        "category": "payload",
    },
    {
        "id": "PAY_002",
        "name": "PowerShell Encoded Payload",
        "description": "Base64-encoded PowerShell execution",
        "byte_patterns": [],
        "string_patterns": [r"powershell.*-[Ee]nc", r"powershell.*-[Ee]ncodedCommand",
                             r"IEX\s*\(", r"Invoke-Expression"],
        "severity": 9,
        "category": "payload",
    },
    {
        "id": "PAY_003",
        "name": "AMSI Bypass",
        "description": "Attempts to disable Windows Antimalware Scan Interface",
        "byte_patterns": [],
        "string_patterns": [r"AmsiScanBuffer", r"amsiInitFailed", r"AMSI", r"amsi\.dll"],
        "severity": 10,
        "category": "evasion",
    },
]


class HeuristicScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def analyze(self, filepath: Path, static_results: dict) -> dict:
        print(f"\n{Colors.BOLD}{'-'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}[STAGE 3]{Colors.RESET} Heuristic Scanning")
        print(f"{'-'*60}")

        data = filepath.read_bytes()
        text = data.decode("latin-1", errors="replace")

        results = {
            "stage": "Heuristic Scanning",
            "score": 0,
            "flags": [],
            "rules_matched": [],
            "c2_indicators": [],
            "decrypted_configs": [],
        }

        # Run all rules
        self._run_rules(results, data, text)

        # C2 config decryption attempts
        self._attempt_c2_decryption(results, data)

        # Behavioral scoring from static results
        self._cross_correlate(results, static_results)

        # Mutation / polymorphism detection
        self._detect_mutation_indicators(results, data)

        results["score"] = self._calculate_score(results["flags"])
        status = "SUSPICIOUS" if results["score"] >= 50 else ("MODERATE" if results["score"] >= 25 else "CLEAN")
        print(f"\n  Result: {status}  |  Score: {results['score']}/100  |  Rules matched: {len(results['rules_matched'])}")
        return results

    def _run_rules(self, results, data: bytes, text: str):
        for rule in HEURISTIC_RULES:
            matched = False

            # Byte pattern matching
            for pattern in rule["byte_patterns"]:
                if pattern in data:
                    matched = True
                    break

            # String pattern matching
            if not matched:
                for pattern in rule["string_patterns"]:
                    if re.search(pattern, text, re.IGNORECASE):
                        matched = True
                        break

            if matched:
                results["rules_matched"].append(rule["id"])
                self._flag(results, rule["severity"],
                           f"[{rule['id']}] {rule['name']} - {rule['description']}")

                if rule["category"] == "c2":
                    # Extract the actual C2 value
                    for pattern in rule["string_patterns"]:
                        m = re.search(pattern, text, re.IGNORECASE)
                        if m:
                            results["c2_indicators"].append(m.group(0)[:80])

    def _attempt_c2_decryption(self, results, data: bytes):
        """Try to decrypt embedded C2 configs"""
        print(f"  {Colors.DIM}... Attempting C2 config decryption...{Colors.RESET}")

        # Find high-entropy blobs
        block_size = 128
        for offset in range(0, min(len(data), 8192), block_size):
            block = data[offset:offset+block_size]
            if len(block) < 32:
                continue
            ent = entropy(block)
            if ent < 6.5:
                continue

            # Try XOR decryption with all single-byte keys
            for key in range(1, 256):
                dec = xor_decrypt(block, key)
                strings = extract_strings(dec, min_len=7)
                for s in strings:
                    if re.search(r"(https?://|cmd\.exe|gate\.php|\.exe|:\d{4,5})", s, re.I):
                        result = {"method": f"XOR(key=0x{key:02x})", "value": s[:80], "offset": offset}
                        results["decrypted_configs"].append(result)
                        results["c2_indicators"].append(s[:80])
                        self._flag(results, 9,
                                   f"C2 config DECRYPTED at offset {offset} (XOR 0x{key:02x}): '{s[:50]}'")
                        break

            # Try ROT-13 on text-ish blocks
            try:
                text = block.decode("ascii")
                import codecs
                rot13 = codecs.decode(text, "rot_13")
                if re.search(r"https?://|\.exe|gate\.php", rot13, re.I):
                    self._flag(results, 7, f"ROT-13 decoded C2 string at offset {offset}")
                    results["c2_indicators"].append(rot13[:80])
            except:
                pass

    def _cross_correlate(self, results, static_results: dict):
        """Boost score if multiple stages agree"""
        static_score = static_results.get("score", 0)
        if static_score >= 60:
            self._flag(results, 5, f"Cross-stage correlation: Static analysis also scored {static_score}/100")

        # If static found injection triad AND heuristic found persistence - very bad
        static_flags = [f["description"] for f in static_results.get("flags", [])]
        has_injection   = any("INJECTION TRIAD" in f for f in static_flags)
        has_persistence = "PERS_001" in results["rules_matched"] or "PERS_002" in results["rules_matched"]
        if has_injection and has_persistence:
            self._flag(results, 10, "CRITICAL COMBINATION: Process injection + persistence = full trojan behavior profile")

    def _detect_mutation_indicators(self, results, data: bytes):
        """Detect self-modifying / polymorphic patterns"""
        # XOR loop pattern (common unpacking stub)
        xor_loop = re.search(b"\x30[\x00-\xFF]\x46\xe2|\x34[\x00-\xFF]\x46\xe2", data)
        if xor_loop:
            self._flag(results, 8, "XOR loop stub detected - self-decrypting payload unpacker")

        # Junk NOP sequences (mutation engine artifact)
        nop_count = data.count(b"\x90\x90\x90")
        if nop_count > 10:
            self._flag(results, 5, f"Excessive NOP sequences ({nop_count}) - possible mutation engine padding")

        # Overlay data (extra data after PE end - common in trojans)
        if data[:2] == b"\x4d\x5a":
            try:
                import pefile
                pe = pefile.PE(data=data)
                overlay_offset = pe.get_overlay_data_start_offset()
                if overlay_offset and overlay_offset < len(data):
                    overlay_size = len(data) - overlay_offset
                    overlay_ent  = entropy(data[overlay_offset:])
                    self._flag(results, 7,
                               f"PE overlay detected: {overlay_size} bytes at offset {overlay_offset}, entropy={overlay_ent:.2f}")
            except:
                pass

    def _flag(self, results, severity, description):
        results["flags"].append({"severity": severity, "description": description})
        color = Colors.RED if severity >= 8 else (Colors.YELLOW if severity >= 5 else Colors.DIM)
        print(f"  {color}[{severity:2d}]{Colors.RESET} {description}")

    def _calculate_score(self, flags) -> int:
        if not flags:
            return 0
        total = sum(f["severity"] for f in flags)
        score = min(100, int((total / max(len(flags), 1)) * 12))
        return score
