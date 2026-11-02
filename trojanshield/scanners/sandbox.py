"""
scanners/sandbox.py - Stage 2: VM Sandbox Simulation
=====================================================
Simulates the 4 VM environments:
  VM1 - Clean environment (detect evasion behavior)
  VM2 - Live-like system (bait dormant trojans)
  VM3 - Network active (C2 bait)
  VM4 - Mutation stress test (fuzzy hash comparison)
"""

import re
import time
import hashlib
from pathlib import Path
from core.utils import Colors, entropy, extract_strings, fuzzy_hash, fuzzy_similarity


# Artifacts that a real user machine has - trojans probe for these
LIVE_SYSTEM_ARTIFACTS = [
    "C:\\Users\\John\\Documents\\invoice.docx",
    "C:\\Users\\John\\Desktop\\passwords.txt",
    "HKLM\\SOFTWARE\\Microsoft\\Office",
    "Mozilla Firefox",
    "Microsoft Outlook",
    "recently_opened_files",
    "browser_history",
]

# Known C2 beacon patterns
C2_BEACON_PATTERNS = [
    r"https?://[a-zA-Z0-9\-\.]+/gate\.php",
    r"https?://[a-zA-Z0-9\-\.]+/panel",
    r"https?://[a-zA-Z0-9\-\.]+/connect",
    r"POST\s+/[a-z]+\.php",
    r"Content-Type:\s*application/x-www-form-urlencoded",
    r"User-Agent:.*Mozilla.*Windows.*rv:",
]

# Anti-VM registry keys trojans check for
ANTIVM_REGISTRY_KEYS = [
    "HKLM\\SOFTWARE\\VMware, Inc.",
    "HKLM\\SOFTWARE\\Oracle\\VirtualBox",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine",
]

# Anti-VM processes trojans look for
ANTIVM_PROCESSES = [
    "vmtoolsd.exe", "vmwaretray.exe", "vboxservice.exe",
    "vboxtray.exe", "qemu-ga.exe", "prl_tools.exe",
    "wireshark.exe", "procmon.exe", "x64dbg.exe",
    "ollydbg.exe", "ida.exe", "pestudio.exe",
]

# Anti-VM file artifacts
ANTIVM_FILES = [
    "C:\\windows\\system32\\drivers\\vmhgfs.sys",
    "C:\\windows\\system32\\drivers\\vboxguest.sys",
    "C:\\program files\\vmware",
    "C:\\program files\\oracle\\virtualbox guest additions",
]


class SandboxAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def analyze(self, filepath: Path, static_results: dict) -> dict:
        print(f"\n{Colors.BOLD}{'-'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}[STAGE 2]{Colors.RESET} VM Sandbox Simulation")
        print(f"{'-'*60}")

        data     = filepath.read_bytes()
        text     = data.decode("latin-1", errors="replace")
        all_strings = extract_strings(data, min_len=5)

        results = {
            "stage": "VM Sandbox Simulation",
            "score": 0,
            "flags": [],
            "vm_results": {},
            "c2_indicators": [],
            "evasion_detected": False,
        }

        # Run each VM environment
        vm1 = self._vm1_clean(data, text, all_strings)
        vm2 = self._vm2_livelike(data, text, all_strings)
        vm3 = self._vm3_network(data, text, all_strings)
        vm4 = self._vm4_mutation(data, filepath)

        results["vm_results"] = {
            "VM1_Clean":    vm1,
            "VM2_LiveLike": vm2,
            "VM3_Network":  vm3,
            "VM4_Mutation": vm4,
        }

        # Merge flags and C2 from all VMs
        for vm_name, vm_data in results["vm_results"].items():
            for flag in vm_data.get("flags", []):
                results["flags"].append(flag)
                color = Colors.RED if flag["severity"] >= 8 else (Colors.YELLOW if flag["severity"] >= 5 else Colors.DIM)
                print(f"  [{vm_name}] {color}[{flag['severity']:2d}]{Colors.RESET} {flag['description']}")
            for c2 in vm_data.get("c2_indicators", []):
                results["c2_indicators"].append(c2)

        if any(vm.get("evasion_detected") for vm in results["vm_results"].values()):
            results["evasion_detected"] = True
            self._flag_direct(results, 9, "EVASION BEHAVIOR: Binary probes for sandbox environment before acting")

        results["score"] = self._calculate_score(results["flags"])
        status = "SUSPICIOUS" if results["score"] >= 50 else ("MODERATE" if results["score"] >= 25 else "CLEAN")
        print(f"\n  Result: {status}  |  Score: {results['score']}/100  |  Evasion: {results['evasion_detected']}")
        return results

    def _vm1_clean(self, data, text, strings) -> dict:
        """VM1: Bare OS - no user artifacts. Trojans stay dormant here."""
        result = {"name": "VM1_Clean", "flags": [], "c2_indicators": [], "evasion_detected": False}

        # Check if binary probes for VM artifacts (means it IS evasion-aware)
        for proc in ANTIVM_PROCESSES:
            if proc.lower() in text.lower():
                result["flags"].append({"severity": 9,
                    "description": f"Probes for analysis process: {proc}"})
                result["evasion_detected"] = True

        for regkey in ANTIVM_REGISTRY_KEYS:
            # Check if the key name appears (trojan would query it)
            key_part = regkey.split("\\")[-1].lower()
            if key_part in text.lower():
                result["flags"].append({"severity": 8,
                    "description": f"Anti-VM registry probe: {regkey}"})
                result["evasion_detected"] = True

        for f in ANTIVM_FILES:
            fname = f.split("\\")[-1].lower()
            if fname in text.lower():
                result["flags"].append({"severity": 8,
                    "description": f"Anti-VM file probe: {fname}"})
                result["evasion_detected"] = True

        # CPUID probe
        if b"\x0f\xa2" in data:
            result["flags"].append({"severity": 9,
                "description": "CPUID instruction - hardware fingerprinting for VM detection"})
            result["evasion_detected"] = True

        # RDTSC timing
        if b"\x0f\x31" in data:
            result["flags"].append({"severity": 7,
                "description": "RDTSC timing check - sandbox speed detection"})
            result["evasion_detected"] = True

        return result

    def _vm2_livelike(self, data, text, strings) -> dict:
        """VM2: Lived-in system - bait dormant trojans into activation."""
        result = {"name": "VM2_LiveLike", "flags": [], "c2_indicators": [], "evasion_detected": False}

        # In a real system, we'd inject artifacts and monitor. Here we analyze
        # what the binary would do when it thinks it's on a real machine.

        # Check for user-data targeting
        user_data_targets = [
            (r"\\Documents\\",         "Targets user Documents folder"),
            (r"\\Desktop\\",           "Targets user Desktop"),
            (r"\\AppData\\",           "Targets AppData (credential stores)"),
            (r"password",              "Searches for password files"),
            (r"\.kdbx",               "Targets KeePass database"),
            (r"wallet\.dat",           "Targets cryptocurrency wallet"),
            (r"Login Data",            "Targets Chrome credential store"),
            (r"cookies\.sqlite",       "Targets Firefox cookie store"),
            (r"id_rsa",               "Targets SSH private key"),
            (r"\.pem",                "Targets SSL certificate/key"),
        ]

        for pattern, desc in user_data_targets:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 8, "description": f"Data targeting: {desc}"})

        # Lateral movement patterns
        lateral = [
            (r"net\s+use\s+\\\\",      "Network share enumeration"),
            (r"\\\\[^\\]+\\[Cc]\$",    "Admin share access (lateral movement)"),
            (r"wmic.*process",         "WMIC process execution"),
            (r"psexec",               "PsExec lateral movement tool"),
            (r"mimikatz",             "Mimikatz credential dumper"),
            (r"lsass",               "LSASS memory access (credential theft)"),
        ]

        for pattern, desc in lateral:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 9, "description": f"Lateral movement: {desc}"})

        # Exfiltration patterns
        exfil = [
            (r"zip|rar|7z.*compress",  "File compression before exfiltration"),
            (r"FTP|SFTP",             "FTP exfiltration channel"),
            (r"smtp.*send",           "Email exfiltration"),
            (r"telegram.*api",        "Telegram bot C2/exfil"),
            (r"discord.*webhook",     "Discord webhook exfiltration"),
        ]

        for pattern, desc in exfil:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 8, "description": f"Exfiltration: {desc}"})
                result["c2_indicators"].append(f"Exfil channel: {desc}")

        return result

    def _vm3_network(self, data, text, strings) -> dict:
        """VM3: Network active - C2 bait with MITM proxy simulation."""
        result = {"name": "VM3_Network", "flags": [], "c2_indicators": [], "evasion_detected": False}

        # Simulate TLS handshake analysis
        # Check for certificate pinning (means it expects a specific cert)
        pinning_indicators = [
            (r"CertGetCertificateChain",       "Certificate chain validation - possible cert pinning"),
            (r"ssl_ctx_set_verify",            "OpenSSL verify callback - SSL inspection check"),
            (r"X509_verify_cert",              "Direct certificate verification"),
            (r"SHA1.*certificate|cert.*sha1",  "Certificate SHA1 pinning pattern"),
        ]

        for pattern, desc in pinning_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 6, "description": f"TLS/Cert: {desc}"})

        # Extract and analyze all URLs/domains
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        for url in urls[:20]:
            result["c2_indicators"].append(url)
            # Suspicious TLD check
            if re.search(r"\.(xyz|top|tk|ml|ga|cf|gq|pw|cc|su|ws|biz)(/|$)", url, re.I):
                result["flags"].append({"severity": 8, "description": f"Suspicious TLD C2 URL: {url[:60]}"})
            # IP-based URL
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                result["flags"].append({"severity": 8, "description": f"IP-based C2 URL: {url[:60]}"})

        # JA3-like cipher suite analysis (what crypto does it request?)
        weak_ciphers = [
            (r"RC4|rc4",          "RC4 cipher - weak, used by older malware"),
            (r"DES|3DES|des",     "DES/3DES - deprecated, malware compatibility"),
            (r"NULL cipher|null", "NULL cipher - no encryption"),
            (r"EXPORT",           "Export-grade cipher - intentionally weak"),
        ]

        for pattern, desc in weak_ciphers:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 6, "description": f"Weak cipher: {desc}"})

        # DNS over HTTPS (malware hiding DNS resolution)
        if re.search(r"dns\.google|cloudflare-dns|doh\.", text, re.I):
            result["flags"].append({"severity": 7, "description": "DNS-over-HTTPS usage - hiding DNS queries from monitoring"})

        # Tor
        if re.search(r"\.onion|torproject|socks5.*127", text, re.I):
            result["flags"].append({"severity": 9, "description": "Tor network usage - C2 traffic anonymization"})
            result["c2_indicators"].append("TOR network")

        return result

    def _vm4_mutation(self, data, filepath) -> dict:
        """VM4: Mutation stress - detect polymorphism indicators."""
        result = {"name": "VM4_Mutation", "flags": [], "c2_indicators": [], "evasion_detected": False}

        fhash = fuzzy_hash(data)

        # Check against known polymorphic malware patterns
        # In real deployment, this compares against a database of variants
        # Here we detect mutation engine signatures

        text = data.decode("latin-1", errors="replace")

        mutation_patterns = [
            (r"MutateCode|metamorph|polymorph",    "Explicit mutation engine reference"),
            (r"RandomizeKey|GenerateKey.*random",  "Random key generation - polymorphic encryption"),
            (r"junk.*insert|insert.*junk",         "Junk code insertion - mutation evasion"),
        ]

        for pattern, desc in mutation_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                result["flags"].append({"severity": 8, "description": f"Mutation: {desc}"})

        # Packer detection via section name signatures
        packer_sigs = {
            b"UPX0": "UPX packer",
            b"UPX1": "UPX packer",
            b".aspack": "ASPack packer",
            b".MPRESS": "MPRESS packer",
            b"Themida": "Themida protector",
            b"VMProtect": "VMProtect - code virtualization",
            b"Obsidium": "Obsidium protector",
            b"PECompact": "PECompact packer",
        }

        for sig, name in packer_sigs.items():
            if sig in data:
                result["flags"].append({"severity": 7, "description": f"Packer detected: {name}"})

        # Entropy variance - packed sections have much higher entropy than normal
        block_entropies = []
        for i in range(0, min(len(data), 8192), 512):
            block = data[i:i+512]
            if len(block) >= 64:
                block_entropies.append(entropy(block))

        if block_entropies:
            ent_variance = max(block_entropies) - min(block_entropies)
            if ent_variance > 4.0:
                result["flags"].append({"severity": 7,
                    "description": f"High entropy variance ({ent_variance:.2f}) - mixed plain+encrypted content"})

        result["fuzzy_hash"] = fhash
        return result

    def _flag_direct(self, results, severity, description):
        results["flags"].append({"severity": severity, "description": description})
        color = Colors.RED if severity >= 8 else Colors.YELLOW
        print(f"  {color}[{severity:2d}]{Colors.RESET} {description}")

    def _calculate_score(self, flags) -> int:
        if not flags:
            return 0
        total = sum(f["severity"] for f in flags)
        return min(100, int(total * 1.5))
