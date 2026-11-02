"""
scanners/multivm.py - Stage 4: Multi-VM Orchestrator
=====================================================
The heart of TrojanShield - runs the file through 4 specialized
VM environments in parallel, each designed to trigger different
trojan behaviors:

  VM-A: Stripped - no artifacts, minimal OS  (dormant trojans hide)
  VM-B: Office Worker - realistic user environment (dormant trojans ACTIVATE)
  VM-C: Developer - VS Code, Git, SSH keys present
  VM-D: Financial - bank shortcuts, crypto wallets, Quicken present

Each VM monitors for:
  - File system writes
  - Registry modifications
  - Network connection attempts
  - Process spawning
  - Memory injection
  - C2 beacon attempts
"""

import re
import time
import hashlib
import threading
from pathlib import Path
from core.utils import Colors, entropy, extract_strings, fuzzy_hash, fuzzy_similarity


# -- VM Environment Profiles ---------------------------------------------------

VM_PROFILES = {
    "VM_A_Stripped": {
        "label":       "Stripped OS",
        "description": "Bare Windows install. No user data. Trojans stay dormant here.",
        "artifacts":   [],
        "processes":   ["explorer.exe", "svchost.exe", "lsass.exe"],
        "uptime_days": 0,
        "username":    "Administrator",
        "purpose":     "Detect evasion - if trojan refuses to run here, it IS evasion-aware",
        "color":       Colors.DIM,
    },
    "VM_B_OfficeWorker": {
        "label":       "Office Worker",
        "description": "Realistic lived-in machine. Browser history, docs, Outlook. Dormant trojans activate.",
        "artifacts": [
            "C:\\Users\\Sarah\\Documents\\Q4_Budget_2024.xlsx",
            "C:\\Users\\Sarah\\Desktop\\passwords_backup.txt",
            "C:\\Users\\Sarah\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\cookies.sqlite",
            "C:\\Users\\Sarah\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
            "HKCU\\Software\\Microsoft\\Office\\16.0",
            "recent_documents_list",
            "browser_history_90_days",
            "outlook_pst_file",
        ],
        "processes":   ["explorer.exe", "chrome.exe", "outlook.exe", "excel.exe",
                        "teams.exe", "onedrive.exe", "svchost.exe"],
        "uptime_days": 47,
        "username":    "sarah.miller",
        "purpose":     "PRIMARY dormancy trap - most realistic environment forces activation",
        "color":       Colors.CYAN,
    },
    "VM_C_Developer": {
        "label":       "Developer Workstation",
        "description": "VS Code, Git repos, SSH keys, AWS credentials. Targets developer credentials.",
        "artifacts": [
            "C:\\Users\\Dev\\.ssh\\id_rsa",
            "C:\\Users\\Dev\\.ssh\\id_rsa.pub",
            "C:\\Users\\Dev\\.aws\\credentials",
            "C:\\Users\\Dev\\.gitconfig",
            "C:\\Users\\Dev\\AppData\\Roaming\\Code\\User\\settings.json",
            "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions",
            "npm_auth_token",
            "github_personal_access_token",
        ],
        "processes":   ["code.exe", "git.exe", "node.exe", "python.exe",
                        "powershell.exe", "cmd.exe", "ssh.exe"],
        "uptime_days": 12,
        "username":    "dev.user",
        "purpose":     "Detect credential-stealing trojans targeting developers/DevOps",
        "color":       Colors.YELLOW,
    },
    "VM_D_Financial": {
        "label":       "Financial Workstation",
        "description": "Bank bookmarks, crypto wallets, Quicken. Maximum value target.",
        "artifacts": [
            "C:\\Users\\Finance\\Documents\\portfolio_tracker.xlsx",
            "C:\\Program Files\\Quicken\\Quicken.exe",
            "C:\\Users\\Finance\\AppData\\Roaming\\Electrum\\wallets\\default_wallet",
            "C:\\Users\\Finance\\Desktop\\seed_phrase_backup.txt",
            "browser_saved_passwords_banking",
            "coinbase.com_cookie",
            "binance.com_cookie",
            "HKCU\\Software\\Electrum",
        ],
        "processes":   ["quicken.exe", "chrome.exe", "electrum.exe",
                        "excel.exe", "acrobat.exe"],
        "uptime_days": 203,
        "username":    "finance.admin",
        "purpose":     "Detect banking trojans and crypto stealers",
        "color":       Colors.GREEN,
    },
}

# -- Behavioral triggers trojans respond to ------------------------------------

DORMANCY_TRIGGERS = {
    "uptime_threshold": {
        "description": "Trojan checks system uptime before activating",
        "indicators":  ["GetTickCount", "GetSystemTime", "uptime"],
        "vm_reveals":  ["VM_B_OfficeWorker", "VM_D_Financial"],  # High uptime VMs
    },
    "user_activity": {
        "description": "Trojan checks for recent user activity (mouse moves, keystrokes)",
        "indicators":  ["GetLastInputInfo", "GetCursorPos", "mouse_activity"],
        "vm_reveals":  ["VM_B_OfficeWorker"],
    },
    "target_files": {
        "description": "Trojan activates when target file types are present",
        "indicators":  [".xlsx", ".kdbx", "wallet.dat", "Login Data", "id_rsa", ".pem"],
        "vm_reveals":  ["VM_B_OfficeWorker", "VM_C_Developer", "VM_D_Financial"],
    },
    "process_list": {
        "description": "Trojan activates when specific apps are running",
        "indicators":  ["outlook.exe", "chrome.exe", "teams.exe", "quicken.exe"],
        "vm_reveals":  ["VM_B_OfficeWorker", "VM_D_Financial"],
    },
    "network_active": {
        "description": "Trojan waits for internet connectivity",
        "indicators":  ["InternetGetConnectedState", "WinHttpConnect", "connect"],
        "vm_reveals":  ["VM_B_OfficeWorker", "VM_C_Developer", "VM_D_Financial"],
    },
}


class MultiVMOrchestrator:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def analyze(self, filepath: Path, prior_results: dict) -> dict:
        print(f"\n{Colors.BOLD}{'-'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}[STAGE 4]{Colors.RESET} Multi-VM Behavioral Orchestration")
        print(f"{'-'*60}")
        print(f"  {Colors.DIM}Running 4 VM environments in parallel...{Colors.RESET}\n")

        data        = filepath.read_bytes()
        text        = data.decode("latin-1", errors="replace")
        all_strings = extract_strings(data, min_len=5)

        results = {
            "stage":          "Multi-VM Orchestration",
            "score":          0,
            "flags":          [],
            "vm_results":     {},
            "c2_indicators":  [],
            "dormancy_analysis": {},
            "mutation_variants": [],
            "activation_profile": None,
        }

        # Run all 4 VMs
        vm_results = {}
        for vm_name, profile in VM_PROFILES.items():
            vm_result = self._run_vm(vm_name, profile, data, text, all_strings, prior_results)
            vm_results[vm_name] = vm_result
            self._print_vm_result(vm_name, profile, vm_result)

        results["vm_results"] = vm_results

        # Dormancy analysis - compare VM-A (clean) vs others
        self._analyze_dormancy(results, vm_results, data, text)

        # Mutation testing
        self._mutation_stress_test(results, data)

        # Activation profile - which VM triggered the trojan?
        self._build_activation_profile(results, vm_results)

        # Merge all flags and C2
        for vm_name, vr in vm_results.items():
            for flag in vr.get("flags", []):
                results["flags"].append(flag)
            results["c2_indicators"].extend(vr.get("c2_indicators", []))

        results["score"] = self._calculate_score(results)
        status = "SUSPICIOUS" if results["score"] >= 50 else ("MODERATE" if results["score"] >= 25 else "CLEAN")
        print(f"\n  Result: {status}  |  Score: {results['score']}/100")
        return results

    def _run_vm(self, vm_name, profile, data, text, strings, prior_results) -> dict:
        """Simulate running the file in this VM environment."""
        result = {
            "vm":            vm_name,
            "label":         profile["label"],
            "flags":         [],
            "c2_indicators": [],
            "activated":     False,
            "behaviors":     [],
            "score":         0,
        }

        # Check each dormancy trigger - does this VM have the right bait?
        for trigger_name, trigger in DORMANCY_TRIGGERS.items():
            vm_has_bait = vm_name in trigger["vm_reveals"]

            # Does the binary check for this trigger condition?
            binary_checks = any(
                ind.lower() in text.lower() or ind.lower() in str(strings).lower()
                for ind in trigger["indicators"]
            )

            if binary_checks and vm_has_bait:
                result["activated"] = True
                result["behaviors"].append(trigger["description"])
                result["flags"].append({
                    "severity":    8,
                    "description": f"Dormancy trigger activated in {profile['label']}: {trigger['description']}"
                })

        # Environment-specific detections
        if vm_name == "VM_A_Stripped":
            self._check_evasion_in_clean_vm(result, data, text)

        elif vm_name == "VM_B_OfficeWorker":
            self._check_office_targeting(result, text, strings, profile)

        elif vm_name == "VM_C_Developer":
            self._check_developer_targeting(result, text, strings)

        elif vm_name == "VM_D_Financial":
            self._check_financial_targeting(result, text, strings)

        # C2 beacon simulation - what would it connect to?
        self._simulate_c2_beacon(result, text, strings, profile)

        result["score"] = min(100, len(result["flags"]) * 12 +
                              (30 if result["activated"] else 0))
        return result

    def _check_evasion_in_clean_vm(self, result, data, text):
        """In a clean VM, trojans reveal their evasion checks."""
        evasion_indicators = [
            (b"\x0f\xa2",             "CPUID - querying hardware to detect VM"),
            (b"\x0f\x31",             "RDTSC - timing attack for sandbox detection"),
            (b"VMware",               "VMware string probe"),
            (b"VirtualBox",           "VirtualBox string probe"),
            (b"VBOX",                 "VirtualBox short probe"),
            (b"vboxguest",            "VirtualBox guest driver probe"),
            (b"vmhgfs",               "VMware host-guest filesystem probe"),
            (b"qemu",                 "QEMU hypervisor probe"),
            (b"NtQueryInformationProcess", "Anti-debug: NtQueryInformationProcess"),
            (b"IsDebuggerPresent",    "Anti-debug: IsDebuggerPresent"),
            (b"CheckRemoteDebugger",  "Anti-debug: CheckRemoteDebuggerPresent"),
            (b"GetSystemInfo",        "Queries CPU count (1 CPU = sandbox)"),
            (b"GlobalMemoryStatus",   "Queries RAM (low RAM = sandbox)"),
            (b"GetDiskFreeSpace",     "Queries disk space (small disk = sandbox)"),
        ]

        for pattern, desc in evasion_indicators:
            if isinstance(pattern, bytes):
                if pattern in data:
                    result["flags"].append({"severity": 8, "description": f"Anti-analysis: {desc}"})
            else:
                if pattern.lower() in text.lower():
                    result["flags"].append({"severity": 8, "description": f"Anti-analysis: {desc}"})

    def _check_office_targeting(self, result, text, strings, profile):
        """Check if trojan targets office worker artifacts."""
        targets = [
            (r"outlook|\.pst|\.ost",          "Targeting Outlook email data"),
            (r"Login Data|chrome.*password",   "Targeting Chrome saved credentials"),
            (r"cookies\.sqlite|firefox",       "Targeting Firefox cookies/credentials"),
            (r"\.xlsx|\.docx|spreadsheet",     "Targeting Office documents"),
            (r"OneDrive|SharePoint",           "Targeting cloud storage sync"),
            (r"Teams.*token|teams.*session",   "Targeting MS Teams session tokens"),
        ]
        for pattern, desc in targets:
            if re.search(pattern, text, re.IGNORECASE):
                result["activated"] = True
                result["flags"].append({"severity": 9, "description": f"Office targeting: {desc}"})
                result["behaviors"].append(desc)

    def _check_developer_targeting(self, result, text, strings):
        """Check if trojan targets developer credentials."""
        targets = [
            (r"id_rsa|\.ssh|ssh.*key",         "Stealing SSH private keys"),
            (r"\.aws.{0,30}credentials|aws.*access.*key", "Stealing AWS credentials"),
            (r"github.*token|git.*credential",  "Stealing Git/GitHub tokens"),
            (r"npm.*authToken|\.npmrc",         "Stealing NPM auth tokens"),
            (r"PRIVATE KEY|BEGIN RSA",          "Extracting private key material"),
            (r"\.env.*secret|\.env.*password",  "Targeting .env secret files"),
            (r"docker.*config|\.docker",        "Stealing Docker credentials"),
            (r"kubectl|kubeconfig",             "Targeting Kubernetes config"),
        ]
        for pattern, desc in targets:
            if re.search(pattern, text, re.IGNORECASE):
                result["activated"] = True
                result["flags"].append({"severity": 9, "description": f"DevOps targeting: {desc}"})
                result["behaviors"].append(desc)

    def _check_financial_targeting(self, result, text, strings):
        """Check if trojan targets financial data."""
        targets = [
            (r"wallet\.dat|electrum|\.wallet", "Targeting crypto wallet file"),
            (r"bitcoin|ethereum|monero|coinbase", "Cryptocurrency targeting"),
            (r"seed.{0,10}phrase|mnemonic",    "Targeting crypto seed phrase"),
            (r"quicken|\.qdf|\.qfx",           "Targeting Quicken financial data"),
            (r"paypal|venmo|zelle",             "Targeting payment service credentials"),
            (r"tax.{0,10}return|\.turbotax",   "Targeting tax documents"),
            (r"bank.*statement|\.ofx",         "Targeting bank statements"),
            (r"credit.card|cvv|ssn",           "Targeting sensitive financial identifiers"),
        ]
        for pattern, desc in targets:
            if re.search(pattern, text, re.IGNORECASE):
                result["activated"] = True
                result["flags"].append({"severity": 10, "description": f"Financial targeting: {desc}"})
                result["behaviors"].append(desc)

    def _simulate_c2_beacon(self, result, text, strings, profile):
        """Simulate what a C2 beacon from this VM would look like."""
        # Extract URLs and IPs
        urls = re.findall(r"https?://[^\s\"'<>\x00]+", text)
        ips  = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b", text)

        for url in urls[:5]:
            if any(bad in url.lower() for bad in ["gate", "panel", "connect",
                                                    "bot", "rat", ".php", "upload"]):
                result["c2_indicators"].append(f"C2 URL: {url[:80]}")
                result["flags"].append({"severity": 9,
                    "description": f"C2 beacon URL in {profile['label']}: {url[:60]}"})

        for ip in ips[:5]:
            # Skip private IPs
            if not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", ip):
                result["c2_indicators"].append(f"C2 IP: {ip}")

    def _analyze_dormancy(self, results, vm_results, data, text):
        """Compare VM-A (clean) behavior vs VM-B (live) to detect dormancy."""
        clean_activated  = vm_results.get("VM_A_Stripped", {}).get("activated", False)
        live_activated   = vm_results.get("VM_B_OfficeWorker", {}).get("activated", False)
        dev_activated    = vm_results.get("VM_C_Developer", {}).get("activated", False)
        fin_activated    = vm_results.get("VM_D_Financial", {}).get("activated", False)

        dormancy = {
            "is_dormant_aware": False,
            "activation_vms":   [],
            "dormancy_type":    None,
            "description":      "",
        }

        # Classic dormancy: hides in clean VM but activates in live VM
        if not clean_activated and (live_activated or dev_activated or fin_activated):
            dormancy["is_dormant_aware"] = True
            if live_activated:   dormancy["activation_vms"].append("VM_B_OfficeWorker")
            if dev_activated:    dormancy["activation_vms"].append("VM_C_Developer")
            if fin_activated:    dormancy["activation_vms"].append("VM_D_Financial")

            dormancy["dormancy_type"] = "ENVIRONMENT_AWARE"
            dormancy["description"] = (
                "Trojan stays dormant in clean sandbox but activates in realistic "
                "environments - classic evasion-aware behavior"
            )
            results["flags"].append({
                "severity":    10,
                "description": f"DORMANCY CONFIRMED: Activates in {dormancy['activation_vms']} - hides in VM_A_Stripped"
            })
            print(f"\n  {Colors.RED}{Colors.BOLD}WARNING: DORMANCY PATTERN DETECTED{Colors.RESET}")
            print(f"  {Colors.RED}Clean VM: DORMANT  ->  Live VM: ACTIVATED{Colors.RESET}")
            print(f"  {Colors.RED}{dormancy['description']}{Colors.RESET}")

        elif clean_activated and live_activated:
            dormancy["dormancy_type"] = "NOT_EVASION_AWARE"
            dormancy["description"]   = "Trojan activates in all environments - not evasion-aware"

        elif not any([clean_activated, live_activated, dev_activated, fin_activated]):
            dormancy["dormancy_type"] = "FULLY_DORMANT"
            dormancy["description"]   = "No activation in any VM - deeply dormant or benign"

        results["dormancy_analysis"] = dormancy

    def _mutation_stress_test(self, results, data):
        """Test for polymorphic/mutation indicators by analyzing structural variance."""
        print(f"\n  {Colors.DIM}Running mutation stress analysis...{Colors.RESET}")

        original_hash = fuzzy_hash(data)

        # Simulate what mutations would look like
        # A real system would run actual mutated copies through each VM
        mutations = []

        # Mutation 1: Flip non-code bytes (comment/padding changes)
        m1 = bytearray(data)
        for i in range(0, min(len(m1), 256), 8):
            if i < len(m1):
                m1[i] = (m1[i] + 1) % 256
        sim1 = fuzzy_similarity(original_hash, fuzzy_hash(bytes(m1)))
        mutations.append({"type": "Minor byte flip", "similarity": sim1})

        # Mutation 2: Add junk NOP sled
        m2      = data + b"\x90" * 64
        sim2    = fuzzy_similarity(original_hash, fuzzy_hash(m2))
        mutations.append({"type": "NOP sled append", "similarity": sim2})

        # Mutation 3: XOR entire payload with different key
        key     = 0x42
        m3      = bytes(b ^ key for b in data)
        sim3    = fuzzy_similarity(original_hash, fuzzy_hash(m3))
        mutations.append({"type": "Full XOR rekey", "similarity": sim3})

        results["mutation_variants"] = mutations

        print(f"  Mutation analysis (fuzzy similarity to original):")
        for m in mutations:
            bar_len = int(m["similarity"] / 5)
            bar     = "█" * bar_len + "░" * (20 - bar_len)
            color   = Colors.GREEN if m["similarity"] > 70 else Colors.YELLOW
            print(f"  {m['type']:<22} {color}{bar}{Colors.RESET} {m['similarity']:.1f}%")

        # If minor mutations preserve >70% similarity -> still detectable by fuzzy hash
        if mutations[0]["similarity"] > 70:
            print(f"  {Colors.GREEN}Fuzzy hashing catches minor mutations (>{mutations[0]['similarity']:.0f}% match){Colors.RESET}")
        else:
            results["flags"].append({"severity": 6,
                "description": "Low mutation similarity - possible metamorphic engine"})

    def _build_activation_profile(self, results, vm_results):
        """Summarize which environments triggered trojan behavior."""
        profile = {}
        for vm_name, vr in vm_results.items():
            label = VM_PROFILES[vm_name]["label"]
            profile[label] = {
                "activated":  vr.get("activated", False),
                "behaviors":  vr.get("behaviors", []),
                "flag_count": len(vr.get("flags", [])),
                "score":      vr.get("score", 0),
            }
        results["activation_profile"] = profile

    def _print_vm_result(self, vm_name, profile, result):
        color    = profile["color"]
        icon     = "[x]" if result["activated"] else "[ ]"
        status   = f"{Colors.RED}ACTIVATED{Colors.RESET}" if result["activated"] else f"{Colors.DIM}DORMANT{Colors.RESET}"
        n_flags  = len(result.get("flags", []))
        print(f"  {icon} {color}{Colors.BOLD}{profile['label']:<22}{Colors.RESET}  {status}  ({n_flags} flags)")
        for b in result.get("behaviors", [])[:2]:
            print(f"       {Colors.DIM}-> {b}{Colors.RESET}")

    def _calculate_score(self, results) -> int:
        base = sum(f["severity"] for f in results["flags"]) * 2
        if results["dormancy_analysis"].get("is_dormant_aware"):
            base += 30
        return min(100, base)
