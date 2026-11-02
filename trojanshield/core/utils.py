"""
core/utils.py - Shared utilities, colors, helpers
"""

import hashlib
import math
import struct
from collections import Counter


class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    TrojanShield{Colors.RESET}{Colors.DIM}    Adaptive Multi-Layer Trojan Detection System  |  v1.0{Colors.RESET}
    {"-"*90}"""
    print(banner)


def print_verdict(results: dict):
    score = results.get("threat_score", 0)
    verdict = results.get("verdict", "UNKNOWN")

    if score >= 75:
        color = Colors.RED
        icon  = "[HIGH]"
    elif score >= 40:
        color = Colors.YELLOW
        icon  = "[MED] "
    else:
        color = Colors.GREEN
        icon  = "[LOW] "

    print(f"\n{'='*60}")
    print(f"  {icon}  VERDICT: {color}{Colors.BOLD}{verdict}{Colors.RESET}")
    print(f"  THREAT SCORE: {color}{Colors.BOLD}{score}/100{Colors.RESET}")
    print(f"{'='*60}")

    # Stage breakdown
    stages = results.get("stages", {})
    print(f"\n  {'Stage':<28} {'Score':>6}  {'Flags'}")
    print(f"  {'-'*55}")
    for stage, data in stages.items():
        s = data.get("score", 0)
        flags = len(data.get("flags", []))
        sc = Colors.RED if s >= 60 else (Colors.YELLOW if s >= 30 else Colors.GREEN)
        print(f"  {stage:<28} {sc}{s:>5}%{Colors.RESET}  {flags} indicator(s)")

    # Top flags
    all_flags = []
    for stage, data in stages.items():
        for f in data.get("flags", []):
            all_flags.append((f["severity"], f["description"], stage))

    all_flags.sort(reverse=True)
    if all_flags:
        print(f"\n  {Colors.BOLD}Top Indicators:{Colors.RESET}")
        for sev, desc, stage in all_flags[:8]:
            sc = Colors.RED if sev >= 8 else (Colors.YELLOW if sev >= 5 else Colors.DIM)
            print(f"  {sc}[{sev:2d}]{Colors.RESET} {desc}  {Colors.DIM}({stage}){Colors.RESET}")

    c2 = results.get("c2_indicators", [])
    if c2:
        print(f"\n  {Colors.RED}{Colors.BOLD}C2 Infrastructure Detected:{Colors.RESET}")
        for item in c2[:5]:
            print(f"  {Colors.RED}->{Colors.RESET} {item}")

    print()


# -- Cryptographic helpers --------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def entropy(data: bytes) -> float:
    """Shannon entropy - 0 (uniform) to 8.0 (random/encrypted)"""
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values() if c)

def section_entropy(data: bytes, block_size: int = 256) -> list:
    """Entropy per block - detect encrypted regions"""
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) >= 16:
            results.append(entropy(block))
    return results

def fuzzy_hash(data: bytes) -> str:
    """Simple rolling hash - approximates ssdeep for similarity matching"""
    if len(data) < 64:
        return hashlib.md5(data).hexdigest()
    window = 7
    hashes = []
    for i in range(0, len(data) - window, window):
        chunk = data[i:i+window]
        hashes.append(sum(chunk) % 256)
    # Compress into 64-char hex
    compressed = []
    step = max(1, len(hashes) // 32)
    for i in range(0, len(hashes), step):
        compressed.append(hashes[i])
    return bytes(compressed[:32]).hex()

def fuzzy_similarity(h1: str, h2: str) -> float:
    """Returns 0-100 similarity between two fuzzy hashes"""
    if h1 == h2:
        return 100.0
    if len(h1) != len(h2) or not h1:
        return 0.0
    matches = sum(a == b for a, b in zip(h1, h2))
    return (matches / len(h1)) * 100

def extract_strings(data: bytes, min_len: int = 4) -> list:
    """Extract printable ASCII strings from binary data"""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings

def xor_decrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def try_xor_decrypt(data: bytes) -> list:
    """Try all single-byte XOR keys, return candidates that look like configs"""
    candidates = []
    for key in range(256):
        decrypted = xor_decrypt(data[:512], key)
        strings   = extract_strings(decrypted, min_len=6)
        for s in strings:
            if any(p in s.lower() for p in ["http", "cmd", ".exe", "192.", "10.", "gate", ".php"]):
                candidates.append({"key": hex(key), "string": s, "method": "XOR"})
    return candidates
