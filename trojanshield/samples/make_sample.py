"""
Generate a synthetic malicious-looking binary sample for testing TrojanShield.
This creates a file with real trojan indicators (NOT actual malware).
"""
import struct, os, hashlib

def make_test_sample():
    # MZ header
    mz = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    mz += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" + b"\x00" * 20
    mz += struct.pack("<I", 0x40)   # PE offset

    # Suspicious strings (trojans leave these behind)
    suspicious_strings = b"\x00".join([
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"IsDebuggerPresent",
        b"RegSetValueEx",
        b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"cmd.exe /c powershell -enc JABjACAA",
        b"http://185.234.218.25:4444/gate.php",
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        b"InternetOpenUrl",
        b"C:\\Users\\Admin\\AppData\\Roaming\\svchost32.exe",
        b"VMware",
        b"VirtualBox",
        b"VBOX",
        b"ReflectiveLoader",
        b"keylog",
        b"password",
        b"NtUnmapViewOfSection",
        b"GetAsyncKeyState",
        b"schtasks /create /tn WindowsUpdate /tr",
    ]) + b"\x00"

    # High-entropy encrypted payload (simulated XOR-encrypted C2 config)
    import random
    random.seed(42)  # reproducible
    payload = bytes([random.randint(0, 255) for _ in range(512)])

    # CPUID + RDTSC opcodes (anti-analysis)
    anti_analysis = b"\x0f\xa2"      # CPUID
    anti_analysis += b"\x0f\x31"    # RDTSC
    anti_analysis += b"\x90" * 16   # NOP sled

    # UPX marker (packer indicator)
    upx_marker = b"UPX0\x00" * 3 + b"UPX1\x00" * 3

    # Metasploit-style stub
    msf_stub = b"\xfc\xe8\x82\x00\x00\x00"

    # Combine
    body = suspicious_strings + payload + anti_analysis + upx_marker + msf_stub
    body += b"\x00" * (0x200 - len(body) % 0x200)

    return mz + body

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_trojan.bin")

with open(OUT_PATH, "wb") as f:
    f.write(make_test_sample())

print(f"Test sample created: {os.path.getsize(OUT_PATH)} bytes")
