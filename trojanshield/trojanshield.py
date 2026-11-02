#!/usr/bin/env python3
"""
TrojanShield - Adaptive Multi-Layer Trojan Detection System
============================================================
Pipeline: Static Analysis -> VM Sandbox Sim -> Heuristic Scan -> Multi-Env Baiting -> ML/YOLO
"""

import sys
import os
import argparse
import json
import time
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.pipeline import DetectionPipeline
from core.report import ReportGenerator
from core.utils import print_banner, print_verdict, Colors

def main():
    parser = argparse.ArgumentParser(
        description="TrojanShield - Adaptive Trojan Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python trojanshield.py suspicious.exe
  python trojanshield.py malware.pdf --verbose
  python trojanshield.py file.dll --output report.json
  python trojanshield.py sample.py --all-stages
        """
    )
    parser.add_argument("target", help="File to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("--dashboard", action="store_true", help="Live rich terminal dashboard")
    parser.add_argument("--train", action="store_true", help="Train the ML model before scanning")
    args = parser.parse_args()

    print_banner()

    target = Path(args.target)
    if not target.exists():
        print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {target}")
        sys.exit(1)

    print(f"{Colors.CYAN}[*]{Colors.RESET} Target: {Colors.BOLD}{target}{Colors.RESET}")
    print(f"{Colors.CYAN}[*]{Colors.RESET} Size:   {target.stat().st_size:,} bytes")
    print(f"{Colors.CYAN}[*]{Colors.RESET} Start:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    if args.train:
        from ml.trainer import train_pipeline
        train_pipeline()
        print()

    if args.dashboard:
        from core.dashboard import run_with_dashboard
        results = run_with_dashboard(target, verbose=args.verbose)
    else:
        pipeline = DetectionPipeline(verbose=args.verbose)
        results  = pipeline.run(target)

    print_verdict(results)

    report = ReportGenerator(results, target)
    if args.output:
        report.save_json(args.output)
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} Report saved: {args.output}")
    else:
        report.save_json(f"trojanshield_report_{target.stem}_{int(time.time())}.json")

if __name__ == "__main__":
    main()
