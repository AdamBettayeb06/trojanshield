"""
core/pipeline.py - Detection Pipeline Orchestrator
===================================================
Runs all 5 stages in sequence, aggregates results, calculates final verdict.
"""

import time
from pathlib import Path
from core.utils import Colors


class DetectionPipeline:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def run(self, filepath: Path) -> dict:
        from scanners.static    import StaticAnalyzer
        from scanners.sandbox   import SandboxAnalyzer
        from scanners.heuristic import HeuristicScanner
        from scanners.multivm   import MultiVMOrchestrator
        from ml.classifier      import MLAnalyzer

        results = {
            "file":           str(filepath),
            "stages":         {},
            "threat_score":   0,
            "verdict":        "UNKNOWN",
            "c2_indicators":  [],
            "evasion_detected": False,
            "timing":         {},
        }

        # -- Stage 1: Static Analysis -------------------------------------
        t0 = time.time()
        static = StaticAnalyzer(verbose=self.verbose)
        s1 = static.analyze(filepath)
        results["stages"]["Static Analysis"] = s1
        results["c2_indicators"].extend(s1.get("c2_indicators", []))
        results["timing"]["static"] = round(time.time() - t0, 2)

        # -- Stage 2: VM Sandbox -------------------------------------------
        t0 = time.time()
        sandbox = SandboxAnalyzer(verbose=self.verbose)
        s2 = sandbox.analyze(filepath, s1)
        results["stages"]["VM Sandbox Simulation"] = s2
        results["c2_indicators"].extend(s2.get("c2_indicators", []))
        if s2.get("evasion_detected"):
            results["evasion_detected"] = True
        results["timing"]["sandbox"] = round(time.time() - t0, 2)

        # -- Stage 3: Heuristic Scanning -----------------------------------
        t0 = time.time()
        heuristic = HeuristicScanner(verbose=self.verbose)
        s3 = heuristic.analyze(filepath, s1)
        results["stages"]["Heuristic Scanning"] = s3
        results["c2_indicators"].extend(s3.get("c2_indicators", []))
        results["timing"]["heuristic"] = round(time.time() - t0, 2)

        # -- Stage 4: Multi-VM Orchestration ------------------------------
        t0 = time.time()
        multivm = MultiVMOrchestrator(verbose=self.verbose)
        s4 = multivm.analyze(filepath, results)
        results["stages"]["Multi-VM Orchestration"] = s4
        results["c2_indicators"].extend(s4.get("c2_indicators", []))
        if s4.get("dormancy_analysis", {}).get("is_dormant_aware"):
            results["evasion_detected"] = True
        results["timing"]["multivm"] = round(time.time() - t0, 2)

        # -- Stage 5: ML Engine --------------------------------------------
        t0 = time.time()
        ml = MLAnalyzer(verbose=self.verbose)
        s5 = ml.analyze(filepath, results)
        results["stages"]["ML Engine"] = s5
        results["timing"]["ml"] = round(time.time() - t0, 2)

        # -- Final scoring -------------------------------------------------
        results["c2_indicators"] = list(dict.fromkeys(results["c2_indicators"]))
        results["threat_score"]  = self._aggregate_score(results)
        results["verdict"]       = self._determine_verdict(results)

        return results

    def _aggregate_score(self, results: dict) -> int:
        weights = {
            "Static Analysis":        0.20,
            "VM Sandbox Simulation":  0.20,
            "Heuristic Scanning":     0.25,
            "Multi-VM Orchestration": 0.20,
            "ML Engine":              0.15,
        }

        total_score  = 0
        total_weight = 0
        for stage, weight in weights.items():
            score = results["stages"].get(stage, {}).get("score", 0)
            total_score  += score * weight
            total_weight += weight

        base = int(total_score / max(total_weight, 1))

        # Bonuses
        if results["evasion_detected"]:
            base = min(100, base + 15)
        if len(results["c2_indicators"]) >= 2:
            base = min(100, base + 10)

        # Critical flag bonus
        critical = sum(
            sum(1 for f in s.get("flags", []) if f.get("severity", 0) >= 9)
            for s in results["stages"].values()
        )
        base = min(100, base + critical * 5)

        return base

    def _determine_verdict(self, results: dict) -> str:
        score = results["threat_score"]
        classification = results["stages"].get("ML Engine", {}).get(
            "classification", {}).get("family", "UNKNOWN")

        if score >= 80:
            return f"MALICIOUS - {classification}"
        elif score >= 60:
            return f"HIGH RISK - {classification}"
        elif score >= 40:
            return "SUSPICIOUS - Recommend quarantine"
        elif score >= 20:
            return "LOW RISK - Monitor recommended"
        else:
            return "CLEAN - No significant threats detected"
