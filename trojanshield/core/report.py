"""
core/report.py - JSON Report Generator
"""
import json
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    def __init__(self, results: dict, filepath: Path):
        self.results  = results
        self.filepath = filepath

    def save_json(self, output_path: str):
        report = {
            "trojanshield_version": "1.0",
            "analysis_timestamp":   datetime.now().isoformat(),
            "target_file":          str(self.filepath),
            "file_size_bytes":      self.filepath.stat().st_size,
            "verdict":              self.results.get("verdict"),
            "threat_score":         self.results.get("threat_score"),
            "evasion_detected":     self.results.get("evasion_detected"),
            "c2_indicators":        self.results.get("c2_indicators", []),
            "timing_seconds":       self.results.get("timing", {}),
            "hashes":               self.results.get("stages", {}).get(
                                        "Static Analysis", {}).get("hashes", {}),
            "malware_family":       self.results.get("stages", {}).get(
                                        "ML Engine", {}).get("classification", {}),
            "stage_scores": {
                stage: data.get("score", 0)
                for stage, data in self.results.get("stages", {}).items()
            },
            "all_flags": {
                stage: [f["description"] for f in data.get("flags", [])]
                for stage, data in self.results.get("stages", {}).items()
            },
            "decrypted_configs":    self.results.get("stages", {}).get(
                                        "Heuristic Scanning", {}).get("decrypted_configs", []),
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
