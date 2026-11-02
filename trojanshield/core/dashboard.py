"""
core/dashboard.py - Live Rich Terminal Dashboard
=================================================
Real-time scan progress with threat meter, stage status,
flag feed, and C2 infrastructure panel.
"""

import time
import threading
from pathlib import Path
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.syntax import Syntax


console = Console()

THREAT_GRADIENT = [
    (0,  20,  "bright_green",   "▓" * 2  + "░" * 18),
    (20, 40,  "green",          "▓" * 5  + "░" * 15),
    (40, 60,  "yellow",         "▓" * 10 + "░" * 10),
    (60, 80,  "dark_orange",    "▓" * 15 + "░" * 5),
    (80, 101, "bold bright_red","▓" * 20),
]

def threat_bar(score: int) -> Text:
    for lo, hi, color, bar in THREAT_GRADIENT:
        if lo <= score < hi:
            t = Text()
            t.append(f" {bar} ", style=color)
            t.append(f" {score}/100", style=f"bold {color}")
            return t
    return Text(f" {'▓'*20} {score}/100", style="bold bright_red")


class Dashboard:
    """Interactive live dashboard for TrojanShield scans."""

    def __init__(self, filepath: Path):
        self.filepath  = filepath
        self.stages    = {}
        self.flags     = []
        self.c2        = []
        self.score     = 0
        self.verdict   = "SCANNING..."
        self.current_stage = ""
        self._lock     = threading.Lock()

    def update(self, stage_name: str, stage_result: dict):
        with self._lock:
            self.stages[stage_name] = stage_result
            self.flags.extend(stage_result.get("flags", []))
            self.c2.extend(stage_result.get("c2_indicators", []))
            self.current_stage = stage_name

    def set_final(self, results: dict):
        with self._lock:
            self.score   = results.get("threat_score", 0)
            self.verdict = results.get("verdict", "UNKNOWN")

    def _build_layout(self) -> Panel:
        with self._lock:
            score   = self.score
            verdict = self.verdict
            stages  = dict(self.stages)
            flags   = list(self.flags)
            c2      = list(set(self.c2))

        # Header
        header = Text(justify="center")
        header.append("TROJANSHIELD", style="bold cyan")
        header.append("  Adaptive Trojan Detection", style="dim")

        # File info
        size = self.filepath.stat().st_size
        file_panel = Panel(
            f"[bold white]{self.filepath.name}[/]\n"
            f"[dim]{size:,} bytes[/]  [dim]|[/]  [cyan]{self.current_stage or 'Initializing...'}[/]",
            title="[bold]Target File[/]",
            border_style="cyan",
            padding=(0, 1),
        )

        # Threat meter
        bar = threat_bar(score)
        verdict_color = "bright_red" if score >= 60 else ("yellow" if score >= 30 else "bright_green")
        meter = Panel(
            Text.assemble(
                ("THREAT SCORE  ", "dim"),
                bar,
                "\n",
                ("VERDICT  ", "dim"),
                (verdict, f"bold {verdict_color}"),
            ),
            title="[bold]Threat Assessment[/]",
            border_style=verdict_color,
            padding=(0, 1),
        )

        # Stage table
        stage_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0,1))
        stage_table.add_column("Stage", style="white", no_wrap=True)
        stage_table.add_column("Status", justify="center")
        stage_table.add_column("Score", justify="right")
        stage_table.add_column("Flags", justify="right")

        all_stages = [
            "Static Analysis",
            "VM Sandbox Simulation",
            "Heuristic Scanning",
            "Multi-VM Orchestration",
            "ML Engine",
        ]
        for sname in all_stages:
            if sname in stages:
                s   = stages[sname].get("score", 0)
                n   = len(stages[sname].get("flags", []))
                sc  = "bright_red" if s >= 60 else ("yellow" if s >= 30 else "bright_green")
                stage_table.add_row(
                    sname,
                    "[bright_green]done[/]",
                    f"[{sc}]{s}/100[/]",
                    f"[{sc}]{n}[/]",
                )
            elif sname == self.current_stage:
                stage_table.add_row(sname, "[cyan]⟳ Running[/]", "-", "-")
            else:
                stage_table.add_row(sname, "[dim]○ Pending[/]", "[dim]-[/]", "[dim]-[/]")

        stages_panel = Panel(stage_table, title="[bold]Pipeline Stages[/]", border_style="blue", padding=(0,0))

        # Flags feed (most recent critical first)
        sorted_flags = sorted(flags, key=lambda f: f.get("severity", 0), reverse=True)
        flag_lines   = Text()
        for f in sorted_flags[:12]:
            sev   = f.get("severity", 0)
            desc  = f.get("description", "")[:72]
            color = "bright_red" if sev >= 8 else ("yellow" if sev >= 5 else "dim")
            flag_lines.append(f" [{sev:2d}] ", style=f"bold {color}")
            flag_lines.append(desc + "\n", style=color)

        if not flag_lines._spans:
            flag_lines.append("  No flags yet...", style="dim")

        flags_panel = Panel(flag_lines, title=f"[bold]Indicators ({len(flags)} total)[/]",
                            border_style="red" if flags else "dim", padding=(0,0))

        # C2 panel
        c2_text = Text()
        if c2:
            for item in list(dict.fromkeys(c2))[:8]:
                c2_text.append("  -> ", style="bold red")
                c2_text.append(item[:70] + "\n", style="red")
        else:
            c2_text.append("  No C2 infrastructure identified", style="dim")

        c2_panel = Panel(c2_text, title="[bold red]C2 Infrastructure[/]",
                         border_style="red" if c2 else "dim", padding=(0,0))

        # Assemble
        from rich.table import Table as RTable
        grid = RTable.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(file_panel, meter)
        grid.add_row(stages_panel, flags_panel)
        grid.add_row(c2_panel, c2_panel)  # full width c2

        return Panel(grid, title="[bold cyan]TROJANSHIELD[/]  [dim]v1.0[/]",
                     border_style="cyan", padding=(0,0))


def run_with_dashboard(filepath: Path, verbose: bool = False) -> dict:
    """Run the full pipeline with a live dashboard."""
    from scanners.static    import StaticAnalyzer
    from scanners.sandbox   import SandboxAnalyzer
    from scanners.heuristic import HeuristicScanner
    from scanners.multivm   import MultiVMOrchestrator
    from ml.classifier      import MLAnalyzer

    dash = Dashboard(filepath)

    STAGES = [
        ("Static Analysis",        StaticAnalyzer,       []),
        ("VM Sandbox Simulation",  SandboxAnalyzer,      ["static"]),
        ("Heuristic Scanning",     HeuristicScanner,     ["static"]),
        ("Multi-VM Orchestration", MultiVMOrchestrator,  ["static", "sandbox", "heuristic"]),
        ("ML Engine",              MLAnalyzer,           ["all"]),
    ]

    results = {
        "file":           str(filepath),
        "stages":         {},
        "threat_score":   0,
        "verdict":        "SCANNING",
        "c2_indicators":  [],
        "evasion_detected": False,
        "timing":         {},
    }

    stage_results = {}

    with Live(dash._build_layout(), refresh_per_second=4, console=console) as live:
        for stage_name, AnalyzerClass, deps in STAGES:
            dash.current_stage = stage_name
            live.update(dash._build_layout())

            t0       = time.time()
            analyzer = AnalyzerClass(verbose=verbose)

            # Call with correct signature
            if stage_name == "Static Analysis":
                sr = analyzer.analyze(filepath)
            elif stage_name == "ML Engine":
                sr = analyzer.analyze(filepath, results)
            elif len(deps) == 1:
                sr = analyzer.analyze(filepath, stage_results.get(deps[0], {}))
            else:
                sr = analyzer.analyze(filepath, stage_results.get("static", {}))

            stage_results[stage_name.lower().split()[0]] = sr
            results["stages"][stage_name] = sr
            results["c2_indicators"].extend(sr.get("c2_indicators", []))
            results["timing"][stage_name] = round(time.time() - t0, 2)

            dash.update(stage_name, sr)
            live.update(dash._build_layout())
            time.sleep(0.3)  # brief pause so UI is visible

        # Final scoring
        results["threat_score"] = _aggregate(results)
        results["verdict"]      = _verdict(results)
        dash.set_final(results)
        live.update(dash._build_layout())
        time.sleep(1.5)

    return results


def _aggregate(results):
    weights = {
        "Static Analysis":       0.20,
        "VM Sandbox Simulation":  0.20,
        "Heuristic Scanning":    0.25,
        "Multi-VM Orchestration": 0.20,
        "ML Engine":             0.15,
    }
    total = sum(
        results["stages"].get(s, {}).get("score", 0) * w
        for s, w in weights.items()
    )
    base = int(total)
    if results.get("evasion_detected"):
        base = min(100, base + 10)
    critical = sum(
        sum(1 for f in results["stages"].get(s, {}).get("flags", []) if f.get("severity", 0) >= 9)
        for s in results["stages"]
    )
    return min(100, base + critical * 3)


def _verdict(results):
    score = results["threat_score"]
    fam   = results["stages"].get("ML Engine", {}).get("classification", {}).get("family", "Unknown")
    if score >= 80:   return f"MALICIOUS - {fam}"
    if score >= 60:   return f"HIGH RISK - {fam}"
    if score >= 40:   return "SUSPICIOUS - Recommend quarantine"
    if score >= 20:   return "LOW RISK - Monitor recommended"
    return "CLEAN - No significant threats detected"
