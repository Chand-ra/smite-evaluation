#!/usr/bin/env python3
"""
scheduler.py — Run all trials in parallel with a live TUI dashboard.

Usage:
    python scheduler.py \
        --cores 0,1,...,23 \
        --configs encrypted_bytes,ir-full-stack \
        --smite-dir ~/smite \
        --afl-dir ~/AFLplusplus \
        [--trials 20] \
        [--targets cln,lnd,ldk,eclair]

Ablation workflow:
    Compile the appropriate mutator variant, place it at
    target/release/libsmite_ir_mutator.so, then run with --configs ir-component-a.
    Repeat for each ablation configuration.
"""

import argparse
import collections
import csv
import json
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

EVAL_DIR = Path(__file__).parent.parent
RUN_TRIAL = Path(__file__).parent / "run_trial.py"

# ── Global thread-safe state ───────────────────────────────────────────────────

CSV_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()

PROGRESS = {"completed": 0, "total": 0}
SUMMARY = {}  # config -> {total, found, censored, in_progress, failed}
EVENT_LOG = collections.deque(maxlen=6)
START_TIME = 0.0

_shutdown = threading.Event()  # set on SIGINT to request graceful stop


# ── Argument parsing ───────────────────────────────────────────────────────────


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--cores", required=True, help="Comma-separated core IDs, e.g. 0,1,2,...,23"
    )
    p.add_argument(
        "--configs",
        required=True,
        help="Comma-separated configs, e.g. encrypted_bytes,ir-full-stack",
    )
    p.add_argument("--smite-dir", required=True, type=Path)
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--trials", type=int, default=20)
    p.add_argument("--targets", default=None)
    return p.parse_args()


# ── Bug loading ────────────────────────────────────────────────────────────────


def load_bugs(target_filter=None) -> list[dict]:
    bugs = []
    for path in sorted((EVAL_DIR / "vulnerabilities").rglob("metadata.json")):
        with open(path) as f:
            meta = json.load(f)
        meta["_meta_path"] = str(path)
        if target_filter is None or meta["target"] in target_filter:
            bugs.append(meta)
    return bugs


# ── Nyx share directory ────────────────────────────────────────────────────────


def config_to_scenario(config: str) -> str:
    """Map evaluation config label to Smite scenario name."""
    return "encrypted_bytes" if config == "encrypted_bytes" else "ir"


def ensure_sharedir(meta: dict, config: str, smite_dir: Path, afl_dir: Path) -> Path:
    """
    Generate the Nyx share directory for a (bug, config) pair if absent.

    Reused across all 20 trials: QEMU boots from it read-only and takes
    snapshots in memory. No cross-contamination between trials.
    """
    target = meta["target"]
    cve = meta["cve"].lower()  # CVE-2023-0001 → cve-2023-0001
    scenario = config_to_scenario(config)
    image = f"smite-eval-{target}-{cve}-{scenario}"
    sharedir = Path.home() / f"smite-nyx-eval-{target}-{cve}-{scenario}"

    if sharedir.exists():
        return sharedir

    result = subprocess.run(
        ["./scripts/setup-nyx.sh", str(sharedir), image, str(afl_dir)],
        cwd=smite_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[ERROR] setup-nyx.sh failed for {sharedir.name}:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    return sharedir


# ── CSV output ─────────────────────────────────────────────────────────────────


def append_csv_row(target, cve, config, trial_num, tte, censored):
    csv_path = EVAL_DIR / "results" / "trials.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with CSV_LOCK:
        write_header = not csv_path.exists()
        with open(csv_path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(
                    ["target", "cve", "config", "trial", "tte_seconds", "censored"]
                )
            w.writerow(
                [
                    target,
                    cve,
                    config,
                    trial_num,
                    f"{tte:.3f}" if tte is not None else "",
                    censored,
                ]
            )
        PROGRESS["completed"] += 1


# ── Worker ─────────────────────────────────────────────────────────────────────


def worker(
    core: int,
    work: Queue,
    smite_dir: Path,
    afl_dir: Path,
    sharedirs: dict,
    core_states: dict,
):
    while not _shutdown.is_set():
        try:
            meta, config, trial_num = work.get_nowait()
        except Empty:
            with STATE_LOCK:
                core_states[core].update(
                    {
                        "task": "Idle",
                        "status": "-",
                        "color": "dim",
                        "elapsed": 0.0,
                        "execs_sec": 0.0,
                        "edges": 0,
                        "crash_count": 0,
                        "start_time": 0.0,
                    }
                )
            return

        target, cve = meta["target"], meta["cve"]
        task_name = f"{target}/{cve}/{config}/trial-{trial_num:02d}"
        trial_dir = (
            EVAL_DIR / "results" / target / cve / config / f"trial-{trial_num:02d}"
        )

        start_time = time.time()  # captured *before* any subprocess launch
        with STATE_LOCK:
            core_states[core].update(
                {
                    "task": task_name,
                    "status": "Starting...",
                    "color": "yellow",
                    "elapsed": 0.0,
                    "execs_sec": 0.0,
                    "edges": 0,
                    "crash_count": 0,
                    "start_time": start_time,
                }
            )
            SUMMARY[config]["in_progress"] += 1

        sharedir = sharedirs[(target, cve, config)]

        cmd = [
            sys.executable,
            "-u",
            str(RUN_TRIAL),
            "--meta",
            meta["_meta_path"],
            "--config",
            config,
            "--trial",
            str(trial_num),
            "--core",
            str(core),
            "--smite-dir",
            str(smite_dir),
            "--afl-dir",
            str(afl_dir),
            "--sharedir",
            str(sharedir),
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # ── Background metrics poller ──────────────────────────────────────────
        def poll_metrics(proc=process, tdir=trial_dir, c=core):
            stats_file = tdir / "afl-out" / "default" / "fuzzer_stats"
            crashes_dir = tdir / "afl-out" / "default" / "crashes"
            last_edges = 0
            while proc.poll() is None and not _shutdown.is_set():
                execs, edges, crashes = 0.0, 0, 0
                if stats_file.exists():
                    try:
                        for line in stats_file.read_text().splitlines():
                            if line.startswith("execs_per_sec"):
                                execs = float(line.split()[-1])
                            elif line.startswith("edges_found"):
                                edges = int(line.split()[-1])
                    except Exception:
                        pass
                # never go backwards
                if edges < last_edges:
                    edges = last_edges
                else:
                    last_edges = edges

                if crashes_dir.exists():
                    try:
                        crashes = sum(
                            1
                            for f in crashes_dir.iterdir()
                            if f.name != "README.txt"
                            and not f.name.endswith(".log")
                            and not f.is_dir()
                        )
                    except Exception:
                        pass
                with STATE_LOCK:
                    core_states[c]["execs_sec"] = execs
                    core_states[c]["edges"] = edges
                    core_states[c]["crash_count"] = crashes
                time.sleep(2)

        threading.Thread(target=poll_metrics, daemon=True).start()

        # ── Output parser ──────────────────────────────────────────────────────
        completed_normally = False
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            with STATE_LOCK:
                if "[repro] MATCH" in line:
                    core_states[core]["status"] = "Match found!"
                    core_states[core]["color"] = "bold green"
                elif "[repro] submitting" in line:
                    core_states[core]["status"] = "Reproducing..."
                    core_states[core]["color"] = "yellow"
                elif "[running]" in line:
                    core_states[core]["status"] = "Fuzzing..."
                    core_states[core]["color"]  = "cyan"
                elif "[warn] afl-fuzz exited early" in line:
                    core_states[core]["status"] = "AFL exited early"
                    core_states[core]["color"] = "bold red"
                elif "[retry]" in line:
                    # Extract reason and delay from lines like:
                    #   [retry] mid-campaign early exit (attempt 1/6), retrying in 150s
                    m = re.search(
                        r"\[retry\]\s+(.+?)\s+\((attempt\s+\d+/\d+)\),\s+retrying\s+in\s+(\d+)s",
                        line,
                    )
                    if m:
                        reason = m.group(1)
                        attempt_str = m.group(2)
                        delay = m.group(3)
                        core_states[core]["status"] = (
                            f"Retry ({attempt_str}): {reason} ({delay}s)"
                        )
                    else:
                        core_states[core]["status"] = "Retrying..."
                    core_states[core]["color"] = "bold yellow"
                elif "[done]" in line:
                    res = line.split()[-1]
                    core_states[core]["status"] = f"Done: {res}"
                    core_states[core]["color"] = (
                        "bold green" if "TTE=" in res else "red"
                    )
                    completed_normally = True

        process.wait()

        # ── Record result ──────────────────────────────────────────────────────
        tte_file = trial_dir / "tte.txt"
        tte, censored = None, True
        if tte_file.exists():
            content = tte_file.read_text().strip()
            if content != "CENSORED":
                try:
                    tte = float(content)
                    censored = False
                except ValueError:
                    pass

        append_csv_row(target, cve, config, trial_num, tte, censored)

        with STATE_LOCK:
            SUMMARY[config]["in_progress"] -= 1
            ts = time.strftime("%H:%M:%S")
            if completed_normally:
                if censored:
                    SUMMARY[config]["censored"] += 1
                    EVENT_LOG.append(f"[[cyan]{ts}[/]] {task_name} → [red]CENSORED[/]")
                else:
                    SUMMARY[config]["found"] += 1
                    EVENT_LOG.append(
                        f"[[cyan]{ts}[/]] {task_name} → "
                        f"[bold green]FOUND ({tte:.1f}s)[/]"
                    )
            else:
                SUMMARY[config]["failed"] += 1
                EVENT_LOG.append(f"[[cyan]{ts}[/]] {task_name} → [bold red]FAILED[/]")

        work.task_done()


# ── Dashboard ──────────────────────────────────────────────────────────────────


def _snapshot_state(core_states: dict) -> tuple[dict, dict, list, dict, float]:
    """
    Copy all mutable state under STATE_LOCK, then release before rendering.
    """
    with STATE_LOCK:
        cores_snap = {c: dict(s) for c, s in core_states.items()}
        summary_snap = {k: dict(v) for k, v in SUMMARY.items()}
        events_snap = list(EVENT_LOG)
        progress_snap = dict(PROGRESS)
    return cores_snap, summary_snap, events_snap, progress_snap


def generate_dashboard(core_states: dict) -> Group:
    cores_snap, summary_snap, events_snap, progress_snap = _snapshot_state(core_states)

    completed = progress_snap["completed"]
    total = progress_snap["total"]
    elapsed = time.time() - START_TIME

    # ── Per-core table ─────────────────────────────────────────────────────────
    core_table = Table(
        title=(
            f"Smite Orchestrator  "
            f"[cyan]{completed}[/]/[cyan]{total}[/] trials  "
            f"Elapsed [cyan]{_fmt_duration(elapsed)}[/]  "
        ),
        title_style="bold magenta",
        expand=True,
    )
    core_table.add_column("Core", justify="right", style="bold cyan", no_wrap=True)
    core_table.add_column("Task", style="white")
    core_table.add_column("Status")
    core_table.add_column("Elapsed", justify="right")
    core_table.add_column("Exec/s", justify="right")
    core_table.add_column("Edges", justify="right")
    core_table.add_column("Crashes", justify="right")

    now = time.time()
    for c in sorted(cores_snap):
        s = cores_snap[c]
        start = s.get("start_time", 0)
        if start and s["task"] != "Idle":
            elapsed_str = f"{now - start:.0f}s"
        else:
            elapsed_str = "—"
        core_table.add_row(
            f"Core {c}",
            s["task"],
            f"[{s['color']}]{s['status']}[/]",
            elapsed_str,
            f"{s['execs_sec']:.0f}" if s["execs_sec"] else "—",
            f"{s['edges']}" if s["edges"] else "—",
            f"{s['crash_count']}" if s["crash_count"] else "—",
        )

    # ── Summary table ──────────────────────────────────────────────────────────
    summary_table = Table(
        title="Overall Progress", title_style="bold green", expand=True
    )
    summary_table.add_column("Config")
    summary_table.add_column("Total", justify="right")
    summary_table.add_column("Found", justify="right", style="bold green")
    summary_table.add_column("Censored", justify="right", style="red")
    summary_table.add_column("In-Progress", justify="right", style="cyan")
    summary_table.add_column("Failed", justify="right", style="bold red")

    for config, vals in summary_snap.items():
        summary_table.add_row(
            config,
            str(vals["total"]),
            str(vals["found"]),
            str(vals["censored"]),
            str(vals["in_progress"]),
            str(vals["failed"]),
        )

    # ── Event log ──────────────────────────────────────────────────────────────
    events_text = "\n".join(events_snap) if events_snap else "No events yet..."
    event_panel = Panel(events_text, title="Recent Events", border_style="blue")

    return Group(core_table, summary_table, event_panel)


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# ── Main ───────────────────────────────────────────────────────────────────────


def main():
    global START_TIME

    args = parse_args()
    cores = [int(c) for c in args.cores.split(",")]
    configs = [c.strip() for c in args.configs.split(",")]
    targets = [t.strip() for t in args.targets.split(",")] if args.targets else None

    bugs = load_bugs(targets)
    if not bugs:
        print("No bugs found under vulnerabilities/.", file=sys.stderr)
        sys.exit(1)

    console = Console()

    # ── SIGINT: request graceful shutdown ──────────────────────────────────────
    def _handle_sigint(sig, frame):
        _shutdown.set()
        console.print(
            "\n[bold yellow]Interrupt received — "
            "finishing in-progress trials then stopping.[/]"
        )

    signal.signal(signal.SIGINT, _handle_sigint)

    # ── Initialise summary ─────────────────────────────────────────────────────
    for config in configs:
        SUMMARY[config] = {
            "total": 0,
            "found": 0,
            "censored": 0,
            "in_progress": 0,
            "failed": 0,
        }

    # ── Build work queue ───────────────────────────────────────────────────────
    work: Queue = Queue()
    for meta in bugs:
        for config in configs:
            for trial_num in range(1, args.trials + 1):
                work.put((meta, config, trial_num))
                SUMMARY[config]["total"] += 1

    PROGRESS["total"] = sum(s["total"] for s in SUMMARY.values())
    wall_est = PROGRESS["total"] * 24 / len(cores)

    console.print(
        f"Bugs: {len(bugs)}  Configs: {len(configs)}  "
        f"Trials: {args.trials}  Cores: {len(cores)}"
    )
    console.print(
        f"Total trials: {PROGRESS['total']}  "
        f"Estimated max wall-clock: {wall_est:.0f} hours"
    )

    # ── Phase 1: share directories ─────────────────────────────────────────────
    with console.status("[bold cyan]Generating Nyx share directories..."):
        sharedirs = {}
        for meta in bugs:
            for config in configs:
                key = (meta["target"], meta["cve"], config)
                sharedirs[key] = ensure_sharedir(
                    meta, config, args.smite_dir, args.afl_dir
                )
    console.print("[green]Share directories ready.[/]")

    # ── Phase 2: run trials ────────────────────────────────────────────────────
    core_states = {
        c: {
            "task": "Idle",
            "status": "-",
            "color": "dim",
            "elapsed": 0.0,
            "execs_sec": 0.0,
            "edges": 0,
            "crash_count": 0,
            "start_time": 0.0,
        }
        for c in cores
    }

    START_TIME = time.time()

    threads = [
        threading.Thread(
            target=worker,
            args=(core, work, args.smite_dir, args.afl_dir, sharedirs, core_states),
            daemon=True,
        )
        for core in cores
    ]

    with Live(
        generate_dashboard(core_states),
        refresh_per_second=4,
        console=console,
    ) as live:
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            live.update(generate_dashboard(core_states))
            time.sleep(0.25)
        for t in threads:
            t.join()

    if _shutdown.is_set():
        console.print("[bold yellow]Stopped early due to interrupt.[/]")
    else:
        console.print("[bold green]=== All trials complete ===[/]")


if __name__ == "__main__":
    main()
