#!/usr/bin/env python3
"""
Smite Survival (TTE) Campaign Orchestrator

This script automates the execution of parallel time-to-exposure (TTE) trials against
known bugs for rigorous A/B survival-analysis evaluation. It queues jobs, maps
cores to trials for strict CPU isolation via `numactl`, launches `afl-fuzz` directly
against pre-built Nyx sharedirs (one per target/bug/scenario), and races background
reproduction attempts against every crash as it appears.

Unlike the coverage orchestrator, this script does not build Docker images itself: each
(target, BUG, scenario) image is expected to already exist, built at the historically
vulnerable commit. All configs share ONE `--smite-dir` checkout — only the mutator
shared library compiled there differs between ablation runs; compile the variant under
test at `target/release/libsmite_ir_mutator.so` before invoking the orchestrator (see
the ablation note below).

`smitebot doctor` is used for one-time host validation. This script handles preparing the
Nyx sharedir and launching `afl-fuzz` with the right strategy flags and environment
variables directly.

A live Rich TUI dashboard monitors coverage (Edges and Execs/s) of all active cores in
real-time, alongside a dedicated panel listing failed trials. Press Ctrl+C to stop
scheduling new jobs and safely kill active fuzzers.

Ablation workflow:
    Compile the mutator variant under test so that `--smite-dir`'s
    `target/release/libsmite_ir_mutator.so` is the variant under evaluation, then run
    with a label for it, e.g. `--configs component-a:ir`. Repeat per ablation, giving
    each run a distinct label (the mutator can only be one thing at a time under a
    shared --smite-dir, so ablations sharing a scenario are run as separate invocations).

Requirements:
    pip install rich
    smitebot (must be available in your PATH: `cargo install --path smitebot`)

Generated Directory Structure:
    <out_dir>/
    ├── <target_1>/                      # e.g., 'cln'
    │   ├── <bug_1>/                     # e.g., 'BUG-2023-0001'
    │   │   ├── <label_a>/               # e.g., 'ir-full-stack'
    │   │   │   ├── trial-01/
    │   │   │   │   ├── afl-fuzz.log     # Raw afl-fuzz stdout/stderr for this trial
    │   │   │   │   ├── sharedir/        # Nyx sharedir (deleted on cleanup)
    │   │   │   │   ├── crashing_input   # Present only if the trial FOUND the bug
    │   │   │   │   ├── tte.txt          # Either a float (seconds) or 'CENSORED'
    │   │   │   │   └── afl-out/default/ # Fuzzer output (stats, plot_data, bitmap)
    │   │   │   ├── trial-02/
    │   │   │   └── ...
    │   │   └── <label_b>/
    │   └── <bug_2>/

Usage:
    python survival-orchestrator.py \
        --out-dir OUT_DIR \
        --configs LABEL:SCENARIO[,LABEL:SCENARIO...] \
        --smite-dir SMITE_DIR \
        --targets TARGET[,TARGET...] \
        --cores CORE[,CORE...] \
        --afl-dir AFL_DIR \
        [--trials N | --trial-ids ID[,ID...]] \
        [--timeout SECONDS] \
        [--seed-dir SEED_DIR] \
        [--bugs BUG_ID[,BUG_ID...]]

Examples:
    # Standard survival evaluation (4 isolated cores, 20 trials per bug/config)
    python survival-orchestrator.py \
        --out-dir ./survival-results \
        --configs encrypted_bytes:encrypted_bytes,ir-full-stack:ir \
        --smite-dir ~/smite \
        --targets cln,lnd,ldk,eclair \
        --cores 0,1,2,3 \
        --afl-dir ~/AFLplusplus

    # Fast exploratory test run (1-hour timeout, 5 trials, with seed corpus)
    python survival-orchestrator.py \
        --out-dir ./survival-results \
        --configs ir-full-stack:ir \
        --smite-dir ~/smite \
        --targets cln \
        --cores 4,5,6,7,8 \
        --trials 5 \
        --timeout 3600 \
        --afl-dir ~/AFLplusplus \
        --seed-dir ./my_seeds   # must contain ./my_seeds/ir/cln/, etc. per scenario, per target

    # Ablation run: compile the component-a mutator under --smite-dir first, then
    python survival-orchestrator.py \
        --out-dir ./survival-results \
        --configs ir-component-a:ir \
        --smite-dir ~/smite \
        --targets cln \
        --cores 0,1 \
        --afl-dir ~/AFLplusplus

    # Targeted re-run of specific failed trials (preserves all other data)
    python survival-orchestrator.py \
        --out-dir ./survival-results \
        --configs ir-full-stack:ir \
        --smite-dir ~/smite \
        --targets lnd \
        --cores 0,1 \
        --trial-ids 1,15,20 \
        --afl-dir ~/AFLplusplus
"""

import argparse
import collections
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

EVAL_DIR = Path(__file__).parent.parent

# ────────────────────────────  CONFIGURATION  ────────────────────────────


def testcache_size_mb() -> Optional[int]:
    """Suggested AFL_TESTCACHE_SIZE (MB) from available RAM.

    Mirrors smitebot's conservative thresholds (50/250/500 MB), since
    machines here are shared across several concurrently-fuzzing cores.
    """
    try:
        meminfo = Path("/proc/meminfo").read_text()
    except OSError:
        return None

    for line in meminfo.splitlines():
        if line.startswith("MemAvailable:"):
            try:
                free_mb = int(line.split()[1]) // 1024
            except (IndexError, ValueError):
                return None
            if free_mb > 32_000:
                return 500
            elif free_mb > 8_000:
                return 250
            else:
                return 50
    return None


def get_numa_node(core: int) -> int:
    """Dynamically resolve the NUMA node for a given CPU core."""
    sys_node_dir = Path(f"/sys/devices/system/cpu/cpu{core}")
    for path in sys_node_dir.glob("node*"):
        return int(path.name.replace("node", ""))

    # Fallback to the interleaved logic shown in your lscpu output
    return core % 2


def tte_from_filename(crash_file: Path | str) -> float | None:
    """Extract wall-clock TTE from the AFL++ crash filename."""
    name = Path(crash_file).name
    if m := re.search(r"time:(\d+)", name):
        return int(m.group(1)) / 1000.0
    return None


def load_bugs(
    target_filter: list[str] | None, bug_filter: list[str] | None = None
) -> list[dict]:
    """Load every bug's metadata.json, optionally filtered by target
    and/or a list of bug identifiers (case-insensitive)."""
    bugs = []
    for path in sorted((EVAL_DIR / "bugs").rglob("metadata.json")):
        with open(path) as f:
            meta = json.load(f)
        meta["_meta_path"] = str(path)

        if target_filter is not None and meta["target"] not in target_filter:
            continue

        if bug_filter is not None and meta["bug"].lower() not in bug_filter:
            continue

        bugs.append(meta)
    return bugs


def update_metadata(meta_path: Path, label: str):
    """Safely append the successful label to metadata.json."""
    import fcntl

    with meta_path.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)

        current_meta = json.load(f)
        found_by = current_meta.get("poc_found_by_config", [])
        if not isinstance(found_by, list):
            found_by = [found_by] if found_by else []

        if label not in found_by:
            found_by.append(label)

        current_meta["poc_found_by_config"] = found_by

        f.seek(0)
        f.truncate()
        json.dump(
            {k: v for k, v in current_meta.items() if not k.startswith("_")},
            f,
            indent=2,
        )

        fcntl.flock(f, fcntl.LOCK_UN)


@dataclass(frozen=True)
class TrialConfig:
    """Immutable configuration and derived path/command resolution for a single
    survival trial."""

    core: int
    label: str
    meta: dict
    trial_num: int
    scenario: str
    out_dir: Path
    smite_dir: Path  # shared across every label/scenario in this run
    afl_dir: Path
    timeout: int
    seed_dir: Path  # base dir; actual corpus used is seed_dir/<scenario>/<target>

    @property
    def target(self) -> str:
        return self.meta["target"]

    @property
    def resolved_seed_dir(self) -> Path:
        """Per-(scenario, target) seed corpus: <seed_dir>/<scenario>/<target>.

        Scoped by scenario as well as target because a single run can now mix
        scenarios (e.g. encrypted_bytes and ir configs together), and their input
        formats aren't interchangeable.
        """
        return self.seed_dir / self.scenario / self.target

    @property
    def bug(self) -> str:
        return self.meta["bug"]

    @property
    def task_name(self) -> str:
        """Human-readable identifier shown in the dashboard and event log."""
        return f"{self.label}/{self.target}/{self.bug}/trial-{self.trial_num:02d}"

    @property
    def trial_dir(self) -> Path:
        """Per-trial output directory: <out_dir>/<target>/<bug>/<label>/trial-NN/"""
        return (
            self.out_dir
            / self.target
            / self.bug
            / self.label
            / f"trial-{self.trial_num:02d}"
        )

    @property
    def afl_out_dir(self) -> Path:
        return self.trial_dir / "afl-out"

    @property
    def crashes_dir(self) -> Path:
        return self.afl_out_dir / "default" / "crashes"

    @property
    def sharedir(self) -> Path:
        """Nyx snapshot working directory created uniquely for this trial."""
        return self.trial_dir / "sharedir"

    @property
    def image_tag(self) -> str:
        """Docker image tag: smite-eval-<target>-<bug>-<scenario>.

        Unlike the coverage orchestrator, this is NOT label-scoped: the image is
        built once per (target, bug, scenario) at the historically vulnerable
        commit, external to this script. Ablation labels only swap the mutator
        .so, not the target image.
        """
        return f"smite-eval-{self.target}-{self.bug.lower()}-{self.scenario}"

    @property
    def log_path(self) -> Path:
        return self.trial_dir / "afl-fuzz.log"

    @property
    def stats_file(self) -> Path:
        return self.afl_out_dir / "default" / "fuzzer_stats"

    @property
    def ir_mutator_path(self) -> Path:
        return self.smite_dir / "target" / "release" / "libsmite_ir_mutator.so"

    def build_afl_cmd(self) -> list[str]:
        """The exact afl-fuzz invocation for a standalone runner."""
        POWER_SCHEDULE = "explore"
        EXEC_TIMEOUT = "500"  # 0.5 seconds
        node = get_numa_node(self.core)
        return [
            "numactl",
            f"--physcpubind={self.core}",
            f"--membind={node}",
            str(self.afl_dir / "afl-fuzz"),
            "-X",
            "-i",
            str(self.resolved_seed_dir),
            "-o",
            str(self.afl_out_dir),
            "-p",
            POWER_SCHEDULE,
            "-V",
            str(self.timeout),
            "-t",
            EXEC_TIMEOUT,
            "--",
            str(self.sharedir),
        ]

    def build_afl_env(self) -> dict:
        env = os.environ.copy()
        env.update(
            {
                "AFL_NO_AFFINITY": "1",
                "AFL_NO_UI": "1",
                "AFL_NO_COLOR": "1",
                "AFL_FORKSRV_INIT_TMOUT": "1800000",
            }
        )
        testcache = testcache_size_mb()
        if testcache:
            env["AFL_TESTCACHE_SIZE"] = str(testcache)

        # Matches smitebot's ir_mutator_envs(): only for scenarios starting with "ir".
        if self.scenario.startswith("ir"):
            env.update(
                {
                    "AFL_CUSTOM_MUTATOR_LIBRARY": str(self.ir_mutator_path),
                    "AFL_CUSTOM_MUTATOR_ONLY": "1",
                    "AFL_FRAMESHIFT_DISABLE": "1",
                }
            )
        return env


# ────────────────────────────  STATE MANAGEMENT  ────────────────────────────


class CampaignState:
    """Thread-safe state shared by every worker thread and the dashboard renderer."""

    def __init__(self, labels: list[str], cores: list[int]):
        self.lock = threading.Lock()
        self.pid_lock = threading.Lock()
        self.csv_lock = threading.Lock()
        self.shutdown = threading.Event()

        self.start_time = time.time()
        self.active_pids = set()
        self.completed, self.total = 0, 0

        self.sharedir_lock = threading.Lock()

        self.failed_trials = []

        self.events = collections.deque(maxlen=10)
        self.summary = {
            l: {
                "total": 0,
                "found": 0,
                "censored": 0,
                "in_progress": 0,
                "failed": 0,
            }
            for l in labels
        }
        self.workers = {
            c: {
                "task": "Idle",
                "status": "-",
                "color": "dim",
                "is_active": False,
                "execs_sec": 0.0,
                "edges": 0,
                "crash_count": 0,
                "start_time": 0.0,
            }
            for c in cores
        }

    def log(self, task: str, msg: str, color: str = "white"):
        """Append a timestamped event to the dashboard's recent-events panel."""
        with self.lock:
            self.events.append(
                f"[[cyan]{time.strftime('%H:%M:%S')}[/]] {task} → [{color}]{msg}[/]"
            )

    def update_worker(self, core: int, **kwargs):
        """Merge fields into a single core's dashboard row."""
        with self.lock:
            self.workers[core].update(kwargs)

    def update_summary(self, label: str, metric: str, delta: int):
        """Apply a signed delta to one summary counter for a label."""
        with self.lock:
            self.summary[label][metric] += delta

    def finish_trial(self):
        """Increment the campaign-wide completed-trial counter (used for N/total display)."""
        with self.lock:
            self.completed += 1

    def record_failure(self, task_name: str):
        """Keep a running list of failed trials for the dashboard."""
        with self.lock:
            if task_name not in self.failed_trials:
                self.failed_trials.append(task_name)

    def register_pid(self, pid: int):
        with self.pid_lock:
            self.active_pids.add(pid)

    def unregister_pid(self, pid: int):
        with self.pid_lock:
            self.active_pids.discard(pid)

    def append_csv_row(
        self,
        csv_path: Path,
        target: str,
        bug: str,
        label: str,
        trial_num: int,
        tte: float | None,
        censored: bool,
    ):
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self.csv_lock:
            write_header = not csv_path.exists()
            with open(csv_path, "a", newline="") as f:
                w = csv.writer(f)
                if write_header:
                    w.writerow(
                        ["target", "bug", "config", "trial", "tte_seconds", "censored"]
                    )
                w.writerow(
                    [
                        target,
                        bug,
                        label,
                        trial_num,
                        f"{tte:.3f}" if tte is not None else "",
                        censored,
                    ]
                )


# ────────────────────────────  REPRODUCTION  ────────────────────────────


class ReproductionManager:
    """Races background reproduction attempts against every crash a trial finds,
    stopping the trial as soon as one matches the target bug's flag."""

    """Caps simultaneous `docker run` reproduction attempts per trial. Without
    this, every crash file spawns its own unbounded thread + docker invocation
    with hundreds of crashes possible per trial and dozens of trials running
    concurrently, that floods the Docker daemon and host resources, leaving
    later attempts starved for hours instead of draining."""
    MAX_CONCURRENT_REPRO = 1

    def __init__(self, meta: dict, image: str, trial_dir: Path):
        self.meta = meta
        self.image = image
        self.trial_dir = trial_dir
        self.found_event = threading.Event()
        self.matched_crash_name: str | None = None
        self._lock = threading.Lock()
        self._submitted = set()
        self._threads = []
        self._sem = threading.Semaphore(self.MAX_CONCURRENT_REPRO)

    def submit(self, crash_file: Path):
        if crash_file.name in self._submitted or self.found_event.is_set():
            return
        self._submitted.add(crash_file.name)
        t = threading.Thread(target=self._worker, args=(crash_file,), daemon=True)
        self._threads.append(t)
        t.start()

    def _reproduce(self, crash_file: Path, timeout: int = 120) -> tuple[bool, Path]:
        safe_temp_file = self.trial_dir / f"smite_crash_{uuid.uuid4().hex[:8]}.bin"
        shutil.copy(crash_file, safe_temp_file)
        safe_temp_file.chmod(0o644)

        container_name = f"smite-repro-{uuid.uuid4().hex[:12]}"
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-i",
                    "--name",
                    container_name,
                    "-v",
                    f"{safe_temp_file.resolve()}:/input.bin:ro",
                    "-e",
                    "SMITE_INPUT=/input.bin",
                    self.image,
                    f"/{self.meta['target']}-scenario",
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
            )
            is_match = self.meta["flag_identifier"] in (result.stdout + result.stderr)
            return is_match, safe_temp_file
        except subprocess.TimeoutExpired:
            # subprocess's timeout only kills the docker CLI client — with no
            # -t, no signal propagates to the container, so it leaks and runs
            # forever unless explicitly killed by name here.
            subprocess.run(["docker", "kill", container_name], capture_output=True)
            print(
                f"  [repro] timed out, killed container: {crash_file.name}", flush=True
            )
            return False, safe_temp_file
        except Exception as e:
            print(f"  [repro] failed: {crash_file.name}: {e}", flush=True)
            return False, safe_temp_file

    def _worker(self, crash_file: Path):
        with self._sem:
            if self.found_event.is_set():
                return
            is_match, temp_file = self._reproduce(crash_file)

        if is_match:
            with self._lock:
                if not self.found_event.is_set():
                    self.matched_crash_name = crash_file.name
                    self.found_event.set()
                    print(f"  [repro] MATCH: {crash_file.name}", flush=True)
                    if temp_file.is_file():
                        shutil.move(
                            str(temp_file), str(self.trial_dir / "crashing_input")
                        )
                    else:
                        shutil.copy(crash_file, self.trial_dir / "crashing_input")
                        if temp_file.is_dir():
                            shutil.rmtree(temp_file, ignore_errors=True)
                    return

        if temp_file.is_file():
            temp_file.unlink(missing_ok=True)
        elif temp_file.is_dir():
            shutil.rmtree(temp_file, ignore_errors=True)

    @property
    def found(self) -> bool:
        return self.found_event.is_set()

    def wait_all(self, timeout=10):
        for t in self._threads:
            t.join(timeout=timeout)


# ────────────────────────────  UI / DASHBOARD  ────────────────────────────


def print_campaign_summary(
    console: Console,
    bugs: list[dict],
    labels: list[str],
    trials: int,
    cores: list[int],
    state: CampaignState,
    timeout: int,
):
    """Display a structured campaign overview panel before the live dashboard starts."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column(style="white")

    grid.add_row("Bugs", str(len(bugs)))
    grid.add_row("Configurations", str(len(labels)))
    grid.add_row("Trials per bug/config", str(trials))
    grid.add_row("Allocated cores", str(len(cores)))
    grid.add_row("Total trials", str(state.total))

    wall_est = (state.total * timeout) / 3600 / len(cores)
    grid.add_row("Estimated max wall-clock", f"{wall_est:.1f} hours")

    console.print(Panel(grid, title="Campaign Configuration", border_style="green"))
    console.print()


class DashboardRenderer:
    """Stateless renderer that turns a CampaignState snapshot into a Rich TUI layout."""

    @staticmethod
    def _fmt_duration(s: float) -> str:
        m, s = divmod(int(s), 60)
        h, m = divmod(m, 60)
        return f"{h}h {m:02d}m {s:02d}s" if h else (f"{m}m {s:02d}s" if m else f"{s}s")

    @classmethod
    def render(cls, state: CampaignState) -> Group:
        with state.lock:
            w_snap = {w: dict(s) for w, s in state.workers.items()}
            s_snap = {k: dict(v) for k, v in state.summary.items()}
            e_snap = list(state.events)
            f_snap = list(state.failed_trials)
            completed, total = state.completed, state.total

        core_table = Table(
            title=f"Smite Orchestrator ([bold yellow]TTE Mode[/])  [cyan]{completed}[/]/[cyan]{total}[/]"
            f" trials  Elapsed [cyan]{cls._fmt_duration(time.time() - state.start_time)}[/]  ",
            title_style="bold magenta",
            expand=True,
        )
        for col in ["Core", "Task", "Status", "Elapsed", "Exec/s", "Edges", "Crashes"]:
            core_table.add_column(
                col,
                justify="right" if col not in ("Task", "Status") else "left",
                style="bold cyan" if col == "Core" else None,
            )

        now = time.time()
        for c, s in sorted(w_snap.items()):
            start = s.get("start_time", 0)
            elap = (
                f"{now - start:.0f}s"
                if (start and s["task"] != "Idle" and s["is_active"])
                else "—"
            )
            core_table.add_row(
                f"Core {c}",
                s["task"],
                f"[{s['color']}]{s['status']}[/]",
                elap,
                f"{s['execs_sec']:.0f}" if s["execs_sec"] else "—",
                f"{s['edges']}" if s["edges"] else "—",
                f"{s['crash_count']}" if s["crash_count"] else "—",
            )

        summary_table = Table(
            title="Overall Progress", title_style="bold green", expand=True
        )
        for col, style in [
            ("Config", None),
            ("Total", None),
            ("Found", "bold green"),
            ("Censored", "red"),
            ("In-Progress", "cyan"),
            ("Failed", "bold red"),
        ]:
            summary_table.add_column(
                col, justify="right" if col != "Config" else "left", style=style
            )

        for label, v in s_snap.items():
            summary_table.add_row(
                label,
                str(v["total"]),
                str(v["found"]),
                str(v["censored"]),
                str(v["in_progress"]),
                str(v["failed"]),
            )

        # Padding creates a 1-character visual gap between the two panels
        bottom_grid = Table.grid(expand=True, padding=(0, 1))
        bottom_grid.add_column(ratio=3)
        bottom_grid.add_column(ratio=2)
        bottom_grid.add_row(
            Panel(
                "\n".join(e_snap) if e_snap else "[dim]No events yet...[/]",
                title="Recent Events",
                border_style="blue",
            ),
            Panel(
                "\n".join(f_snap) if f_snap else "[dim]All trials healthy[/]",
                title="Failed Trials",
                border_style="red",
            ),
        )
        return Group(core_table, summary_table, bottom_grid)


# ────────────────────────────  ENVIRONMENT  ────────────────────────────


class EnvironmentManager:
    """One-time synchronous setup run before any trial threads start: binary checks,
    a `smitebot doctor` preflight, and (for IR scenarios) confirming the mutator .so
    under the shared --smite-dir has already been compiled — this script does not
    build it, since ablations are expected to be recompiled by hand between runs."""

    @staticmethod
    def validate(afl_dir: Path, smite_dir: Path, console: Console):
        if not shutil.which("smitebot"):
            sys.exit(
                "ERROR: 'smitebot' not found in PATH. Install via `cargo install --path smitebot`."
            )

        console.print("[bold cyan]Running smitebot doctor...[/]")
        res = subprocess.run(
            [
                "smitebot",
                "doctor",
                "--aflpp-path",
                str(afl_dir),
                "--smite-dir",
                str(smite_dir),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        try:
            data = json.loads(res.stdout)
            if not data.get("overall"):
                for c in data.get("checks", []):
                    if not c.get("passed"):
                        console.print(f"[red] - {c.get('name')}: {c.get('reason')}[/]")
                sys.exit(1)
            console.print("[bold green]smitebot doctor checks passed![/]\n")
        except Exception:
            sys.exit(
                f"[bold red]Doctor failed to parse output.[/]\n{res.stdout}\n{res.stderr}"
            )

    @staticmethod
    def validate_paths(
        afl_dir: Path, smite_dir: Path, scenarios: set[str], console: Console
    ):
        """Fail fast on missing binaries or an uncompiled ablation mutator, instead
        of discovering it mid-campaign."""
        missing = {}
        afl_fuzz = afl_dir / "afl-fuzz"
        if not afl_fuzz.exists():
            missing["afl-fuzz binary"] = afl_fuzz

        if any(s.startswith("ir") for s in scenarios):
            mutator = smite_dir / "target" / "release" / "libsmite_ir_mutator.so"
            if not mutator.exists():
                missing["libsmite_ir_mutator.so"] = mutator

        if missing:
            console.print("[bold red]Missing required file(s):[/]")
            for name, p in missing.items():
                console.print(f"  - {name}: {p}")
            sys.exit(1)


# ────────────────────────────  TRIAL RUNNER  ────────────────────────────


class TrialRunner:
    """Owns the full lifecycle of a single survival trial: filesystem/sharedir prep,
    direct afl-fuzz process spawn, boot detection, live telemetry + reproduction
    polling, and teardown. Each trial is attempted exactly once — a boot failure or
    mid-campaign crash marks the trial FAILED rather than being retried."""

    COMPLETION_GRACE_PERIOD_SEC = 120
    STARTUP_POLL_INTERVAL = 5
    BOOT_TIMEOUT_SEC = 3600
    METRICS_POLL_INTERVAL = 2

    def __init__(self, config: TrialConfig, state: CampaignState, csv_path: Path):
        self.cfg = config
        self.state = state
        self.csv_path = csv_path

        self.process = None
        self.fuzzer_pid = None
        self.start_time = 0.0
        self._started = False
        self.aborted = False
        self.repro: ReproductionManager | None = None

    def run(self):
        try:
            self.prepare_fs()
            if self.spawn() and self.wait_for_boot():
                self.monitor()
        except Exception as e:
            self._abort(f"RUNTIME EXCEPTION: {e}")
        finally:
            self.cleanup()

    def prepare_fs(self):
        shutil.rmtree(self.cfg.trial_dir, ignore_errors=True)
        self.cfg.afl_out_dir.mkdir(parents=True)
        self.ensure_sharedir()
        self.repro = ReproductionManager(
            self.cfg.meta, self.cfg.image_tag, self.cfg.trial_dir
        )

    def ensure_sharedir(self):
        self.state.update_worker(
            self.cfg.core, status="Setting up Nyx sharedir...", color="cyan"
        )
        script = self.cfg.smite_dir / "scripts" / "setup-nyx.sh"
        with self.state.sharedir_lock:
            result = subprocess.run(
                [
                    str(script),
                    str(self.cfg.sharedir),
                    self.cfg.image_tag,
                    str(self.cfg.afl_dir),
                ],
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            raise RuntimeError(
                f"setup-nyx.sh failed (code {result.returncode}): "
                f"{(result.stderr or result.stdout).strip()[:300]}"
            )

    def spawn(self) -> bool:
        self.start_time = time.time()
        self.state.update_worker(
            self.cfg.core,
            task=self.cfg.task_name,
            status="Spawning AFL++...",
            color="yellow",
            start_time=self.start_time,
            is_active=True,
            execs_sec=0.0,
            edges=0,
            crash_count=0,
        )

        self.state.update_summary(self.cfg.label, "in_progress", 1)
        self._started = True

        cmd = self.cfg.build_afl_cmd()
        env = self.cfg.build_afl_env()

        self.log_file = open(self.cfg.log_path, "w")
        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # makes pid == pgid, so killpg() works in cleanup
        )
        self.fuzzer_pid = self.process.pid
        return True

    def wait_for_boot(self) -> bool:
        self.state.update_worker(self.cfg.core, status="Booting VM...", color="cyan")

        for _ in range(self.BOOT_TIMEOUT_SEC // self.STARTUP_POLL_INTERVAL):
            if self.state.shutdown.is_set():
                return False

            ret = self.process.poll()
            if ret is not None:
                self._abort(
                    f"AFL++ EXITED DURING BOOT (code {ret}) — see {self.cfg.log_path.name}"
                )
                return False

            if self._log_has_abort():
                self._abort(f"AFL++ PROGRAM ABORT — see {self.cfg.log_path.name}")
                return False

            if self.cfg.stats_file.exists():
                return True

            time.sleep(self.STARTUP_POLL_INTERVAL)

        self._abort("BOOT TIMEOUT (Check log)")
        return False

    def _log_has_abort(self) -> bool:
        try:
            return "PROGRAM ABORT" in self.cfg.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return False

    def _read_stats(self) -> dict:
        return {
            k.strip(): v.strip()
            for k, v in (
                l.split(":", 1)
                for l in self.cfg.stats_file.read_text().splitlines()
                if ":" in l
            )
        }

    def _count_crashes(self) -> int:
        if not self.cfg.crashes_dir.exists():
            return 0
        try:
            return sum(
                1
                for f in self.cfg.crashes_dir.iterdir()
                if f.name != "README.txt"
                and not f.is_dir()
                and not f.name.endswith(".log")
            )
        except FileNotFoundError:
            return 0

    def monitor(self):
        """Poll fuzzer_stats + crashes/ every 2s, submit new crashes for background
        reproduction, and stop the trial the moment one matches (or the AFL run
        naturally ends)."""
        self.state.register_pid(self.fuzzer_pid)
        self.state.update_worker(self.cfg.core, status="Fuzzing...", color="bold green")

        last_edges = 0
        submitted_reproducing = False
        while self.process.poll() is None and not self.state.shutdown.is_set():
            try:
                stats = self._read_stats()
                execs = float(stats.get("execs_per_sec", 0.0))
                edges = int(stats.get("edges_found", 0))
                last_edges = max(edges, last_edges)
            except (FileNotFoundError, ValueError, KeyError):
                execs = 0.0

            if self.cfg.crashes_dir.exists():
                for f in self.cfg.crashes_dir.iterdir():
                    if (
                        f.name not in ("README.txt",)
                        and not f.is_dir()
                        and not f.name.endswith(".log")
                    ):
                        self.repro.submit(f)
                        submitted_reproducing = True

            self.state.update_worker(
                self.cfg.core,
                execs_sec=execs,
                edges=last_edges,
                crash_count=self._count_crashes(),
                status=("Reproducing..." if submitted_reproducing else "Fuzzing..."),
            )

            if self.repro.found:
                self.state.update_worker(
                    self.cfg.core, status="Match found!", color="bold green"
                )
                self.process.terminate()
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
                return

            time.sleep(self.METRICS_POLL_INTERVAL)

        # afl-fuzz exited on its own (natural -V timeout, or a mid-trial crash).
        ret = self.process.poll()
        self.repro.wait_all(timeout=10)
        if (
            not self.repro.found
            and ret is not None
            and ret != 0
            and not self.state.shutdown.is_set()
        ):
            self._abort(
                f"AFL++ CRASHED MID-TRIAL (code {ret}) — see {self.cfg.log_path.name}"
            )

    def cleanup(self):
        if self.fuzzer_pid:
            self.state.unregister_pid(self.fuzzer_pid)
            try:
                os.killpg(self.fuzzer_pid, signal.SIGKILL)
            except OSError:
                pass

        if self.process and self.process.poll() is None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if hasattr(self, "log_file"):
            self.log_file.close()

        for f in self.cfg.trial_dir.glob("smite_crash_*"):
            try:
                if f.is_file() or f.is_symlink():
                    f.unlink(missing_ok=True)
                elif f.is_dir():
                    shutil.rmtree(f, ignore_errors=True)
            except Exception:
                pass

        shutil.rmtree(self.cfg.afl_out_dir / "workdir", ignore_errors=True)
        shutil.rmtree(self.cfg.sharedir, ignore_errors=True)

        if self._started:
            self.state.update_summary(self.cfg.label, "in_progress", -1)
            self._started = False

        self.state.update_worker(
            self.cfg.core,
            status="Done",
            color="dim",
            is_active=False,
            execs_sec=0.0,
            edges=0,
            crash_count=0,
        )

        if self.aborted:
            self.state.finish_trial()
            return

        found = bool(self.repro and self.repro.found)
        tte = None
        if found:
            tte = tte_from_filename(self.repro.matched_crash_name)
            if tte is None:
                tte = time.time() - self.start_time
            (self.cfg.trial_dir / "tte.txt").write_text(f"{tte:.3f}\n")
            update_metadata(Path(self.cfg.meta["_meta_path"]), self.cfg.label)
            self.state.update_summary(self.cfg.label, "found", 1)
            self.state.log(self.cfg.task_name, f"FOUND ({tte:.1f}s)", "bold green")
        else:
            (self.cfg.trial_dir / "tte.txt").write_text("CENSORED\n")
            self.state.update_summary(self.cfg.label, "censored", 1)
            self.state.log(self.cfg.task_name, "CENSORED", "red")

        self.state.append_csv_row(
            self.csv_path,
            self.cfg.target,
            self.cfg.bug,
            self.cfg.label,
            self.cfg.trial_num,
            tte,
            not found,
        )
        self.state.finish_trial()

    def _abort(self, msg: str):
        self.aborted = True
        self.state.update_worker(
            self.cfg.core, status="Failed", color="bold red", is_active=False
        )

        if self._started:
            self.state.update_summary(self.cfg.label, "in_progress", -1)
            self._started = False

        self.state.record_failure(self.cfg.task_name)
        self.state.update_summary(self.cfg.label, "failed", 1)
        self.state.log(self.cfg.task_name, msg, "bold red")

        self.state.append_csv_row(
            self.csv_path,
            self.cfg.target,
            self.cfg.bug,
            self.cfg.label,
            self.cfg.trial_num,
            None,
            True,
        )


# ────────────────────────────  ENTRY POINT  ────────────────────────────


def worker_thread(
    core: int,
    work: Queue,
    args,
    state: CampaignState,
    label_scenarios: dict,
    csv_path: Path,
):
    """Per-core worker loop: pull trials off the shared queue until it's empty or
    shutdown is requested, running each one to completion via TrialRunner.run()."""
    while not state.shutdown.is_set():
        try:
            label, meta, trial_num = work.get_nowait()
        except Empty:
            state.update_worker(
                core,
                task="Idle",
                status="-",
                color="dim",
                is_active=False,
                execs_sec=0.0,
                edges=0,
                crash_count=0,
            )
            return

        config = TrialConfig(
            core=core,
            label=label,
            meta=meta,
            trial_num=trial_num,
            scenario=label_scenarios[label],
            out_dir=args.out_dir,
            smite_dir=args.smite_dir,
            afl_dir=args.afl_dir,
            timeout=args.timeout,
            seed_dir=args.seed_dir,
        )

        runner = TrialRunner(config, state, csv_path)
        runner.run()
        work.task_done()


def ensure_seed_dir(args, scenarios: list[str], targets: list[str], console: Console):
    """Resolve args.seed_dir to a real directory with a non-empty subdirectory per
    (scenario, target) pair, creating a minimal one-byte corpus for any missing
    combination if the user didn't pass --seed-dir. Scoped by scenario as well as
    target since a single run can mix scenarios (e.g. encrypted_bytes and ir)."""
    if args.seed_dir:
        if not args.seed_dir.is_dir():
            sys.exit(f"ERROR: Seed directory '{args.seed_dir}' does not exist.")

        for scen in scenarios:
            for tgt in targets:
                combo_seed = args.seed_dir / scen / tgt
                if not combo_seed.is_dir() or not any(combo_seed.iterdir()):
                    sys.exit(
                        f"ERROR: Seed directory for '{scen}/{tgt}' is missing or empty: {combo_seed}"
                    )
        return

    default_seeds = EVAL_DIR / "seeds" / ".default-seeds"
    for scen in scenarios:
        for tgt in targets:
            combo_dir = default_seeds / scen / tgt
            combo_dir.mkdir(parents=True, exist_ok=True)
            if not any(combo_dir.iterdir()):
                (combo_dir / "seed0").write_bytes(b"\x00")

    args.seed_dir = default_seeds
    console.print(
        f"[dim]No --seed-dir given; using minimal generated corpus at {default_seeds}/<scenario>/<target>[/]"
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Smite Survival (TTE) Campaign Orchestrator"
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--configs", required=True, help="'label:scenario,label:scenario'")
    p.add_argument(
        "--smite-dir", required=True, type=Path, help="Shared across all configs"
    )
    p.add_argument("--targets", help="e.g. cln,lnd (default: all targets with bugs)")
    p.add_argument("--cores", required=True, help="e.g. 0,1,2,3")
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--trials", type=int, default=20)
    p.add_argument(
        "--trial-ids",
        help="Comma-separated trial numbers to run, e.g. '1,5,15'. Overrides --trials.",
    )
    p.add_argument("--timeout", type=int, default=86_400)
    p.add_argument(
        "--seed-dir",
        type=Path,
        help="Directory containing one seed-corpus subdirectory per scenario/target, e.g. <seed-dir>/ir/cln/",
    )
    p.add_argument(
        "--bugs",
        type=str,
        default=None,
        help="Filter by a comma-separated list of bug identifiers (case-insensitive), e.g., send_tlvs,badonion",
    )

    args = p.parse_args()

    args.out_dir = args.out_dir.resolve()
    args.smite_dir = args.smite_dir.expanduser().resolve()
    args.afl_dir = args.afl_dir.resolve()
    if args.seed_dir:
        args.seed_dir = args.seed_dir.resolve()

    return args


def main():
    args = parse_args()
    console = Console()

    target_filter = (
        [t.strip() for t in args.targets.split(",")] if args.targets else None
    )

    bug_filter = (
        [b.strip().lower() for b in args.bugs.split(",")] if args.bugs else None
    )

    bugs = load_bugs(target_filter, args.bugs)
    if not bugs:
        if args.bugs:
            sys.exit(f"ERROR: No bugs found matching --bugs '{args.bugs}'.")

    labels, label_scenarios = [], {}
    try:
        for item in args.configs.split(","):
            l, s = item.split(":")
            l = l.strip()
            labels.append(l)
            label_scenarios[l] = s.strip()
    except ValueError:
        sys.exit("ERROR: --configs must use 'label:scenario' format")
    scenarios = sorted(set(label_scenarios.values()))

    # Seeds are provisioned per (scenario, target) actually needed by this run —
    # target set comes from the loaded bugs, not just the (possibly broader)
    # --targets filter.
    targets = sorted({meta["target"] for meta in bugs})
    ensure_seed_dir(args, scenarios, targets, console)

    EnvironmentManager.validate(args.afl_dir, args.smite_dir, console)
    EnvironmentManager.validate_paths(
        args.afl_dir, args.smite_dir, set(scenarios), console
    )

    cores = [int(c) for c in args.cores.split(",")]

    state = CampaignState(labels, cores)
    csv_path = args.out_dir / "trials.csv"

    def _handle_sigint(sig, frame):
        if state.shutdown.is_set():
            console.print("\n[bold red]Force-quitting immediately![/]")
            os._exit(1)
        state.shutdown.set()
        console.print(
            "\n[bold yellow]Interrupt received — gracefully killing fuzzers... (Press Ctrl+C again to force quit)[/]"
        )
        with state.pid_lock:
            for pid in state.active_pids:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass

    signal.signal(signal.SIGINT, _handle_sigint)

    if args.trial_ids:
        try:
            trial_range = [int(x.strip()) for x in args.trial_ids.split(",")]
        except ValueError:
            sys.exit("ERROR: --trial-ids must be a comma-separated list of integers.")
        display_trials = len(trial_range)
    else:
        trial_range = list(range(1, args.trials + 1))
        display_trials = args.trials

    # Enqueue every (label, bug, trial_num) combination up front; workers pull
    # from this shared queue rather than being statically assigned ranges.
    work = Queue()
    for label in labels:
        for meta in bugs:
            for i in trial_range:
                work.put((label, meta, i))
                state.summary[label]["total"] += 1
    state.total = sum(s["total"] for s in state.summary.values())

    print_campaign_summary(
        console=console,
        bugs=bugs,
        labels=labels,
        trials=display_trials,
        cores=cores,
        state=state,
        timeout=args.timeout,
    )

    threads = [
        threading.Thread(
            target=worker_thread,
            args=(c, work, args, state, label_scenarios, csv_path),
            daemon=True,
        )
        for c in cores
    ]

    with Live(
        DashboardRenderer.render(state), refresh_per_second=4, console=console
    ) as live:
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            live.update(DashboardRenderer.render(state))
            time.sleep(0.25)
        for t in threads:
            t.join()

        live.update(DashboardRenderer.render(state))

    if state.shutdown.is_set():
        console.print("[bold yellow]Stopped early due to interrupt.[/]")
    else:
        console.print("[bold green]=== All trials complete ===[/]")


if __name__ == "__main__":
    main()
