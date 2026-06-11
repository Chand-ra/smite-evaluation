#!/usr/bin/env python3
"""
scheduler.py — Run all trials in parallel across available cores.

Usage:
    python scheduler.py \
        --cores 0,1,...,23 \
        --configs raw-bytes,ir-full-stack \
        --smite-dir ~/smite \
        --afl-dir ~/AFLplusplus \
        [--trials 20] \
        [--targets cln,lnd,ldk,eclair]

Ablation workflow:
    Compile the appropriate mutator variant, place it at
    target/release/libsmite_ir_mutator.so, then run:
        python scheduler.py --configs ir-component-a ...
    Repeat for each ablation configuration.
"""

import argparse
import csv
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue

EVAL_DIR  = Path(__file__).parent.parent
RUN_TRIAL = Path(__file__).parent / "run_trial.py"


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--cores",     required=True)
    p.add_argument("--configs",   required=True)
    p.add_argument("--smite-dir", required=True, type=Path)
    p.add_argument("--afl-dir",   required=True, type=Path)
    p.add_argument("--trials",    type=int, default=20)
    p.add_argument("--targets",   default=None)
    return p.parse_args()


def load_bugs(target_filter=None) -> list[dict]:
    bugs = []
    for path in sorted((EVAL_DIR / "vulnerabilities").rglob("metadata.json")):
        with open(path) as f:
            meta = json.load(f)
        meta["_meta_path"] = str(path)
        if target_filter is None or meta["target"] in target_filter:
            bugs.append(meta)
    return bugs


def ensure_sharedir(meta: dict, config: str,
                    smite_dir: Path, afl_dir: Path) -> Path:
    """
    Generate the Nyx share directory for a (bug, config) pair if absent.
    Reused across all trials: AFL++ Nyx mode never writes back to the share
    directory — QEMU boots from it read-only and snapshots in memory.
    """
    target   = meta["target"]
    cve      = meta["cve"].lower()
    image    = f"smite-eval-{target}-{cve}-{config}"
    sharedir = Path.home() / f"smite-nyx-eval-{target}-{cve}-{config}"

    if sharedir.exists():
        print(f"[nyx]   exists: {sharedir.name}", flush=True)
        return sharedir

    print(f"[nyx]   generating {sharedir.name} ...", flush=True)
    subprocess.run(
        ["./scripts/setup-nyx.sh", str(sharedir), image, str(afl_dir)],
        cwd=smite_dir,
        check=True,
    )
    return sharedir


CSV_LOCK = threading.Lock()


def append_csv_row(target, cve, config, trial_num, tte, censored):
    csv_path = EVAL_DIR / "results" / "trials.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with CSV_LOCK:
        write_header = not csv_path.exists()
        with open(csv_path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["target", "cve", "config", "trial",
                             "tte_seconds", "censored"])
            w.writerow([target, cve, config, trial_num,
                        f"{tte:.3f}" if tte is not None else "",
                        censored])


def worker(core: int, work: Queue, smite_dir: Path,
           afl_dir: Path, sharedirs: dict, trials: int):
    while True:
        try:
            meta, config, trial_num = work.get_nowait()
        except Empty:
            return

        key      = (meta["target"], meta["cve"], config)
        sharedir = sharedirs[key]

        subprocess.run([
            sys.executable, str(RUN_TRIAL),
            "--meta",      meta["_meta_path"],
            "--config",    config,
            "--trial",     str(trial_num),
            "--core",      str(core),
            "--smite-dir", str(smite_dir),
            "--afl-dir",   str(afl_dir),
            "--sharedir",  str(sharedir),
        ])

        target = meta["target"]
        cve    = meta["cve"]
        tte_file = (EVAL_DIR / "results" / target / cve / config
                    / f"trial-{trial_num:02d}" / "tte.txt")
        tte      = None
        censored = True
        if tte_file.exists():
            content = tte_file.read_text().strip()
            if content != "CENSORED":
                try:
                    tte      = float(content)
                    censored = False
                except ValueError:
                    pass

        append_csv_row(target, cve, config, trial_num, tte, censored)
        work.task_done()


def main():
    args    = parse_args()
    cores   = [int(c) for c in args.cores.split(",")]
    configs = [c.strip() for c in args.configs.split(",")]
    targets = ([t.strip() for t in args.targets.split(",")]
               if args.targets else None)

    bugs = load_bugs(targets)
    if not bugs:
        print("No bugs found under vulnerabilities/.", flush=True)
        sys.exit(1)

    total    = len(bugs) * len(configs) * args.trials
    wall_est = total * 24 / len(cores)
    print(f"Bugs={len(bugs)}  Configs={len(configs)}  "
          f"Trials={args.trials}  Cores={len(cores)}", flush=True)
    print(f"Total trials: {total}  "
          f"Estimated wall-clock: {wall_est:.0f} hours", flush=True)

    print("\n=== Generating Nyx share directories ===", flush=True)
    sharedirs = {}
    for meta in bugs:
        for config in configs:
            key = (meta["target"], meta["cve"], config)
            sharedirs[key] = ensure_sharedir(
                meta, config, args.smite_dir, args.afl_dir
            )

    print("\n=== Running trials ===", flush=True)
    work: Queue = Queue()
    for meta in bugs:
        for config in configs:
            for trial_num in range(1, args.trials + 1):
                work.put((meta, config, trial_num))

    threads = [
        threading.Thread(
            target=worker,
            args=(core, work, args.smite_dir, args.afl_dir,
                  sharedirs, args.trials),
            daemon=True,
        )
        for core in cores
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("\n=== All trials complete ===", flush=True)


if __name__ == "__main__":
    main()