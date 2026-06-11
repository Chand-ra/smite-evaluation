#!/usr/bin/env python3
"""
run_trial.py — Execute one fuzzing trial. Called by scheduler.py.

For raw-bytes: standard AFL++ mutations only.
For IR configs: AFL_CUSTOM_MUTATOR_ONLY=1. The correct mutator variant
must be compiled and present at target/release/libsmite_ir_mutator.so
before invoking the scheduler.

Usage (called by scheduler.py, not directly):
    python run_trial.py \
        --meta vulnerabilities/cln/CVE-2023-0001/metadata.json \
        --config raw-bytes \
        --trial 1 \
        --core 0 \
        --smite-dir /home/user/smite \
        --afl-dir /home/user/AFLplusplus
        --sharedir /home/smite-nyx-eval-cln-cve-2023-0001-raw-bytes
"""

import argparse
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TIMEOUT       = 86_400   # 24 hours
POLL_INTERVAL = 3        # seconds between polls

EVAL_DIR = Path(__file__).parent.parent


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--meta",      required=True, type=Path)
    p.add_argument("--config",    required=True)
    p.add_argument("--trial",     required=True, type=int)
    p.add_argument("--core",      required=True, type=int)
    p.add_argument("--smite-dir", required=True, type=Path)
    p.add_argument("--afl-dir",   required=True, type=Path)
    p.add_argument("--sharedir",  required=True, type=Path)
    return p.parse_args()


def load_meta(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


# ── TTE extraction ─────────────────────────────────────────────────────────────

def tte_from_filename(crash_file: Path | str) -> float | None:
    """
    Extract wall-clock TTE from the AFL++ crash filename.

    AFL++ encodes time elapsed since campaign start in the filename as
    time:<milliseconds>. Convert to seconds. Example:
        id:000000,sig:00,src:000015,time:302878,execs:70866,...
        → 302.878 seconds
    """
    if isinstance(crash_file, Path):
        name = crash_file.name
    else:
        # If it's a string, just use the basename
        name = os.path.basename(crash_file)
    m = re.search(r"time:(\d+)", name)
    if m:
        return int(m.group(1)) / 1000.0
    return None


# ── Local reproduction ─────────────────────────────────────────────────────────

def reproduce_crash(crash_file: Path, meta: dict,
                    image: str, trial_dir: Path, timeout: int = 120) -> tuple[bool, Path]:
    # Returns (is_match, path_to_temp_file)
    fd, temp_path = tempfile.mkstemp(prefix="smite_crash_", dir=str(trial_dir))
    os.close(fd)
    
    safe_temp_file = Path(temp_path)
    shutil.copy(crash_file, safe_temp_file)
    os.chmod(safe_temp_file, 0o644)

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "-i",
                "-v", f"{safe_temp_file.resolve()}:/input.bin:ro",
                "-e", "SMITE_INPUT=/input.bin",
                image,
                f"/{meta['target']}-scenario",
            ],
            capture_output=True, text=True, errors="replace", timeout=timeout,
        )
        is_match = meta["flag_identifier"] in (result.stdout + result.stderr)
        return is_match, safe_temp_file

    except Exception as e:
        print(f"  [repro] failed: {crash_file.name}: {e}", flush=True)
        return False, safe_temp_file


# ── Metadata update ────────────────────────────────────────────────────────────

def update_metadata(meta_path: Path, config: str):
    """
    Update metadata.json to record the config that found the crash.
    Uses file locking to safely append to the list across parallel processes.
    """
    with open(meta_path, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        
        current_meta = json.load(f)
        found_by = current_meta.get("poc_found_by_config")
        if not isinstance(found_by, list):
            found_by = [] if found_by is None else [found_by]
            
        # Append the successful config if it isn't already there
        if config not in found_by:
            found_by.append(config)
            
        current_meta["poc_found_by_config"] = found_by
        
        # Write back to the file
        f.seek(0)
        f.truncate()
        # Filter out internal tracking keys (like _meta_path from scheduler)
        meta_to_write = {k: v for k, v in current_meta.items() if not k.startswith("_")}
        json.dump(meta_to_write, f, indent=2)
        
        # Release the lock
        fcntl.flock(f, fcntl.LOCK_UN)
        
    print(f"  [meta]  appended '{config}' to {meta_path.name}", flush=True)


# ── Background reproduction manager ───────────────────────────────────────────

class ReproductionManager:
    def __init__(self, meta: dict, image: str, trial_dir: Path):
        self.meta = meta
        self.image = image
        self.trial_dir = trial_dir
        self.found_event = threading.Event()
        self.matched_crash_name: str | None = None
        self._lock = threading.Lock()
        self._submitted = set()
        self._threads = []

    def submit(self, crash_file: Path):
        if crash_file.name in self._submitted:
            return
        self._submitted.add(crash_file.name)
        t = threading.Thread(target=self._worker, args=(crash_file,), daemon=True)
        self._threads.append(t)
        t.start()

    def _worker(self, crash_file: Path):
        is_match, temp_file = reproduce_crash(crash_file, self.meta, self.image, self.trial_dir)
        
        if is_match:
            with self._lock:
                if not self.found_event.is_set():
                    self.matched_crash_name = crash_file.name
                    self.found_event.set()
                    print(f"  [repro] MATCH: {crash_file.name}", flush=True)
                    # Rescue the file immediately before AFL++ deletes the directory!
                    shutil.move(str(temp_file), str(self.trial_dir / "crashing_input"))
                else:
                    if temp_file.exists(): temp_file.unlink()
        else:
            if temp_file.exists(): temp_file.unlink()

    @property
    def found(self) -> bool:
        return self.found_event.is_set()

    def wait_all(self, timeout=10):
        # Wait for pending Docker verification runs to finish
        for t in self._threads:
            t.join(timeout=timeout)

# ── AFL++ environment ──────────────────────────────────────────────────────────

def make_env(config: str, smite_dir: Path) -> dict:
    """
    raw-bytes: standard AFL++ mutations only.
    ir-*:      AFL_CUSTOM_MUTATOR_ONLY=1 so only the IR mutator runs.
               Standard byte-level mutations corrupt structured IR programs.
    """
    env = os.environ.copy()
    env["AFL_NO_UI"]    = "1"
    env["AFL_NO_COLOR"] = "1"
    env["AFL_NO_AFFINITY"] = "1"

    if config != "raw-bytes":
        mutator = smite_dir / "target" / "release" / "libsmite_ir_mutator.so"
        if not mutator.exists():
            print(f"ERROR: mutator not found: {mutator}", flush=True)
            sys.exit(1)
        env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(mutator)
        env["AFL_CUSTOM_MUTATOR_ONLY"]    = "1"
        env["AFL_FRAMESHIFT_DISABLE"]     = "1"
        env["AFL_DISABLE_TRIM"]           = "1"

    return env


# ── Main ───────────────────────────────────────────────────────────────────────

def run(args):
    meta      = load_meta(args.meta)
    meta_path = args.meta
    target    = meta["target"]
    cve       = meta["cve"]
    config    = args.config
    image     = f"smite-eval-{target}-{cve.lower()}-{config}"

    seed_type = "raw-bytes" if config == "raw-bytes" else "ir"
    seed_dir  = EVAL_DIR / "seeds" / seed_type

    if not seed_dir.exists() or not any(seed_dir.iterdir()):
        print(f"ERROR: seed directory empty: {seed_dir}", flush=True)
        sys.exit(1)

    trial_dir = (EVAL_DIR / "results" / target / cve / config / f"trial-{args.trial:02d}")
    afl_out   = trial_dir / "afl-out"
    afl_log = trial_dir / "afl-fuzz.log"
    
    # Force a clean slate so old crashes don't trigger immediate exits
    if afl_out.exists():
        shutil.rmtree(afl_out, ignore_errors=True)
        
    trial_dir.mkdir(parents=True, exist_ok=True)
    afl_out.mkdir(parents=True, exist_ok=True)

    afl_default = afl_out / "default"
    crashes     = afl_default / "crashes"

    print(f"[start] {target}/{cve}/{config}/trial-{args.trial:02d} core={args.core}", flush=True)

    cmd = [
        "taskset", "-c", str(args.core),
        str(args.afl_dir / "afl-fuzz"),
        "-X",
        "-i", str(seed_dir),
        "-o", str(afl_out),
        "-p", "fast",
        "--", str(args.sharedir),
    ]

    process = subprocess.Popen(
        cmd,
        env=make_env(config, args.smite_dir),
        stdout=open(afl_log, "w"),
        stderr=subprocess.STDOUT,   # merge stderr into stdout → single log file
    )

    start = time.time()
    tte   = None
    repro = ReproductionManager(meta, image, trial_dir)

    while True:
        elapsed = time.time() - start

        if elapsed >= TIMEOUT:
            process.terminate()
            process.wait()
            break

        if crashes.exists():
            for f in sorted(crashes.iterdir()):
                if f.name == "README.txt" or f.is_dir() or f.name.endswith(".log"):
                    continue
                repro.submit(f)

        if repro.found:
            tte = tte_from_filename(repro.matched_crash_name)
            if tte is None: tte = elapsed
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            break

        if process.poll() is not None:
            # AFL++ exited early (usually because the bug is so shallow the seed triggered it)
            # Wait up to 10 seconds for Docker to finish verifying the final crashes
            repro.wait_all(timeout=10) 
            if repro.found:
                tte = tte_from_filename(repro.matched_crash_name)
                if tte is None: tte = elapsed
            else:
                print(f"  [warn] afl-fuzz exited early (rc={process.returncode})", flush=True)
            break

        time.sleep(POLL_INTERVAL)

    # ── Save results ───────────────────────────────────────────────────────────────
    
    if tte is not None and repro.matched_crash_name is not None:
        # crashing_input is already secured by ReproductionManager; just update metadata
        update_metadata(meta_path, config)
        (trial_dir / "tte.txt").write_text(f"{tte:.3f}\n")
        print(f"[done]  {target}/{cve}/{config}/trial-{args.trial:02d} TTE={tte:.3f}s", flush=True)
    else:
        (trial_dir / "tte.txt").write_text("CENSORED\n")
        print(f"[done]  {target}/{cve}/{config}/trial-{args.trial:02d} CENSORED", flush=True)

    # ── Cleanup ────────────────────────────────────────────────────────────────────
    for f in trial_dir.glob("smite_crash_*"):
        try:
            f.unlink()
        except OSError:
            pass

    # Delete per-trial sharedir after telemetry is saved.
    # Base sharedir is preserved for copying subsequent trials.
    # try:
    #     shutil.rmtree(args.sharedir)
    # except Exception as e:
    #     print(f"  [warn] could not remove sharedir: {e}", flush=True)

    # sys.exit(0 if tte is not None else 1)

if __name__ == "__main__":
    run(parse_args())