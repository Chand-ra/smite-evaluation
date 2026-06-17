#!/usr/bin/env python3
"""
run_trial.py — Execute one fuzzing trial. Called by scheduler.py.

For encrypted_bytes: standard AFL++ mutations only.
For IR configs: AFL_CUSTOM_MUTATOR_ONLY=1. The correct mutator variant
must be compiled and present at target/release/libsmite_ir_mutator.so
before invoking the scheduler.

Usage (called by scheduler.py, not directly):
    python run_trial.py \
        --meta vulnerabilities/cln/CVE-2023-0001/metadata.json \
        --config encrypted_bytes \
        --trial 1 \
        --core 0 \
        --smite-dir /home/user/smite \
        --afl-dir /home/user/AFLplusplus
        --sharedir /home/smite-nyx-eval-cln-cve-2023-0001-encrypted_bytes
"""

import argparse
import fcntl
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

TIMEOUT = 86_400
POLL_INTERVAL = 3
MAX_STARTUP_RETRIES = 6
STARTUP_RETRY_DELAY_BASE = 30
BOOT_LOCK_PATH = Path("/tmp/smite-nyx-boot.lock")

EVAL_DIR = Path(__file__).parent.parent


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--meta", required=True, type=Path)
    p.add_argument("--config", required=True)
    p.add_argument("--trial", required=True, type=int)
    p.add_argument("--core", required=True, type=int)
    p.add_argument("--smite-dir", required=True, type=Path)
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--sharedir", required=True, type=Path)
    return p.parse_args()


def load_meta(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def config_to_scenario(config: str) -> str:
    """
    Map an evaluation config label to the Smite scenario name.

    Evaluation config labels are internal identifiers for this evaluation.
    Smite scenario names are what the Dockerfiles and scenario binaries
    actually use. All IR evaluation configs (ir-full-stack, ir-component-a,
    ir-component-b) use the same 'ir' scenario image and sharedir; only the
    mutator .so differs between them.
    """
    return "encrypted_bytes" if config == "encrypted_bytes" else "ir"


# ── TTE extraction ─────────────────────────────────────────────────────────────


def tte_from_filename(crash_file: Path | str) -> float | None:
    """Extract wall-clock TTE from the AFL++ crash filename."""
    name = Path(crash_file).name
    if m := re.search(r"time:(\d+)", name):
        return int(m.group(1)) / 1000.0
    return None


# ── Local reproduction ─────────────────────────────────────────────────────────


def reproduce_crash(
    crash_file: Path, meta: dict, image: str, trial_dir: Path, timeout: int = 120
) -> tuple[bool, Path]:
    # Use UUID to avoid OS file descriptor management overhead from tempfile.mkstemp
    safe_temp_file = trial_dir / f"smite_crash_{uuid.uuid4().hex[:8]}.bin"
    shutil.copy(crash_file, safe_temp_file)
    safe_temp_file.chmod(0o644)

    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "-v",
                f"{safe_temp_file.resolve()}:/input.bin:ro",
                "-e",
                "SMITE_INPUT=/input.bin",
                image,
                f"/{meta['target']}-scenario",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        is_match = meta["flag_identifier"] in (result.stdout + result.stderr)
        return is_match, safe_temp_file

    except Exception as e:
        print(f"  [repro] failed: {crash_file.name}: {e}", flush=True)
        return False, safe_temp_file


# ── Metadata update ────────────────────────────────────────────────────────────


def update_metadata(meta_path: Path, config: str):
    """Safely append the successful config to metadata.json."""
    with meta_path.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)

        current_meta = json.load(f)
        found_by = current_meta.get("poc_found_by_config", [])
        if not isinstance(found_by, list):
            found_by = [found_by] if found_by else []

        if config not in found_by:
            found_by.append(config)

        current_meta["poc_found_by_config"] = found_by

        f.seek(0)
        f.truncate()
        json.dump(
            {k: v for k, v in current_meta.items() if not k.startswith("_")},
            f,
            indent=2,
        )

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
        is_match, temp_file = reproduce_crash(
            crash_file, self.meta, self.image, self.trial_dir
        )

        if is_match:
            with self._lock:
                if not self.found_event.is_set():
                    self.matched_crash_name = crash_file.name
                    self.found_event.set()
                    print(f"  [repro] MATCH: {crash_file.name}", flush=True)

                    # If it is a file, move it safely.
                    if temp_file.is_file():
                        shutil.move(
                            str(temp_file), str(self.trial_dir / "crashing_input")
                        )
                    else:
                        # If Docker turned it into a directory, copy the original and delete the dir
                        shutil.copy(crash_file, self.trial_dir / "crashing_input")
                        if temp_file.is_dir():
                            shutil.rmtree(temp_file, ignore_errors=True)
                else:
                    if temp_file.is_file():
                        temp_file.unlink(missing_ok=True)
                    elif temp_file.is_dir():
                        shutil.rmtree(temp_file, ignore_errors=True)
        else:
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


# ── AFL++ environment ──────────────────────────────────────────────────────────


def make_env(config: str, smite_dir: Path) -> dict:
    import os

    env = os.environ.copy()
    env.update(
        {
            "AFL_NO_UI": "1",
            "AFL_NO_COLOR": "1",
            "AFL_NO_AFFINITY": "1",
            "AFL_FORKSRV_INIT_TMOUT": "300000",
        }
    )

    if config != "encrypted_bytes":
        mutator = smite_dir / "target" / "release" / "libsmite_ir_mutator.so"
        if not mutator.exists():
            print(f"ERROR: mutator not found: {mutator}", flush=True)
            sys.exit(1)
        env.update(
            {
                "AFL_CUSTOM_MUTATOR_LIBRARY": str(mutator),
                "AFL_CUSTOM_MUTATOR_ONLY": "1",
                "AFL_FRAMESHIFT_DISABLE": "1",
                "AFL_DISABLE_TRIM": "1",
            }
        )

    return env


def wait_for_afl_ready(
    process: subprocess.Popen, log_path: Path, timeout: int = 300
) -> bool:
    deadline = time.time() + timeout

    # Wait for the file to be created before tailing it
    while not log_path.exists():
        if process.poll() is not None or time.time() > deadline:
            return False
        time.sleep(0.5)

    with log_path.open("r", errors="replace") as f:
        while time.time() < deadline:
            if process.poll() is not None:
                return False

            # Read only new lines instead of entire file
            chunk = f.read()
            if "All set and ready to roll" in chunk:
                return True
            if "PROGRAM ABORT" in chunk:
                return False

            time.sleep(1)
    return False


# ── Execution Core ─────────────────────────────────────────────────────────────


def execute_single_attempt(
    cmd: list,
    env: dict,
    attempt_log: Path,
    crashes_dir: Path,
    repro: ReproductionManager | None,
) -> tuple[float | None, bool, bool]:
    """Handles the boot lock, subprocess execution, and the monitoring loop for a single attempt."""
    with BOOT_LOCK_PATH.open("w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        log_fh = attempt_log.open("w")
        process = subprocess.Popen(
            cmd, env=env, stdout=log_fh, stderr=subprocess.STDOUT
        )
        ready = wait_for_afl_ready(process, attempt_log)
        fcntl.flock(lock_file, fcntl.LOCK_UN)

    if not ready:
        process.terminate()
        process.wait()
        log_fh.close()
        return None, False, True

    print(f"[running] AFL++ active", flush=True)

    start = time.time()
    tte = None
    timed_out = False

    while True:
        elapsed = time.time() - start

        if elapsed >= TIMEOUT:
            timed_out = True
            process.terminate()
            process.wait()
            break

        if repro is not None:
            if crashes_dir.exists():
                for f in crashes_dir.iterdir():
                    if (
                        f.name not in ("README.txt",)
                        and not f.is_dir()
                        and not f.name.endswith(".log")
                    ):
                        repro.submit(f)

            if repro.found:
                tte = tte_from_filename(repro.matched_crash_name) or elapsed
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                break

        if process.poll() is not None:
            if repro is not None:
                repro.wait_all(timeout=10)
                if repro.found:
                    tte = tte_from_filename(repro.matched_crash_name) or elapsed
                else:
                    print(
                        f"  [warn] afl-fuzz exited early (rc={process.returncode})",
                        flush=True,
                    )
            else:
                print(
                    f"  [warn] afl-fuzz exited early (rc={process.returncode})",
                    flush=True,
                )
            break

        time.sleep(POLL_INTERVAL)

    return tte, timed_out, False


# ── Main ───────────────────────────────────────────────────────────────────────


def run(args):
    meta = load_meta(args.meta)
    target = meta["target"]
    cve = meta["cve"]
    config = args.config
    image = f"smite-eval-{target}-{cve.lower()}-{config}"

    seed_dir = EVAL_DIR / "seeds" / config_to_scenario(config)
    if not seed_dir.exists() or not any(seed_dir.iterdir()):
        print(f"ERROR: seed directory empty: {seed_dir}", flush=True)
        sys.exit(1)

    trial_dir = EVAL_DIR / "results" / target / cve / config / f"trial-{args.trial:02d}"
    afl_out = trial_dir / "afl-out"
    crashes = afl_out / "default" / "crashes"

    if afl_out.exists():
        shutil.rmtree(afl_out, ignore_errors=True)
    trial_dir.mkdir(parents=True, exist_ok=True)
    afl_out.mkdir(parents=True, exist_ok=True)

    print(
        f"[start] {target}/{cve}/{config}/trial-{args.trial:02d} core={args.core}",
        flush=True,
    )

    cmd = [
        "taskset",
        "-c",
        str(args.core),
        str(args.afl_dir / "afl-fuzz"),
        "-X",
        "-i",
        str(seed_dir),
        "-o",
        str(afl_out),
        "-p",
        "fast",
        "--",
        str(args.sharedir),
    ]
    env = make_env(config, args.smite_dir)

    tte = None
    timed_out = False

    repro = None
    if meta["cve"] != "coverage":
        repro = ReproductionManager(meta, image, trial_dir)

    for attempt in range(1, MAX_STARTUP_RETRIES + 1):
        if afl_out.exists():
            shutil.rmtree(afl_out, ignore_errors=True)
        afl_out.mkdir(parents=True, exist_ok=True)

        attempt_log = trial_dir / f"afl-fuzz-attempt-{attempt:02d}.log"

        tte, timed_out, startup_failed = execute_single_attempt(
            cmd, env, attempt_log, crashes, repro
        )

        if tte is not None or timed_out:
            break

        reason = "startup failed" if startup_failed else "mid-campaign early exit"
        if attempt < MAX_STARTUP_RETRIES:
            delay = STARTUP_RETRY_DELAY_BASE * (5**attempt)
            print(
                f"  [retry]  {reason} (attempt {attempt}/{MAX_STARTUP_RETRIES}), retrying in {delay}s",
                flush=True,
            )
            time.sleep(delay)
        else:
            print(
                f"  [warn]  {reason} after {MAX_STARTUP_RETRIES} attempts, giving up",
                flush=True,
            )

    # ── Save results ───────────────────────────────────────────────────────────────
    if meta["cve"] == "coverage":
        status = "COMPLETE" if timed_out else "INCOMPLETE"
        (trial_dir / "status.txt").write_text(f"{status}\n")
        print(
            f"[done]  {target}/coverage/{config}/trial-{args.trial:02d} {status}",
            flush=True,
        )
    elif tte is not None and repro is not None and repro.matched_crash_name is not None:
        update_metadata(args.meta, config)
        (trial_dir / "tte.txt").write_text(f"{tte:.3f}\n")
        print(
            f"[done]  {target}/{cve}/{config}/trial-{args.trial:02d} TTE={tte:.3f}s",
            flush=True,
        )
    else:
        (trial_dir / "tte.txt").write_text("CENSORED\n")
        print(
            f"[done]  {target}/{cve}/{config}/trial-{args.trial:02d} CENSORED",
            flush=True,
        )

    # ── Cleanup ────────────────────────────────────────────────────────────────────
    for f in trial_dir.glob("smite_crash_*"):
        try:
            if f.is_file() or f.is_symlink():
                f.unlink(missing_ok=True)
            elif f.is_dir():
                shutil.rmtree(f, ignore_errors=True)
        except Exception:
            pass

    sys.exit(0 if (tte is not None or meta["cve"] == "coverage") else 1)


if __name__ == "__main__":
    run(parse_args())
