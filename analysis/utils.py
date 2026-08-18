#!/usr/bin/env python3
"""
Shared utilities, math helpers, data validation, and path constants
for Smite Fuzzing Analysis.
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path

# ── Global Paths & Constants ───────────────────────────────────────────────────
EVAL_DIR = Path(__file__).parent.parent

SURVIVAL_RESULTS_DIR = EVAL_DIR / "survival-results"
SURVIVAL_OUTPUT_DIR = EVAL_DIR / "analysis" / "survival-output"

COVERAGE_RESULTS_DIR = EVAL_DIR / "coverage-results"
COVERAGE_OUTPUT_DIR = EVAL_DIR / "analysis" / "coverage-output"

TIMEOUT = 86_400.0

# Each target directory under coverage-results/ holds 6 config subdirectories:
# the baseline, the full IR mutator stack, and one ir-<mutator> variant per
# mutator with that single mutator ablated from the full stack.
COVERAGE_BASELINE_CONFIG = "encrypted_bytes"
COVERAGE_FULL_STACK_CONFIG = "ir-full-stack"
ABLATION_CONFIGS = {
    "splice": "ir-splice",
    "gen-insert": "ir-gen-insert",
    "delete": "ir-delete",
    "reorder": "ir-reorder",
}

# Ensure output directories exists for all downstream scripts
SURVIVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
COVERAGE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Data Validation ────────────────────────────────────────────────────────────


def _find_valid_trials(target_path, label):
    """Scans a single <target>/<config> directory for trial subdirectories with
    the required AFL++ output files, unwrapping the afl-out/default layout when
    present. Shared by validate_coverage_data() and validate_ablation_data() so
    the trial-validity rules only live in one place."""
    if not target_path.exists():
        print(
            f"[!] Warning: {target_path.relative_to(EVAL_DIR)} does not exist. Skipping."
        )
        return []

    trials = [d.name for d in target_path.iterdir() if d.is_dir()]
    valid_trials = []

    for trial in trials:
        trial_path = target_path / trial

        base_out = trial_path / "afl-out" / "default"
        if not base_out.exists():
            base_out = trial_path

        req_files = ["plot_data", "fuzzer_stats", "fuzz_bitmap"]
        if all((base_out / f).exists() for f in req_files):
            # Store string paths to maintain compatibility with existing numpy/pandas code
            valid_trials.append(str(base_out))
        else:
            print(
                f"[!] Warning: Missing required files in {trial_path.relative_to(EVAL_DIR)}. Skipping."
            )

    print(f"    - {label}: found {len(valid_trials)} valid trials")
    return valid_trials


def validate_coverage_data():
    """Scans the results directory and validates the coverage evaluation layout.

    Each target directory contains 6 configs (baseline, full stack, and 4
    per-mutator ablation variants); this only validates/loads the main
    baseline-vs-full-stack comparison. Use validate_ablation_data() for the
    ir-<mutator> ablation configs.
    """
    if not COVERAGE_RESULTS_DIR.exists():
        raise FileNotFoundError(
            f"Results directory '{COVERAGE_RESULTS_DIR}' does not exist."
        )

    targets = sorted(
        [
            d.name
            for d in COVERAGE_RESULTS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
    )
    if not targets:
        raise ValueError(f"No valid targets found in {COVERAGE_RESULTS_DIR}")

    print(f"[*] Detected Targets for Coverage: {targets}")

    config_a, config_b = COVERAGE_BASELINE_CONFIG, COVERAGE_FULL_STACK_CONFIG
    print(f"[*] Detected Configurations: A = {config_a}, B = {config_b}")

    for target in targets:
        tgt_configs = {
            d.name for d in (COVERAGE_RESULTS_DIR / target).iterdir() if d.is_dir()
        }
        if config_a not in tgt_configs or config_b not in tgt_configs:
            raise ValueError(
                f"Target mismatch! {target} must contain both {config_a} and {config_b}, "
                f"found: {sorted(tgt_configs)}"
            )

    data_paths = {config_a: {}, config_b: {}}

    for config in [config_a, config_b]:
        for target in targets:
            target_path = COVERAGE_RESULTS_DIR / target / config
            data_paths[config][target] = _find_valid_trials(
                target_path, f"{target}/coverage/{config}"
            )

    return config_a, config_b, targets, data_paths


def validate_ablation_data():
    """Scans the same coverage-results tree for the mutator-ablation configs:
    for each mutator, ir-full-stack (shared "full" arm) vs. ir-<mutator> (that
    single mutator ablated from the full stack).

    Returns (mutators, targets, ablation_data_paths) where
    ablation_data_paths[mutator][target]["full" | "ablated"] is a list of
    trial directory paths, matching the shape process_ablation_appendix()
    expects.
    """
    if not COVERAGE_RESULTS_DIR.exists():
        raise FileNotFoundError(
            f"Results directory '{COVERAGE_RESULTS_DIR}' does not exist."
        )

    targets = sorted(
        d.name
        for d in COVERAGE_RESULTS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )
    if not targets:
        raise ValueError(f"No valid targets found in {COVERAGE_RESULTS_DIR}")

    required_configs = {COVERAGE_FULL_STACK_CONFIG, *ABLATION_CONFIGS.values()}
    missing = {}
    for target in targets:
        tgt_configs = {
            d.name for d in (COVERAGE_RESULTS_DIR / target).iterdir() if d.is_dir()
        }
        gap = required_configs - tgt_configs
        if gap:
            missing[target] = sorted(gap)
    if missing:
        raise ValueError(f"Missing ablation configs by target: {missing}")

    mutators = sorted(ABLATION_CONFIGS.keys())
    print(f"[*] Detected Ablation Mutators: {mutators}")

    ablation_data_paths = {mutator: {} for mutator in mutators}

    # ir-full-stack trials are shared across every mutator's "full" arm for a
    # given target, so scan them once per target instead of once per mutator.
    full_stack_by_target = {
        target: _find_valid_trials(
            COVERAGE_RESULTS_DIR / target / COVERAGE_FULL_STACK_CONFIG,
            f"{target}/ablation/{COVERAGE_FULL_STACK_CONFIG}",
        )
        for target in targets
    }

    for mutator, config_name in ABLATION_CONFIGS.items():
        for target in targets:
            ablated_trials = _find_valid_trials(
                COVERAGE_RESULTS_DIR / target / config_name,
                f"{target}/ablation/{mutator}",
            )
            ablation_data_paths[mutator][target] = {
                "full": full_stack_by_target[target],
                "ablated": ablated_trials,
            }

    return mutators, targets, ablation_data_paths


def validate_survival_data():
    """Loads and validates the TTE survival trials CSV."""
    csv_path = SURVIVAL_RESULTS_DIR / "trials.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"[!] Error: Cannot find trial data at {csv_path}")

    df = pd.read_csv(csv_path)

    required_cols = {"target", "cve", "config", "trial", "tte_seconds", "censored"}
    if not required_cols.issubset(df.columns):
        missing = required_cols - set(df.columns)
        raise ValueError(f"trials.csv is missing required columns: {missing}")

    # Drop coverage rows immediately to prevent survival analysis pollution
    initial_len = len(df)
    df = df[df["cve"] != "coverage"].copy()
    dropped = initial_len - len(df)
    if dropped > 0:
        print(f"[*] Filtered {dropped} coverage pseudo-trials from survival dataset.")

    if df.empty:
        raise ValueError("trials.csv contains no valid TTE (bug-finding) trials.")

    # Validate data integrity
    if (df["tte_seconds"] < 0).any():
        raise ValueError("Found negative TTE values in trials.csv")

    print(f"[*] Detected TTE Targets: {list(df['target'].unique())}")
    print(f"[*] Detected TTE Configs: {list(df['config'].unique())}")
    print(f"[*] Validated {len(df)} total survival records.")

    # Calculate duration (filling NaNs with TIMEOUT) and event flag
    df["duration"] = df["tte_seconds"].fillna(TIMEOUT).astype(float)
    df["event"] = ~df["censored"].astype(bool)

    return df


# ── Data Parsing ───────────────────────────────────────────────────────────────


def parse_plot_data(filepath):
    """Parses AFL++ plot_data and returns (times_in_hours, coverage)."""
    with open(filepath, "r") as f:
        header_line = f.readline().strip()

    header = [col.strip() for col in header_line.lstrip("#").split(",")]
    df = pd.read_csv(
        filepath, comment="#", sep=",", header=None, names=header, skipinitialspace=True
    )

    time_col = (
        "relative_time"
        if "relative_time" in header
        else ("unix_time" if "unix_time" in header else None)
    )
    cov_col = (
        "edges_found"
        if "edges_found" in header
        else ("map_size" if "map_size" in header else None)
    )

    if not time_col or not cov_col:
        raise ValueError(
            f"Could not find valid time/coverage column in {filepath}. Header: {header}"
        )

    times = pd.to_numeric(df[time_col], errors="coerce").fillna(0).values
    if df[cov_col].dtype == object:
        df[cov_col] = df[cov_col].astype(str).str.rstrip("%")
    coverage = pd.to_numeric(df[cov_col], errors="coerce").fillna(0).values

    relative_times_hrs = (times - times[0]) / 3600.0 if len(times) > 0 else times
    return relative_times_hrs, coverage


def parse_fuzzer_stats(filepath):
    """Extracts execs_per_sec from fuzzer_stats."""
    with open(filepath, "r") as f:
        for line in f:
            if "execs_per_sec" in line:
                return float(line.split(":")[1].strip())
    return 0.0


def calculate_union_coverage(trial_paths):
    """Performs bitwise-AND across all trial bitmaps to calculate multi-core union coverage."""
    bitmaps, expected_size = [], None
    for path in trial_paths:
        bmp = np.fromfile(os.path.join(path, "fuzz_bitmap"), dtype=np.uint8)
        if expected_size is None:
            expected_size = len(bmp)
        elif len(bmp) != expected_size:
            continue
        bitmaps.append(bmp)

    return int(np.sum(np.bitwise_and.reduce(bitmaps, axis=0) < 255)) if bitmaps else 0


# ── Statistics Helpers ─────────────────────────────────────────────────────────


def vargha_delaney_a12(u_stat, n_a, n_b):
    """Calculates the Vargha-Delaney A12 effect size."""
    return 0.5 if n_a == 0 or n_b == 0 else u_stat / (n_a * n_b)


def format_median_iqr(series):
    """Returns a tuple of formatted string (median, IQR_range) for reports."""
    if series.empty:
        return "—", "—"
    return (
        f"{series.median():.0f}",
        f"{series.quantile(0.25):.0f}-{series.quantile(0.75):.0f}",
    )
