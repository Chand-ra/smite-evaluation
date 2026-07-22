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

# Ensure output directories exists for all downstream scripts
SURVIVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
COVERAGE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Data Validation ────────────────────────────────────────────────────────────


def validate_coverage_data():
    """Scans the results directory and validates the coverage evaluation layout."""
    if not COVERAGE_RESULTS_DIR.exists():
        raise FileNotFoundError(f"Results directory '{COVERAGE_RESULTS_DIR}' does not exist.")

    targets = sorted(
        [
            d.name
            for d in COVERAGE_RESULTS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
    )
    if not targets:
        raise ValueError(
            f"No valid targets found in {COVERAGE_RESULTS_DIR}"
        )

    print(f"[*] Detected Targets for Coverage: {targets}")
    sample_cov_dir = COVERAGE_RESULTS_DIR / targets[0]
    items = [d.name for d in sample_cov_dir.iterdir() if d.is_dir()]

    if len(items) != 2:
        raise ValueError(
            f"Expected exactly 2 configurations in {sample_cov_dir}, found {len(items)}: {items}"
        )

    config_a, config_b = sorted(items)
    print(f"[*] Detected Configurations: A = {config_a}, B = {config_b}")

    for target in targets:
        tgt_configs = set(
            [
                d.name
                for d in (COVERAGE_RESULTS_DIR / target).iterdir()
                if d.is_dir()
            ]
        )
        if config_a not in tgt_configs or config_b not in tgt_configs:
            raise ValueError(
                f"Target mismatch! {target} must contain both {config_a} and {config_b}"
            )

    data_paths = {config_a: {}, config_b: {}}

    for config in [config_a, config_b]:
        for target in targets:
            target_path = COVERAGE_RESULTS_DIR / target / config
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

            data_paths[config][target] = valid_trials
            print(
                f"    - {target}/coverage/{config}: found {len(valid_trials)} valid trials"
            )

    return config_a, config_b, targets, data_paths


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
