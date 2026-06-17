#!/usr/bin/env python3
"""
Smite Fuzzing Coverage Evaluation Script
Usage: python3 analysis/coverage_analysis.py ./results --out ./analysis/output
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from statsmodels.stats.multitest import multipletests

sns.set_style("whitegrid")


def validate_and_find_data(root_dir):
    if not os.path.exists(root_dir):
        raise FileNotFoundError(f"Results directory '{root_dir}' does not exist.")

    targets = sorted(
        [
            d
            for d in os.listdir(root_dir)
            if os.path.isdir(os.path.join(root_dir, d))
            and os.path.exists(os.path.join(root_dir, d, "coverage"))
        ]
    )
    if not targets:
        raise ValueError(
            f"No targets with a 'coverage' subdirectory found in {root_dir}"
        )

    print(f"[*] Detected Targets: {targets}")
    sample_cov_dir = os.path.join(root_dir, targets[0], "coverage")
    items = [
        d
        for d in os.listdir(sample_cov_dir)
        if os.path.isdir(os.path.join(sample_cov_dir, d))
    ]

    if len(items) != 2:
        raise ValueError(
            f"Expected exactly 2 configurations in {sample_cov_dir}, found {len(items)}: {items}"
        )

    config_a, config_b = sorted(items)
    print(f"[*] Detected Configurations: A = {config_a}, B = {config_b}")

    for target in targets:
        tgt_configs = set(os.listdir(os.path.join(root_dir, target, "coverage")))
        if config_a not in tgt_configs or config_b not in tgt_configs:
            raise ValueError(
                f"Target mismatch! {target}/coverage must contain both {config_a} and {config_b}"
            )

    data_paths = {config_a: {}, config_b: {}}

    for config in [config_a, config_b]:
        for target in targets:
            target_path = os.path.join(root_dir, target, "coverage", config)
            trials = [
                d
                for d in os.listdir(target_path)
                if os.path.isdir(os.path.join(target_path, d))
            ]
            valid_trials = []

            for trial in trials:
                trial_path = os.path.join(target_path, trial)
                status_file = os.path.join(trial_path, "status.txt")

                is_complete = False
                if os.path.exists(status_file):
                    with open(status_file, "r") as sf:
                        if sf.read().strip() == "COMPLETE":
                            is_complete = True

                if not is_complete:
                    print(
                        f"[!] Warning: {trial_path} marked INCOMPLETE or missing status.txt. Skipping to prevent bias."
                    )
                    continue

                base_out = os.path.join(trial_path, "afl-out", "default")
                if not os.path.exists(base_out):
                    base_out = trial_path

                req_files = ["plot_data", "fuzzer_stats", "fuzz_bitmap"]
                if all(os.path.exists(os.path.join(base_out, f)) for f in req_files):
                    valid_trials.append(base_out)
                else:
                    print(
                        f"[!] Warning: Missing required files in {trial_path}. Skipping."
                    )

            data_paths[config][target] = valid_trials
            print(
                f"    - {target}/coverage/{config}: found {len(valid_trials)} valid trials"
            )

    return config_a, config_b, targets, data_paths


def parse_plot_data(filepath):
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
    with open(filepath, "r") as f:
        for line in f:
            if "execs_per_sec" in line:
                return float(line.split(":")[1].strip())
    return 0.0


def calculate_union_coverage(trial_paths):
    bitmaps, expected_size = [], None
    for path in trial_paths:
        bmp = np.fromfile(os.path.join(path, "fuzz_bitmap"), dtype=np.uint8)
        if expected_size is None:
            expected_size = len(bmp)
        elif len(bmp) != expected_size:
            continue
        bitmaps.append(bmp)
    return np.sum(np.bitwise_and.reduce(bitmaps, axis=0) < 255) if bitmaps else 0


def vargha_delaney_a12(u_stat, n_a, n_b):
    return 0.5 if n_a == 0 or n_b == 0 else u_stat / (n_a * n_b)


def process_data(root_dir, output_dir, config_a, config_b, targets, data_paths):
    os.makedirs(output_dir, exist_ok=True)
    summary_stats, p_values_cov_raw, p_values_auc_raw = [], [], []

    for target in targets:
        print(f"\n[*] Processing Target: {target}")
        target_data = {
            config_a: {"final_cov": [], "auc": [], "execs": [], "union": 0},
            config_b: {"final_cov": [], "auc": [], "execs": [], "union": 0},
        }
        raw_time_series = {config_a: [], config_b: []}
        global_max_hrs = 0.0

        for config in [config_a, config_b]:
            for path in data_paths[config][target]:
                times, covs = parse_plot_data(os.path.join(path, "plot_data"))
                if len(times) > 0 and times[-1] > global_max_hrs:
                    global_max_hrs = times[-1]
                target_data[config]["execs"].append(
                    parse_fuzzer_stats(os.path.join(path, "fuzzer_stats"))
                )
                raw_time_series[config].append((times, covs))
            target_data[config]["union"] = calculate_union_coverage(
                data_paths[config][target]
            )

        eval_hours = global_max_hrs
        grid_times = np.linspace(0, eval_hours, 1000)
        interpolated_series = {config_a: [], config_b: []}

        for config in [config_a, config_b]:
            for times, covs in raw_time_series[config]:
                if len(times) == 0:
                    continue
                interp_cov = np.interp(grid_times, times, covs)
                interpolated_series[config].append(interp_cov)
                target_data[config]["final_cov"].append(interp_cov[-1])
                target_data[config]["auc"].append(
                    np.trapezoid(y=interp_cov, x=grid_times)
                )

        cov_a, cov_b = (
            target_data[config_a]["final_cov"],
            target_data[config_b]["final_cov"],
        )
        auc_a, auc_b = target_data[config_a]["auc"], target_data[config_b]["auc"]
        n_a, n_b = len(cov_a), len(cov_b)

        if n_a == 0 or n_b == 0:
            print(f"[!] Insufficient data for {target}. Skipping stats.")
            continue

        u_stat_cov, p_raw_cov = stats.mannwhitneyu(
            cov_b, cov_a, alternative="two-sided"
        )
        a12_cov = vargha_delaney_a12(u_stat_cov, n_b, n_a)
        p_values_cov_raw.append(p_raw_cov)

        u_stat_auc, p_raw_auc = stats.mannwhitneyu(
            auc_b, auc_a, alternative="two-sided"
        )
        a12_auc = vargha_delaney_a12(u_stat_auc, n_b, n_a)
        p_values_auc_raw.append(p_raw_auc)

        summary_stats.append(
            {
                "Target": target,
                "Duration (h)": eval_hours,
                "n (Baseline)": n_a,
                "n (Exp.)": n_b,
                "Median Cov. (Baseline)": np.median(cov_a),
                "Median Cov. (Exp.)": np.median(cov_b),
                "IQR Cov. (Baseline)": stats.iqr(cov_a),
                "IQR Cov. (Exp.)": stats.iqr(cov_b),
                "Raw p-value (Cov.)": p_raw_cov,
                "Â12 (Cov.)": a12_cov,
                "Median AUC (Baseline)": np.median(auc_a),
                "Median AUC (Exp.)": np.median(auc_b),
                "IQR AUC (Baseline)": stats.iqr(auc_a),
                "IQR AUC (Exp.)": stats.iqr(auc_b),
                "Raw p-value (AUC)": p_raw_auc,
                "Â12 (AUC)": a12_auc,
                "Union Cov. (Baseline)": target_data[config_a]["union"],
                "Union Cov. (Exp.)": target_data[config_b]["union"],
                "Execs/s (Baseline)": np.median(target_data[config_a]["execs"]),
                "Execs/s (Exp.)": np.median(target_data[config_b]["execs"]),
            }
        )

        # --- Plots ---
        plt.figure(figsize=(8, 6))
        sns.boxplot(data=[cov_a, cov_b], palette="Set2")
        plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
        plt.title(f"{target} - Final Edge Coverage ({eval_hours:.1f}h)")
        plt.suptitle(
            "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
            fontsize=10,
            color="gray",
        )
        plt.ylabel("Edges Found")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"{target}_boxplot.png"), dpi=300)
        plt.close()

        plt.figure(figsize=(8, 6))
        sns.boxplot(data=[auc_a, auc_b], palette="Set2")
        plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
        plt.title(f"{target} - Area Under Curve (AUC)")
        plt.suptitle(
            "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
            fontsize=10,
            color="gray",
        )
        plt.ylabel("Cumulative Coverage × Time")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"{target}_auc_boxplot.png"), dpi=300)
        plt.close()

        plt.figure(figsize=(10, 6))
        colors = {config_a: "blue", config_b: "orange"}
        for config in [config_a, config_b]:
            ts_matrix = np.array(interpolated_series[config])
            if ts_matrix.shape[0] == 0:
                continue
            plt.plot(
                grid_times,
                np.median(ts_matrix, axis=0),
                label=f"{config} (n={len(interpolated_series[config])})",
                color=colors[config],
                linewidth=2,
            )
            plt.fill_between(
                grid_times,
                np.percentile(ts_matrix, 25, axis=0),
                np.percentile(ts_matrix, 75, axis=0),
                color=colors[config],
                alpha=0.2,
            )
        plt.title(f"{target} - Median Coverage Over Time (with IQR bounds)")
        plt.xlabel("Time (Hours)")
        plt.ylabel("Edges Found")
        plt.xlim([0, eval_hours])
        plt.ylim(bottom=0)
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"{target}_time_series.png"), dpi=300)
        plt.close()

    if len(p_values_cov_raw) > 0:
        reject_cov, p_adj_cov, _, _ = multipletests(
            p_values_cov_raw, alpha=0.05, method="holm"
        )
        reject_auc, p_adj_auc, _, _ = multipletests(
            p_values_auc_raw, alpha=0.05, method="holm"
        )
        for i, stat in enumerate(summary_stats):
            stat["Adj. p-value (Cov.)"] = p_adj_cov[i]
            stat["Sig_Cov"] = reject_cov[i]
            stat["Adj. p-value (AUC)"] = p_adj_auc[i]
            stat["Sig_AUC"] = reject_auc[i]

    if not summary_stats:
        print("[!] No data processed. Reports not generated.")
        return

    df_results = pd.DataFrame(summary_stats)
    csv_path = os.path.join(output_dir, "coverage_evaluation_metrics.csv")
    df_results.to_csv(csv_path, index=False)

    view_cols = [
        "Target",
        "Duration (h)",
        "n (Baseline)",
        "n (Exp.)",
        "Median Cov. (Baseline)",
        "Median Cov. (Exp.)",
        "Adj. p-value (Cov.)",
        "Â12 (Cov.)",
        "Median AUC (Baseline)",
        "Median AUC (Exp.)",
        "Adj. p-value (AUC)",
        "Â12 (AUC)",
        "Union Cov. (Baseline)",
        "Union Cov. (Exp.)",
        "Execs/s (Baseline)",
        "Execs/s (Exp.)",
    ]

    report_path = os.path.join(output_dir, "coverage_evaluation_report.md")
    with open(report_path, "w") as f:
        f.write("# Fuzzing Evaluation Report\n\n")
        f.write(f"**Configuration A (Baseline):** `{config_a}`\n")
        f.write(f"**Configuration B (Experimental):** `{config_b}`\n\n")
        f.write("## 1. Summary Statistics\n\n")
        pd.set_option("display.float_format", lambda x: "%.3f" % x)
        f.write(df_results[view_cols].to_markdown(index=False))
        f.write(
            "\n\n*A comprehensive version of this table is available in `coverage_evaluation_metrics.csv`.*\n\n"
        )
        f.write("## 2. Interpretation Guide\n\n")
        f.write(
            "- **`Adj. p-value`**: Mann-Whitney U test corrected for multiple targets via Holm-Bonferroni.\n"
        )
        f.write(
            "- **`Â12`**: Probability that a random B trial outperforms a random A trial (0.5 = no diff).\n"
        )
        f.write("- **`IQR`**: Spread of the middle 50% of trials.\n")
        f.write(
            "- **`AUC`**: Coverage *speed* — how much was discovered and how early.\n"
        )
        f.write(
            "- **Union Coverage**: OR of all trial bitmaps; the coverage ceiling for a multi-core deployment.\n\n"
        )
        f.write("## 3. Visualizations\n\n")
        for target in targets:
            f.write(f"### Target: {target}\n\n")
            f.write(f"#### Median Coverage Over Time\n\n")
            f.write(f"![{target} Time Series]({target}_time_series.png)\n\n")
            f.write(f"#### Distribution Comparisons\n\n")
            f.write(
                f"| Final Edge Coverage | Area Under Curve (Speed) |\n|:---:|:---:|\n"
            )
            f.write(
                f"| ![{target} Boxplot]({target}_boxplot.png) | ![{target} AUC]({target}_auc_boxplot.png) |\n\n---\n\n"
            )

    print(f"\n[*] Evaluation complete. Results saved to {output_dir}")
    print(f"    - Open {report_path} to interpret the campaign.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Smite Fuzzing Evaluation Script")
    parser.add_argument(
        "results_dir", type=str, help="Path to the global results directory."
    )
    parser.add_argument(
        "--out",
        type=str,
        default="analysis/output",
        help="Directory to save generated reports and plots.",
    )
    args = parser.parse_args()

    cfg_a, cfg_b, tgts, data = validate_and_find_data(args.results_dir)
    process_data(args.results_dir, args.out, cfg_a, cfg_b, tgts, data)
