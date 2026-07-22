#!/usr/bin/env python3
"""
Smite Fuzzing Coverage Evaluation Script

Usage:
    python3 analysis/coverage_analysis.py
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from statsmodels.stats.multitest import multipletests

from utils import (
    COVERAGE_OUTPUT_DIR,
    validate_coverage_data,
    parse_plot_data,
    parse_fuzzer_stats,
    calculate_union_coverage,
    vargha_delaney_a12,
)

sns.set_style("whitegrid")


def process_data(config_a, config_b, targets, data_paths):
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
        plt.savefig(COVERAGE_OUTPUT_DIR / f"{target}_boxplot.png", dpi=300)
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
        plt.savefig(COVERAGE_OUTPUT_DIR / f"{target}_auc_boxplot.png", dpi=300)
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
        plt.savefig(COVERAGE_OUTPUT_DIR / f"{target}_time_series.png", dpi=300)
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
    csv_path = COVERAGE_OUTPUT_DIR / "coverage_evaluation_metrics.csv"
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

    report_path = COVERAGE_OUTPUT_DIR / "coverage_evaluation_report.md"
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

    print(f"\n[*] Evaluation complete. Results saved to {COVERAGE_OUTPUT_DIR}")
    print(f"    - Open {report_path} to interpret the campaign.")


if __name__ == "__main__":
    cfg_a, cfg_b, tgts, data = validate_coverage_data()
    process_data(cfg_a, cfg_b, tgts, data)
