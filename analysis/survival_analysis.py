#!/usr/bin/env python3
"""
Kaplan-Meier survival curves, log-rank tests, Holm-Bonferroni correction,
median TTE + IQR, ablation comparisons.

Outputs a consolidated Markdown report with embedded plots.

Usage:
    python3 analysis/survival_analysis.py
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from lifelines import KaplanMeierFitter
from lifelines.statistics import logrank_test
from statsmodels.stats.multitest import multipletests

from utils import SURVIVAL_OUTPUT_DIR, TIMEOUT, validate_survival_data, format_median_iqr

sns.set_style("whitegrid")

# Load and validate data using shared utility
df = validate_survival_data()

# ── Primary: encrypted_bytes vs ir-full-stack ───────────────────────────────────────

records = []
generated_plots = []

for (target, cve), bug in df.groupby(["target", "cve"]):
    baseline = bug[bug["config"] == "encrypted_bytes"]
    expmt = bug[bug["config"] == "ir-full-stack"]
    if baseline.empty or expmt.empty:
        continue

    lr = logrank_test(
        durations_A=baseline["duration"],
        event_observed_A=baseline["event"],
        durations_B=expmt["duration"],
        event_observed_B=expmt["event"],
    )

    bm, biqr = format_median_iqr(baseline[baseline["event"]]["duration"])
    em, eiqr = format_median_iqr(expmt[expmt["event"]]["duration"])

    records.append(
        dict(
            Target=target,
            CVE=cve,
            Raw_p=lr.p_value,
            n_Baseline=int(len(baseline)),
            Found_Baseline=int(baseline["event"].sum()),
            Med_Baseline=bm,
            IQR_Baseline=biqr,
            n_Exp=int(len(expmt)),
            Found_Exp=int(expmt["event"].sum()),
            Med_Exp=em,
            IQR_Exp=eiqr,
        )
    )

ab_results = pd.DataFrame()

if records:
    results = pd.DataFrame(records)
    reject, corrected, _, _ = multipletests(results["Raw_p"].fillna(1.0), method="holm")
    results["Adj_p"] = corrected
    results["Significant"] = reject

    print("\n=== Primary comparison (encrypted_bytes vs ir-full-stack) ===")
    print(results.to_string(index=False))
    results.to_csv(SURVIVAL_OUTPUT_DIR / "survival_primary_results.csv", index=False)

    # ── Kaplan-Meier plots ────────────────────────────────────────────────────────
    for _, row in results.iterrows():
        target = row["Target"]
        cve = row["CVE"]

        bug = df[(df["target"] == target) & (df["cve"] == cve)]

        fig, ax = plt.subplots(figsize=(8, 5))
        kmf = KaplanMeierFitter()
        for config, label in [
            ("encrypted_bytes", "Raw-Bytes Baseline"),
            ("ir-full-stack", "IR Full Stack"),
        ]:
            grp = bug[bug["config"] == config]
            if grp.empty:
                continue
            kmf.fit(grp["duration"], grp["event"], label=label)
            kmf.plot_survival_function(ax=ax, ci_show=True, linewidth=2)

        sig = " *" if row["Significant"] else ""
        ax.set_title(
            f"{target.upper()} {cve} — p={row['Adj_p']:.4f} Holm-corrected{sig}"
        )
        ax.set_xlabel("Wall-Clock Time (s)")
        ax.set_ylabel("Probability of Bug Remaining Undiscovered")
        ax.set_xlim(0, TIMEOUT)
        ax.set_ylim(0, 1.05)
        plt.tight_layout()

        plot_filename = f"km_{target.lower()}_{cve.lower()}.png"
        plt.savefig(SURVIVAL_OUTPUT_DIR / plot_filename, dpi=300)
        plt.close()
        generated_plots.append((target, cve, plot_filename))
else:
    print("\n=== No valid paired trials found for primary comparison ===")


# ── Ablation ──────────────────────────────────────────────────────────────────

ablation_configs = ["ir-full-stack", "ir-component-a", "ir-component-b"]
ab_df = df[df["config"].isin(ablation_configs)]

if not ab_df.empty:
    ab_records = []
    for (target, cve), bug in ab_df.groupby(["target", "cve"]):
        for a, b in [
            ("ir-full-stack", "ir-component-a"),
            ("ir-full-stack", "ir-component-b"),
        ]:
            ga = bug[bug["config"] == a]
            gb = bug[bug["config"] == b]

            if len(ga) < 2 or len(gb) < 2:
                continue

            lr = logrank_test(
                durations_A=ga["duration"],
                event_observed_A=ga["event"],
                durations_B=gb["duration"],
                event_observed_B=gb["event"],
            )
            ab_records.append(
                dict(Target=target, CVE=cve, Comparison=f"{a} vs {b}", Raw_p=lr.p_value)
            )

    if ab_records:
        ab_results = pd.DataFrame(ab_records)
        _, ab_corr, _, _ = multipletests(ab_results["Raw_p"].fillna(1.0), method="holm")
        ab_results["Adj_p"] = ab_corr
        print("\n=== Ablation (exploratory) ===")
        print(ab_results.to_string(index=False))
        ab_results.to_csv(SURVIVAL_OUTPUT_DIR / "survival_ablation_results.csv", index=False)


# ── Generate Markdown Report ──────────────────────────────────────────────────
if records:
    report_path = SURVIVAL_OUTPUT_DIR / "survival_evaluation_report.md"

    view_cols = [
        "Target",
        "CVE",
        "Found_Baseline",
        "Found_Exp",
        "Med_Baseline",
        "Med_Exp",
        "IQR_Baseline",
        "IQR_Exp",
        "Adj_p",
        "Significant",
    ]
    df_view = results[view_cols].copy()

    df_view.columns = [
        "Target",
        "CVE",
        "Baseline Finds",
        "Exp. Finds",
        "Baseline Med. (s)",
        "Exp. Med. (s)",
        "Baseline IQR",
        "Exp. IQR",
        "Adj. p-value",
        "Significant",
    ]

    with open(report_path, "w") as f:
        f.write("# Time-To-Exposure (TTE) Survival Analysis Report\n\n")
        f.write("**Baseline:** `encrypted_bytes`\n")
        f.write("**Experimental:** `ir-full-stack`\n\n")

        f.write("## 1. Summary Statistics\n\n")
        pd.set_option("display.float_format", lambda x: "%.4f" % x)
        f.write(df_view.to_markdown(index=False))
        f.write(
            "\n\n*A comprehensive version of this table is available in `survival_primary_results.csv`.*\n\n"
        )

        f.write("## 2. Interpretation Guide\n\n")
        f.write(
            "Use the table above and the Kaplan-Meier plots below to evaluate the fuzzer's speed and reliability in triggering specific vulnerabilities.\n\n"
        )

        f.write("### Key Metrics\n\n")
        f.write(
            "- **`Finds`**: The number of trials (out of 20) that successfully triggered the bug within the 24-hour timeout. Trials that fail to find the bug are considered *censored*.\n"
        )
        f.write(
            "- **`Med. (s)`**: The median Time-To-Exposure. The exact wall-clock second at which 50% of the successful trials had found the bug. Lower is better.\n"
        )
        f.write(
            "- **`IQR`**: Interquartile Range (25th to 75th percentile). Represents the variance/consistency of the fuzzer's time-to-find. A narrow IQR indicates highly predictable performance.\n"
        )
        f.write(
            "- **`Adj. p-value`**: Log-rank test p-value corrected for multiple targets via Holm-Bonferroni. It tests the null hypothesis that there is no difference in the survival curves of the two configurations. `< 0.05` is statistically significant.\n\n"
        )

        f.write("### Reading Kaplan-Meier Plots\n\n")
        f.write(
            "Kaplan-Meier estimates the probability that a bug has **not yet been found** at a given time `t`. "
        )
        f.write(
            "The curve starts at `1.0` (100% chance the bug is undiscovered) and steps downward each time a trial finds the bug.\n\n"
        )
        f.write("- **Steeper drops** indicate faster discovery.\n")
        f.write("- **Shaded bands** represent the 95% Confidence Interval.\n")
        f.write(
            "- If a curve **flatlines above 0**, it means some trials timed out (censored) before finding the bug.\n"
        )
        f.write(
            "- The experimental curve should ideally be **below and to the left** of the baseline curve.\n\n"
        )

        f.write("## 3. Visualizations\n\n")

        for target, cve, plot_file in generated_plots:
            f.write(f"### {target.upper()} - {cve}\n\n")
            f.write(f"![KM Plot for {target} {cve}]({plot_file})\n\n")
            f.write("---\n\n")

        if not ab_results.empty:
            f.write("## 4. Exploratory Ablation Results\n\n")
            f.write(
                "Log-rank comparisons between the full mutator stack and its stripped-down component configurations.\n\n"
            )
            f.write(ab_results.to_markdown(index=False))
            f.write("\n\n")

    print(f"\n[*] Evaluation complete. Report saved to {report_path}")
