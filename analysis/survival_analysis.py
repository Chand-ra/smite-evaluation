#!/usr/bin/env python3
"""
Kaplan-Meier survival curves, log-rank tests, Holm-Bonferroni correction,
median TTE + IQR, ablation comparisons.

Usage:
    python survival_analysis.py
"""

import pandas as pd
import matplotlib.pyplot as plt
from lifelines import KaplanMeierFitter
from lifelines.statistics import logrank_test
from statsmodels.stats.multitest import multipletests
from pathlib import Path

EVAL_DIR = Path(__file__).parent.parent
OUTPUT = EVAL_DIR / "analysis" / "output"
TIMEOUT = 86_400.0
OUTPUT.mkdir(exist_ok=True)

df = pd.read_csv(EVAL_DIR / "results" / "trials.csv")
df["duration"] = df["tte_seconds"].fillna(TIMEOUT).astype(float)
df["event"] = ~df["censored"].astype(bool)


# ── Primary: encrypted_bytes vs ir-full-stack ───────────────────────────────────────

records = []
# Group by both target and cve to prevent merging different implementations
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

    def stats(g):
        found = g[g["event"]]["duration"]
        if found.empty:
            return "—", "—"
        return (
            f"{found.median():.0f}",
            f"{found.quantile(0.25):.0f}-{found.quantile(0.75):.0f}",
        )

    bm, biqr = stats(baseline)
    em, eiqr = stats(expmt)

    records.append(
        dict(
            target=target,  # Added target tracking
            cve=cve,
            p_raw=lr.p_value,
            baseline_n=int(baseline["event"].sum()),
            baseline_median=bm,
            baseline_iqr=biqr,
            ir_n=int(expmt["event"].sum()),
            ir_median=em,
            ir_iqr=eiqr,
        )
    )

# Check if records is empty before generating results to prevent errors on dry-runs
if records:
    results = pd.DataFrame(records)
    reject, corrected, _, _ = multipletests(results["p_raw"].fillna(1.0), method="holm")
    results["p_corrected"] = corrected
    results["significant"] = reject

    print("\n=== Primary comparison (encrypted_bytes vs ir-full-stack) ===")
    print(results.to_string(index=False))
    results.to_csv(OUTPUT / "primary_results.csv", index=False)

    # ── Kaplan-Meier plots ────────────────────────────────────────────────────────

    for _, row in results.iterrows():
        target = row["target"]
        cve = row["cve"]

        # Isolate the specific bug for the plot
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
            kmf.plot_survival_function(ax=ax, ci_show=True)

        sig = " *" if row["significant"] else ""
        ax.set_title(
            f"{target.upper()} {cve} — p={row['p_corrected']:.4f} Holm-corrected{sig}"
        )
        ax.set_xlabel("Wall-Clock Time (s)")
        ax.set_ylabel("P(bug not yet found)")
        ax.set_xlim(0, TIMEOUT)
        plt.tight_layout()

        # Save filename utilizing the target to prevent overwrites
        plt.savefig(OUTPUT / f"km_{target.lower()}_{cve.lower()}.pdf")
        plt.close()
else:
    print("\n=== No valid paired trials found for primary comparison ===")


# ── Ablation ──────────────────────────────────────────────────────────────────

ablation_configs = ["ir-full-stack", "ir-component-a", "ir-component-b"]
ab_df = df[df["config"].isin(ablation_configs)]

if not ab_df.empty:
    ab_records = []
    # FIX: Group by both target and cve here as well
    for (target, cve), bug in ab_df.groupby(["target", "cve"]):
        for a, b in [
            ("ir-full-stack", "ir-component-a"),
            ("ir-full-stack", "ir-component-b"),
        ]:
            ga = bug[bug["config"] == a]
            gb = bug[bug["config"] == b]

            # Require at least 2 events in each group to perform a meaningful log-rank
            if len(ga) < 2 or len(gb) < 2:
                continue

            lr = logrank_test(
                durations_A=ga["duration"],
                event_observed_A=ga["event"],
                durations_B=gb["duration"],
                event_observed_B=gb["event"],
            )
            ab_records.append(
                dict(target=target, cve=cve, comparison=f"{a} vs {b}", p_raw=lr.p_value)
            )

    if ab_records:
        ab_results = pd.DataFrame(ab_records)
        _, ab_corr, _, _ = multipletests(ab_results["p_raw"].fillna(1.0), method="holm")
        ab_results["p_corrected"] = ab_corr
        print("\n=== Ablation (exploratory) ===")
        print(ab_results.to_string(index=False))
        ab_results.to_csv(OUTPUT / "ablation_results.csv", index=False)
