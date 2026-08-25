#!/usr/bin/env python3
"""
Kaplan-Meier survival curves, log-rank tests, Holm-Bonferroni correction,
median TTE + IQR.

Bugs with zero discovery events in BOTH configurations are excluded from the
log-rank / Holm-Bonferroni family entirely: with every trial in both arms
right-censored there are no observed event times for the log-rank statistic
to sum over, so the test is undefined (not merely uninformative). These bugs
are reported separately as "not exposed by either configuration" instead of
being assigned a placeholder p-value, and the Holm-Bonferroni family size
`m` reflects only the bugs that actually contributed a test.

Bugs with discovery events in only ONE arm remain in the primary comparison
-- the log-rank test is still well-defined, since the zero-event arm simply
contributes its full risk set as censored observations at each event time in
the other arm -- but no median TTE is reported for the zero-event arm (its
KM curve never crosses 0.5); it is reported as "Not Reached" instead.

Outputs a consolidated Markdown report with embedded plots, plus a single
compact "USENIX Ribbon" figure: an N x 1 vertical stack (N = number of
targets), each panel showing the *pooled* cumulative probability of
discovery (1 - S(t)) across every bug + trial for that target, on a log
time axis. Per-bug TTEs span ~4 orders of magnitude within a single
target's benchmark, so a per-bug grid on a linear axis just collapses the
fast bugs to a vertical line near t=0; pooling + log-scale keeps the full
range legible in one compact panel per target. Panels are stacked
vertically (rather than side-by-side) to fit a single paper column, and
each panel's x-axis is scaled to that target's own observed duration
range rather than a single shared window, since targets can differ from
each other by orders of magnitude and a shared window wastes most of a
narrow column-width panel on the tighter-range targets.

Usage:
    python3 analysis/survival_analysis.py
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from lifelines import KaplanMeierFitter
from lifelines.statistics import logrank_test
from statsmodels.stats.multitest import multipletests

from utils import (
    SURVIVAL_OUTPUT_DIR,
    TIMEOUT,
    validate_survival_data,
    format_median_iqr,
)

sns.set_style("whitegrid")

CONFIG_STYLES = {
    "encrypted_bytes": {"label": "Raw-Bytes Baseline", "color": "0.4"},
    "ir": {"label": "IR", "color": "C0"},
}

NOT_REACHED = "Not Reached"


def median_iqr_or_not_reached(grp):
    """Median/IQR of TTE for one arm, or 'Not Reached' if the arm had zero
    discovery events. With zero events the KM curve never crosses 0.5, so
    the median is genuinely undefined -- report that explicitly rather than
    fabricating a number or silently dropping the field."""
    if grp["event"].sum() == 0:
        return NOT_REACHED, NOT_REACHED
    return format_median_iqr(grp[grp["event"]]["duration"])


# Load and validate data using shared utility
df = validate_survival_data()

# ── Primary: encrypted_bytes vs ir ──────────────────────────────────────────

records = []  # bugs with >=1 event in at least one arm -> tested
excluded_records = []  # bugs with 0 events in BOTH arms -> log-rank undefined
generated_plots = []
excluded_plots = []

# NOTE: the groupby key (bug_name) and the per-group DataFrame (grp) must be
# kept as distinct variables. Reusing the same name for both (e.g. naming
# both "bug") causes the group key to be silently overwritten by the group
# DataFrame on the very next loop-target assignment, which then corrupts
# every downstream use of the bug name (including boolean masks like
# df["bug"] == bug, which breaks with a DataFrame-vs-Series alignment error).
for (target, bug_name), grp in df.groupby(["target", "bug"]):
    baseline = grp[grp["config"] == "encrypted_bytes"]
    expmt = grp[grp["config"] == "ir"]
    if baseline.empty or expmt.empty:
        continue

    found_baseline = int(baseline["event"].sum())
    found_exp = int(expmt["event"].sum())

    bm, biqr = median_iqr_or_not_reached(baseline)
    em, eiqr = median_iqr_or_not_reached(expmt)

    base_record = dict(
        Target=target,
        BUG=bug_name,
        n_Baseline=int(len(baseline)),
        Found_Baseline=found_baseline,
        Med_Baseline=bm,
        IQR_Baseline=biqr,
        n_Exp=int(len(expmt)),
        Found_Exp=found_exp,
        Med_Exp=em,
        IQR_Exp=eiqr,
    )

    if found_baseline == 0 and found_exp == 0:
        # Neither configuration found the bug: every trial in both arms is
        # right-censored, so there are no event times for the log-rank
        # statistic to compare. Exclude from the comparative family rather
        # than reporting a meaningless (or NaN) p-value.
        excluded_records.append(base_record)
        continue

    # At least one arm has events, so the log-rank test is well-defined even
    # if the other arm is entirely censored (it still contributes its full
    # risk set at each event time observed in the other arm).
    lr = logrank_test(
        durations_A=baseline["duration"],
        event_observed_A=baseline["event"],
        durations_B=expmt["duration"],
        event_observed_B=expmt["event"],
    )
    base_record["Raw_p"] = lr.p_value
    records.append(base_record)

if records:
    results = pd.DataFrame(records)

    # Global Holm-Bonferroni correction over only the bugs that actually
    # contributed a test (m = number of bugs with >=1 event in either arm,
    # NOT the fixed benchmark size).
    reject, corrected, _, _ = multipletests(results["Raw_p"].fillna(1.0), method="holm")
    results["Adj_p"] = corrected
    results["Significant"] = reject

    # Per-target Holm-Bonferroni correction (RQ4): apply the same
    # "m = tested bugs" logic within each target's sub-family so a target
    # with fewer testable bugs isn't penalized by the global m.
    results["Adj_p_by_target"] = pd.NA
    results["Significant_by_target"] = pd.NA
    for target, idx in results.groupby("Target").groups.items():
        sub_p = results.loc[idx, "Raw_p"].fillna(1.0)
        sub_reject, sub_corrected, _, _ = multipletests(sub_p, method="holm")
        results.loc[idx, "Adj_p_by_target"] = sub_corrected
        results.loc[idx, "Significant_by_target"] = sub_reject

    print("\n=== Primary comparison (encrypted_bytes vs ir) ===")
    print(f"    Tested bugs (>=1 event in either arm): {len(results)}")
    print(results.to_string(index=False))
    results.to_csv(SURVIVAL_OUTPUT_DIR / "survival_primary_results.csv", index=False)

    # ── Kaplan-Meier plots (per bug) ─────────────────────────────────────────
    for _, row in results.iterrows():
        target = row["Target"]
        bug_name = row["BUG"]

        grp = df[(df["target"] == target) & (df["bug"] == bug_name)]

        fig, ax = plt.subplots(figsize=(8, 5))
        kmf = KaplanMeierFitter()
        for config, style in CONFIG_STYLES.items():
            arm = grp[grp["config"] == config]
            if arm.empty:
                continue
            kmf.fit(arm["duration"], arm["event"], label=style["label"])
            kmf.plot_survival_function(
                ax=ax, ci_show=True, linewidth=2, color=style["color"]
            )

        sig = " *" if row["Significant"] else ""
        ax.set_title(
            f"{target.upper()} {bug_name} — p={row['Adj_p']:.4f} Holm-corrected{sig}"
        )
        ax.set_xlabel("Wall-Clock Time (s)")
        ax.set_ylabel("Probability of Bug Remaining Undiscovered")
        ax.set_xlim(0, TIMEOUT)
        ax.set_ylim(0, 1.05)
        plt.tight_layout()

        plot_filename = f"km_{target.lower()}_{bug_name.lower()}.png"
        plt.savefig(SURVIVAL_OUTPUT_DIR / plot_filename, dpi=300)
        plt.close()
        generated_plots.append((target, bug_name, plot_filename))

    # ── "USENIX Ribbon": pooled cumulative-discovery curves, 2-col grid ──────
    # Per-bug TTEs span ~4 orders of magnitude within a single target's
    # benchmark (e.g. cln: malformed_cannounce medians ~4s vs.
    # openchannel_assert ~16,000s), so a per-bug grid on a linear axis just
    # collapses the fast bugs to a vertical line. Instead: pool every bug +
    # trial for a target into one KM fit per arm, plot 1-S(t) (cumulative
    # probability of discovery -- more intuitive for a security audience
    # than a downward-sloping survival curve), and use a log time axis to
    # keep the full range legible. Panels are laid out two-per-row (matching
    # the coverage-analysis grids), which fits more targets per row than a
    # single column while still leaving each panel wide enough to read.
    # Each panel gets its own x-limits derived from that target's own
    # observed durations, rather than one shared [x_floor, TIMEOUT] window
    # -- with per-target ranges differing by orders of magnitude, a shared
    # window would leave the tighter-range targets squeezed into a sliver
    # of their panel.
    targets_sorted = sorted(df["target"].unique())
    ribbon_ncols = 2
    ribbon_nrows = int(np.ceil(len(targets_sorted) / ribbon_ncols))

    fig_ribbon, axes_ribbon = plt.subplots(
        ribbon_nrows,
        ribbon_ncols,
        figsize=(7.0, 1.6 * ribbon_nrows),
        sharey=True,
    )
    axes_ribbon = np.atleast_2d(axes_ribbon)

    legend_handles, legend_labels = None, None

    for i, target in enumerate(targets_sorted):
        ax = axes_ribbon[i // ribbon_ncols, i % ribbon_ncols]
        tgt_df = df[df["target"] == target]

        tgt_positive = tgt_df.loc[tgt_df["duration"] > 0, "duration"]
        tgt_min = tgt_positive.min() if not tgt_positive.empty else 1e-2
        tgt_max = tgt_df["duration"].max()
        x_floor = max(tgt_min * 0.5, 1e-2)
        x_ceil = max(tgt_max * 1.5, x_floor * 10)

        kmf = KaplanMeierFitter()
        for config, style in CONFIG_STYLES.items():
            arm = tgt_df[tgt_df["config"] == config]
            if arm.empty:
                continue
            kmf.fit(arm["duration"], arm["event"], label=style["label"])
            kmf.plot_cumulative_density(
                ax=ax, ci_show=True, linewidth=1.4, color=style["color"]
            )

        ax.set_xscale("log")
        ax.set_xlim(x_floor, x_ceil)
        ax.set_ylim(0, 1.0)
        ax.set_title(target.upper(), fontsize=9, loc="left", pad=2)
        ax.set_xlabel("")
        ax.tick_params(labelsize=6)

        leg = ax.get_legend()
        if leg is not None:
            if legend_handles is None:
                legend_handles, legend_labels = ax.get_legend_handles_labels()
            leg.remove()

    # Turn off any trailing empty cells if the target count is odd.
    for j in range(len(targets_sorted), ribbon_nrows * ribbon_ncols):
        axes_ribbon[j // ribbon_ncols, j % ribbon_ncols].axis("off")

    for ax in axes_ribbon[:, 0]:
        ax.set_ylabel("P(discovered)", fontsize=8)
    fig_ribbon.supxlabel("Wall-clock time (s, log scale)", fontsize=8)

    if legend_handles is not None:
        fig_ribbon.legend(
            legend_handles,
            legend_labels,
            loc="upper center",
            ncol=2,
            frameon=False,
            bbox_to_anchor=(0.5, 1.0 + 0.5 / (1.6 * ribbon_nrows)),
            fontsize=8,
        )
    fig_ribbon.tight_layout(rect=[0, 0.02, 1, 0.92])
    fig_ribbon.savefig(
        SURVIVAL_OUTPUT_DIR / "fig_survival_ribbon.pdf", bbox_inches="tight"
    )
    plt.close(fig_ribbon)
else:
    results = pd.DataFrame()
    print("\n=== No valid paired trials found for primary comparison ===")

# ── Excluded bugs: neither configuration found them (both fully censored) ──
if excluded_records:
    excluded_results = pd.DataFrame(excluded_records)
    print(
        f"\n=== {len(excluded_results)} bug(s) not exposed by either "
        "configuration within the timeout (excluded from log-rank family) ==="
    )
    print(excluded_results.to_string(index=False))
    excluded_results.to_csv(
        SURVIVAL_OUTPUT_DIR / "survival_excluded_results.csv", index=False
    )

    for _, row in excluded_results.iterrows():
        target = row["Target"]
        bug_name = row["BUG"]
        grp = df[(df["target"] == target) & (df["bug"] == bug_name)]

        fig, ax = plt.subplots(figsize=(8, 5))
        kmf = KaplanMeierFitter()
        for config, style in CONFIG_STYLES.items():
            arm = grp[grp["config"] == config]
            if arm.empty:
                continue
            kmf.fit(arm["duration"], arm["event"], label=style["label"])
            kmf.plot_survival_function(
                ax=ax, ci_show=True, linewidth=2, color=style["color"]
            )

        ax.set_title(
            f"{target.upper()} {bug_name} — not found by either configuration "
            "(no log-rank test: both arms fully censored)"
        )
        ax.set_xlabel("Wall-Clock Time (s)")
        ax.set_ylabel("Probability of Bug Remaining Undiscovered")
        ax.set_xlim(0, TIMEOUT)
        ax.set_ylim(0, 1.05)
        plt.tight_layout()

        plot_filename = f"km_{target.lower()}_{bug_name.lower()}_censored.png"
        plt.savefig(SURVIVAL_OUTPUT_DIR / plot_filename, dpi=300)
        plt.close()
        excluded_plots.append((target, bug_name, plot_filename))
else:
    excluded_results = pd.DataFrame()


# ── Generate Markdown Report ──────────────────────────────────────────────────
if records or excluded_records:
    report_path = SURVIVAL_OUTPUT_DIR / "survival_evaluation_report.md"

    with open(report_path, "w") as f:
        f.write("# Time-To-Exposure (TTE) Survival Analysis Report\n\n")
        f.write("**Baseline:** `encrypted_bytes`\n")
        f.write("**Experimental:** `ir`\n\n")
        f.write(
            f"**Tested bugs (>=1 discovery event in either arm):** {len(records)}  \n"
        )
        f.write(
            f"**Excluded bugs (0 events in both arms, log-rank undefined):** {len(excluded_records)}\n\n"
        )

        f.write("## 1. Summary Statistics\n\n")
        pd.set_option("display.float_format", lambda x: "%.4f" % x)

        if records:
            view_cols = [
                "Target",
                "BUG",
                "Found_Baseline",
                "Found_Exp",
                "Med_Baseline",
                "Med_Exp",
                "IQR_Baseline",
                "IQR_Exp",
                "Adj_p",
                "Significant",
                "Adj_p_by_target",
                "Significant_by_target",
            ]
            df_view = results[view_cols].copy()
            df_view.columns = [
                "Target",
                "BUG",
                "Baseline Finds",
                "Exp. Finds",
                "Baseline Med. (s)",
                "Exp. Med. (s)",
                "Baseline IQR",
                "Exp. IQR",
                "Adj. p-value (global)",
                "Significant (global)",
                "Adj. p-value (per-target)",
                "Significant (per-target)",
            ]
            f.write(df_view.to_markdown(index=False))
            f.write(
                "\n\n*A comprehensive version of this table is available in `survival_primary_results.csv`.*\n\n"
            )
        else:
            f.write(
                "*No bug had a discovery event in either configuration; no comparative statistics to report.*\n\n"
            )

        if excluded_records:
            f.write("### Bugs Not Exposed By Either Configuration\n\n")
            f.write(
                "The following bugs were not triggered by any trial in either configuration within the "
                f"{TIMEOUT}s timeout. Every trial is right-censored, so there are no observed event times for "
                "the log-rank statistic to compare and the test is undefined; these bugs are therefore excluded "
                "from the Holm-Bonferroni family above (`m` reflects only the tested bugs) rather than assigned "
                "a placeholder p-value.\n\n"
            )
            excl_view = excluded_results[
                ["Target", "BUG", "n_Baseline", "n_Exp"]
            ].copy()
            excl_view.columns = ["Target", "BUG", "Baseline Trials", "Exp. Trials"]
            f.write(excl_view.to_markdown(index=False))
            f.write(
                "\n\n*Full detail is available in `survival_excluded_results.csv`.*\n\n"
            )

        f.write("## 2. Interpretation Guide\n\n")
        f.write(
            "Use the table above and the Kaplan-Meier plots below to evaluate the fuzzer's speed and reliability in triggering specific bugs.\n\n"
        )

        f.write("### Key Metrics\n\n")
        f.write(
            "- **`Finds`**: The number of trials (out of 20) that successfully triggered the bug within the 24-hour timeout. Trials that fail to find the bug are considered *censored*.\n"
        )
        f.write(
            "- **`Med. (s)`**: The median Time-To-Exposure. The exact wall-clock second at which 50% of the successful trials had found the bug. Lower is better. Reported as `Not Reached` when an arm had zero discovery events, since the KM curve never crosses 0.5 in that case.\n"
        )
        f.write(
            "- **`IQR`**: Interquartile Range (25th to 75th percentile). Represents the variance/consistency of the fuzzer's time-to-find. A narrow IQR indicates highly predictable performance.\n"
        )
        f.write(
            "- **`Adj. p-value (global)`**: Log-rank test p-value corrected for multiple comparisons via Holm-Bonferroni across all *tested* bugs (`m` = number of bugs with at least one discovery event in either arm). It tests the null hypothesis that there is no difference in the survival curves of the two configurations. `< 0.05` is statistically significant.\n"
        )
        f.write(
            "- **`Adj. p-value (per-target)`**: The same log-rank p-values, Holm-Bonferroni corrected within each target's sub-family instead of globally (addresses RQ4: is the effect consistent per target?). `m` for each target is the number of that target's tested bugs.\n\n"
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

        if generated_plots:
            f.write("### Tested Bugs\n\n")
            for target, bug_name, plot_file in generated_plots:
                f.write(f"#### {target.upper()} - {bug_name}\n\n")
                f.write(f"![KM Plot for {target} {bug_name}]({plot_file})\n\n")
                f.write("---\n\n")

        if excluded_plots:
            f.write("### Bugs Not Exposed By Either Configuration\n\n")
            for target, bug_name, plot_file in excluded_plots:
                f.write(f"#### {target.upper()} - {bug_name}\n\n")
                f.write(f"![KM Plot for {target} {bug_name}]({plot_file})\n\n")
                f.write("---\n\n")

    print(f"\n[*] Evaluation complete. Report saved to {report_path}")
    if records:
        print(
            f"    - USENIX Ribbon saved to {SURVIVAL_OUTPUT_DIR / 'fig_survival_ribbon.pdf'}"
        )
else:
    print("\n=== No data to report (no bugs found in dataset) ===")
