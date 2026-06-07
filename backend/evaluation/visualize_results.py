#!/usr/bin/env python3
"""
Generate evaluation visualizations from a pipeline report .txt file.

Produces:
  1. Per-vulnerability F1 heatmap  (Detection / Slither / Debate-LLM / Debate-Both)
  2. Overall metrics bar chart      (Precision / Recall / F1 across all four modes)

Usage:
    python visualize_results.py                          # latest report in reports/
    python visualize_results.py reports/evaluation_X.txt # specific report
"""

import re
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import seaborn as sns

# ── Report parsing ─────────────────────────────────────────────────────────────

SECTION_HEADERS = {
    "RAW DETECTOR ONLY":   "Detection (raw)",
    "RAW SLITHER ONLY":    "Slither (raw)",
    "DEBATE — LLM CONFIRMED": "Debate — LLM",
    "DEBATE — BOTH ENGINES":  "Debate — Both",
}

OVERALL_PATTERN = re.compile(
    r"Precision:\s+([\d.]+)%.*?Recall:\s+([\d.]+)%.*?F1-Score:\s+([\d.]+)",
    re.DOTALL,
)

ROW_PATTERN = re.compile(
    r"^\s{2}(\w[\w_\s]+?)\s{2,}(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)",
    re.MULTILINE,
)

CATEGORY_LABELS = {
    "reentrancy":              "Reentrancy",
    "arithmetic":              "Arithmetic",
    "unchecked_low_level_calls": "Unchecked LL Calls",
    "access_control":          "Access Control",
    "denial_of_service":       "Denial of Service",
    "bad_randomness":          "Bad Randomness",
    "time_manipulation":       "Time Manipulation",
    "front_running":           "Front Running",
    "short_address":           "Short Address",
    "short_addresses":         "Short Address",
    "other":                   "Other",
}

MODE_ORDER = ["Detection (raw)", "Slither (raw)", "Debate — LLM", "Debate — Both"]


def find_latest_report(reports_dir: Path) -> Path:
    reports = sorted(reports_dir.glob("evaluation_*.txt"))
    if not reports:
        raise FileNotFoundError(f"No evaluation reports found in {reports_dir}")
    return reports[-1]


def parse_report(path: Path) -> tuple[dict, dict]:
    """
    Returns:
      overall  — {mode: {"precision": float, "recall": float, "f1": float}}
      per_vuln — {mode: {category_label: {"tp": int, "fp": int, "fn": int,
                                          "precision": float, "recall": float, "f1": float}}}
    """
    text = path.read_text(encoding="utf-8")

    # Split into labelled sections
    sections: dict[str, str] = {}
    boundaries = []
    for header, label in SECTION_HEADERS.items():
        pos = text.find(header)
        if pos != -1:
            boundaries.append((pos, label))
    boundaries.sort()

    for idx, (pos, label) in enumerate(boundaries):
        end = boundaries[idx + 1][0] if idx + 1 < len(boundaries) else len(text)
        sections[label] = text[pos:end]

    overall: dict[str, dict] = {}
    per_vuln: dict[str, dict] = {}

    for label, section in sections.items():
        m = OVERALL_PATTERN.search(section)
        if m:
            overall[label] = {
                "precision": float(m.group(1)),
                "recall":    float(m.group(2)),
                "f1":        float(m.group(3)),
            }

        rows = {}
        for row in ROW_PATTERN.finditer(section):
            raw_cat = row.group(1).strip().lower().replace(" ", "_")
            cat_label = CATEGORY_LABELS.get(raw_cat, raw_cat.replace("_", " ").title())
            rows[cat_label] = {
                "tp":        int(row.group(2)),
                "fp":        int(row.group(3)),
                "fn":        int(row.group(4)),
                "precision": float(row.group(5)),
                "recall":    float(row.group(6)),
                "f1":        float(row.group(7)),
            }
        if rows:
            per_vuln[label] = rows

    return overall, per_vuln


# ── Plot 1: Per-vulnerability F1 heatmap ──────────────────────────────────────

def plot_heatmap(per_vuln: dict, out_path: Path, modes: list[str] | None = None) -> None:
    modes = modes or MODE_ORDER
    modes = [m for m in modes if m in per_vuln]

    # Collect all categories that appear in any mode
    all_cats: list[str] = []
    for m in modes:
        for cat in per_vuln[m]:
            if cat not in all_cats:
                all_cats.append(cat)

    # Build F1 matrix  (rows = modes, columns = categories)
    data = []
    for m in modes:
        row = [per_vuln[m].get(cat, {}).get("f1", 0.0) for cat in all_cats]
        data.append(row)

    df = pd.DataFrame(data, index=modes, columns=all_cats)

    fig, ax = plt.subplots(figsize=(max(14, len(all_cats) * 1.4), len(modes) * 1.6 + 1.5))

    sns.heatmap(
        df,
        ax=ax,
        annot=True,
        fmt=".2f",
        cmap="RdYlGn",
        vmin=0.0,
        vmax=1.0,
        linewidths=0.5,
        linecolor="white",
        annot_kws={"size": 11, "weight": "bold"},
        cbar_kws={"label": "F1-Score", "shrink": 0.6},
    )

    # Gold border on perfect scores
    for r, mode in enumerate(modes):
        for c, cat in enumerate(all_cats):
            val = per_vuln[mode].get(cat, {}).get("f1", 0.0)
            if val >= 1.0:
                ax.add_patch(plt.Rectangle(
                    (c, r), 1, 1,
                    fill=False, edgecolor="gold", linewidth=3, zorder=3,
                ))

    ax.set_title("Per-Vulnerability F1 Score — Multi-Agent Pipeline", fontsize=15, pad=14)
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", rotation=30, labelsize=10)
    ax.tick_params(axis="y", rotation=0,  labelsize=10)

    gold_patch = mpatches.Patch(edgecolor="gold", facecolor="none",
                                linewidth=2, label="Perfect score (F1 = 1.00)")
    ax.legend(handles=[gold_patch], loc="upper right",
              bbox_to_anchor=(1.0, -0.12), fontsize=9)

    plt.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ── Plot 2: Overall metrics bar chart ─────────────────────────────────────────

def plot_overall(overall: dict, out_path: Path, modes: list[str] | None = None) -> None:
    modes = modes or MODE_ORDER
    modes = [m for m in modes if m in overall]

    metrics = ["precision", "recall", "f1"]
    labels  = ["Precision (%)", "Recall (%)", "F1-Score (×100)"]
    colours = ["#5b9bd5", "#ed7d31", "#70ad47"]

    x     = np.arange(len(modes))
    width = 0.22
    fig, ax = plt.subplots(figsize=(10, 5))

    for i, (metric, label, colour) in enumerate(zip(metrics, labels, colours)):
        vals = [overall[m][metric] for m in modes]
        bars = ax.bar(x + (i - 1) * width, vals, width, label=label, color=colour, alpha=0.85)
        for bar, val in zip(bars, vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val:.1f}",
                ha="center", va="bottom", fontsize=8.5,
            )

    ax.set_title("Overall Metrics — Multi-Agent Pipeline", fontsize=14, pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(modes, fontsize=10)
    ax.set_ylabel("Score")
    ax.set_ylim(0, 100)
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    here = Path(__file__).parent

    if len(sys.argv) > 1:
        report_path = Path(sys.argv[1])
    else:
        report_path = find_latest_report(here / "reports")

    print(f"Parsing: {report_path.name}")
    overall, per_vuln = parse_report(report_path)

    print(f"Modes found: {list(overall.keys())}")
    print(f"Categories:  {list(next(iter(per_vuln.values())).keys())}")

    stem = report_path.stem
    out_dir = here / "reports"

    plot_heatmap(per_vuln, out_dir / f"{stem}_heatmap.png")
    plot_overall(overall,  out_dir / f"{stem}_overall.png")

    print("\nDone.")


if __name__ == "__main__":
    main()
