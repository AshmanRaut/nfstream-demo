"""Create presentation-ready charts from the NFStream demonstration CSV files.

Run from the project directory:

    python visualize_results.py

The input and output directories can be changed when the CSVs are elsewhere:

    python visualize_results.py --input-dir "old results" --output-dir plots
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


FILES = {
    "flows": "network_flows.csv",
    "plugin": "network_flows_with_plugin.csv",
    "benchmark": "feature_benchmark_results.csv",
    "splt_summary": "splt_experiment_summary.csv",
    "splt_details": "splt_experiment_details.csv",
}

COLORS = {
    "blue": "#2563eb",
    "teal": "#0f766e",
    "orange": "#ea580c",
    "purple": "#7c3aed",
    "gray": "#64748b",
}


def read_csv(input_dir: Path, filename: str) -> pd.DataFrame | None:
    """Read one optional result file and report useful input errors."""
    path = input_dir / filename
    if not path.is_file():
        return None

    try:
        frame = pd.read_csv(path)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as error:
        raise RuntimeError(f"Could not read {path}: {error}") from error

    if frame.empty:
        print(f"Skipping empty file: {path}", file=sys.stderr)
        return None
    return frame


def numeric(frame: pd.DataFrame, column: str) -> pd.Series:
    """Return a numeric column, with invalid or missing values as NaN."""
    if column not in frame:
        return pd.Series(index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce")


def finish_figure(figure: plt.Figure, output_path: Path) -> None:
    """Apply consistent layout and save a figure."""
    figure.tight_layout()
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)
    print(f"Created {output_path}")


def add_empty_message(axis: plt.Axes, message: str) -> None:
    axis.text(
        0.5,
        0.5,
        message,
        ha="center",
        va="center",
        transform=axis.transAxes,
        color=COLORS["gray"],
    )
    axis.set_axis_off()


def plot_flow_features(frame: pd.DataFrame, output_dir: Path) -> Path:
    """Plot application mix and the relationship between flow size and duration."""
    figure, axes = plt.subplots(1, 2, figsize=(13, 5))
    figure.suptitle("NFStream: extracted network flows", fontsize=16, fontweight="bold")

    category_column = (
        "application_category_name"
        if "application_category_name" in frame
        else "application_name"
    )
    if category_column in frame:
        counts = frame[category_column].fillna("Unknown").astype(str).value_counts().head(10)
        counts.sort_values().plot.barh(ax=axes[0], color=COLORS["blue"])
        axes[0].set_title("Top application categories")
        axes[0].set_xlabel("Number of flows")
        axes[0].set_ylabel("")
    else:
        add_empty_message(axes[0], "No application labels in this CSV")

    duration = numeric(frame, "bidirectional_duration_ms")
    flow_bytes = numeric(frame, "bidirectional_bytes")
    valid = duration.notna() & flow_bytes.notna() & (duration >= 0) & (flow_bytes >= 0)
    if valid.any():
        axes[1].scatter(
            duration[valid],
            flow_bytes[valid],
            s=18,
            alpha=0.45,
            color=COLORS["teal"],
            edgecolors="none",
        )
        axes[1].set_xscale("log")
        axes[1].set_yscale("log")
        axes[1].set_title("Flow duration vs. bytes")
        axes[1].set_xlabel("Duration (ms, log scale)")
        axes[1].set_ylabel("Bidirectional bytes (log scale)")
        axes[1].grid(True, which="both", alpha=0.2)
    else:
        add_empty_message(axes[1], "Duration/byte columns unavailable")

    output_path = output_dir / "network_flows.png"
    finish_figure(figure, output_path)
    return output_path


def plot_plugin_features(frame: pd.DataFrame, output_dir: Path) -> Path:
    """Plot the custom TCP SYN count added by the NFStream plugin."""
    figure, axes = plt.subplots(1, 2, figsize=(12, 5))
    figure.suptitle("NFStream plugin: TCP SYN counter", fontsize=16, fontweight="bold")
    syn_counts = numeric(frame, "udps.tcp_syn_count").dropna()

    if syn_counts.empty:
        add_empty_message(axes[0], "No udps.tcp_syn_count column")
        add_empty_message(axes[1], "No SYN-count data")
    else:
        counts = syn_counts.value_counts().sort_index()
        axes[0].bar(counts.index.astype(str), counts.values, color=COLORS["orange"])
        axes[0].set_title("Flows by SYN count")
        axes[0].set_xlabel("TCP SYN packets in flow")
        axes[0].set_ylabel("Number of flows")
        axes[0].grid(axis="y", alpha=0.25)

        packet_counts = numeric(frame, "bidirectional_packets")
        valid = packet_counts.notna() & syn_counts.reindex(frame.index).notna()
        axes[1].scatter(
            packet_counts[valid],
            syn_counts.reindex(frame.index)[valid],
            s=20,
            alpha=0.5,
            color=COLORS["orange"],
            edgecolors="none",
        )
        axes[1].set_title("SYN count vs. total flow packets")
        axes[1].set_xlabel("Bidirectional packets")
        axes[1].set_ylabel("TCP SYN count")
        axes[1].grid(alpha=0.25)

    output_path = output_dir / "network_flows_with_plugin.png"
    finish_figure(figure, output_path)
    return output_path


def plot_benchmark(frame: pd.DataFrame, output_dir: Path) -> Path:
    """Compare median extraction time and input throughput."""
    figure, axes = plt.subplots(1, 2, figsize=(12, 5))
    figure.suptitle("NFStream feature-extraction benchmark", fontsize=16, fontweight="bold")
    labels = frame["configuration"].astype(str) if "configuration" in frame else pd.Series(dtype=str)

    if labels.empty:
        add_empty_message(axes[0], "No benchmark configurations")
        add_empty_message(axes[1], "No benchmark configurations")
    else:
        timings = numeric(frame, "median_time_ms")
        throughput = numeric(frame, "input_packets_per_second")
        x_positions = range(len(labels))
        axes[0].bar(x_positions, timings, color=COLORS["purple"])
        axes[0].set_title("Median processing time")
        axes[0].set_ylabel("Milliseconds (lower is faster)")
        axes[0].set_xticks(list(x_positions), labels, rotation=20, ha="right")
        axes[0].grid(axis="y", alpha=0.25)
        for index, value in enumerate(timings):
            if pd.notna(value):
                axes[0].text(index, value, f"{value:.2f}", ha="center", va="bottom")

        axes[1].bar(x_positions, throughput, color=COLORS["teal"])
        axes[1].set_title("Input packet throughput")
        axes[1].set_ylabel("Packets per second (higher is better)")
        axes[1].set_xticks(list(x_positions), labels, rotation=20, ha="right")
        axes[1].grid(axis="y", alpha=0.25)
        for index, value in enumerate(throughput):
            if pd.notna(value):
                axes[1].text(index, value, f"{value:,.0f}", ha="center", va="bottom")

    output_path = output_dir / "feature_benchmark_results.png"
    finish_figure(figure, output_path)
    return output_path


def plot_splt_summary(frame: pd.DataFrame, output_dir: Path) -> Path:
    """Show how the early-packet limit affects information and runtime."""
    figure, axes = plt.subplots(1, 2, figsize=(12, 5))
    figure.suptitle("NFStream SPLT early-packet experiment", fontsize=16, fontweight="bold")

    limit = numeric(frame, "splt_packet_limit")
    average_packets = numeric(frame, "average_splt_packets_per_flow")
    processing_time = numeric(frame, "median_processing_time_ms")
    valid = limit.notna()

    if not valid.any():
        add_empty_message(axes[0], "No SPLT summary data")
        add_empty_message(axes[1], "No SPLT summary data")
    else:
        axes[0].plot(
            limit[valid],
            average_packets[valid],
            marker="o",
            linewidth=2,
            color=COLORS["blue"],
        )
        axes[0].plot(
            limit[valid],
            limit[valid],
            linestyle="--",
            color=COLORS["gray"],
            label="configured limit",
        )
        axes[0].set_title("Early-packet features per flow")
        axes[0].set_xlabel("SPLT packet limit")
        axes[0].set_ylabel("Average extracted packets per flow")
        axes[0].legend()
        axes[0].grid(alpha=0.25)

        axes[1].plot(
            limit[valid],
            processing_time[valid],
            marker="o",
            linewidth=2,
            color=COLORS["orange"],
        )
        axes[1].set_title("Processing time")
        axes[1].set_xlabel("SPLT packet limit")
        axes[1].set_ylabel("Median time (ms)")
        axes[1].grid(alpha=0.25)

    output_path = output_dir / "splt_experiment_summary.png"
    finish_figure(figure, output_path)
    return output_path


def plot_splt_details(frame: pd.DataFrame, output_dir: Path) -> Path:
    """Show the distribution of extracted early-packet counts per flow."""
    figure, axis = plt.subplots(figsize=(9, 5))
    figure.suptitle("SPLT details: packets captured per flow", fontsize=16, fontweight="bold")
    limit = numeric(frame, "splt_packet_limit")
    packet_sizes = numeric(frame, "splt_packet_sizes")
    valid = limit.notna() & packet_sizes.notna()

    if not valid.any():
        add_empty_message(axis, "No SPLT detail data")
    else:
        detail_frame = pd.DataFrame(
            {"limit": limit[valid], "packet_sizes": packet_sizes[valid]}
        )
        groups = [
            group["packet_sizes"].to_numpy()
            for _, group in detail_frame.groupby("limit", sort=True)
        ]
        labels = [
            str(int(value))
            for value in sorted(detail_frame["limit"].unique())
        ]
        axis.boxplot(groups, tick_labels=labels, patch_artist=True)
        for box in axis.artists:
            box.set_facecolor(COLORS["blue"])
            box.set_alpha(0.65)
        axis.set_title("Distribution by configured SPLT limit")
        axis.set_xlabel("SPLT packet limit")
        axis.set_ylabel("Extracted packet-size values per flow")
        axis.grid(axis="y", alpha=0.25)

    output_path = output_dir / "splt_experiment_details.png"
    finish_figure(figure, output_path)
    return output_path


def build_dashboard(
    frames: dict[str, pd.DataFrame],
    output_dir: Path,
) -> Path:
    """Create a compact contact sheet linking the available visual summaries."""
    figure, axes = plt.subplots(2, 3, figsize=(18, 9))
    figure.suptitle("NFStream demonstration results", fontsize=18, fontweight="bold")
    panels = [
        ("flows", "Flow extraction", "network_flows.png"),
        ("plugin", "TCP SYN plugin", "network_flows_with_plugin.png"),
        ("benchmark", "Feature benchmark", "feature_benchmark_results.png"),
        ("splt_summary", "SPLT experiment", "splt_experiment_summary.png"),
        ("splt_details", "SPLT details", "splt_experiment_details.png"),
    ]

    for axis, (key, title, filename) in zip(axes.flat, panels):
        if key not in frames:
            add_empty_message(axis, f"{title}\n(no CSV found)")
            continue
        image = plt.imread(output_dir / filename)
        axis.imshow(image)
        axis.set_title(title)
        axis.axis("off")

    output_path = output_dir / "dashboard.png"
    finish_figure(figure, output_path)
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Turn NFStream result CSV files into PNG visualizations."
    )
    project_dir = Path(__file__).resolve().parent
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=project_dir / "results",
        help="Directory containing result CSV files (default: results).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_dir / "visualizations",
        help="Directory for generated PNG files (default: visualizations).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.expanduser()
    output_dir = args.output_dir.expanduser()

    if not input_dir.is_dir():
        print(f"Input directory does not exist: {input_dir}", file=sys.stderr)
        return 2

    frames = {
        key: frame
        for key, filename in FILES.items()
        if (frame := read_csv(input_dir, filename)) is not None
    }
    if not frames:
        print(
            f"No non-empty result CSV files found in {input_dir}. "
            "Run one of the demos first.",
            file=sys.stderr,
        )
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    plotters = {
        "flows": plot_flow_features,
        "plugin": plot_plugin_features,
        "benchmark": plot_benchmark,
        "splt_summary": plot_splt_summary,
        "splt_details": plot_splt_details,
    }
    generated = []
    for key, plotter in plotters.items():
        if key in frames:
            output_path = plotter(frames[key], output_dir)
            generated.append(output_path)

    build_dashboard(frames, output_dir)
    print(f"Generated {len(generated) + 1} visualization(s) in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
