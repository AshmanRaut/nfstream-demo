from pathlib import Path
from time import perf_counter
from statistics import median
import csv

from nfstream import NFStreamer

PCAP_FILE = "sample.pcap"

# Number of early packets to analyze in each configuration.
SPLT_CONFIGURATIONS = [1, 3, 5, 10, 20]

# Repeat each configuration to reduce the influence of timing noise.
REPEATS = 5


def run_experiment(packet_limit):
    """Analyze the capture and measure SPLT extraction."""

    start = perf_counter()

    streamer = NFStreamer(
        source=PCAP_FILE,
        n_dissections=0,
        splt_analysis=packet_limit,
    )

    flow_results = []

    for flow in streamer:
        flow_results.append({
            "flow_id": flow.id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "total_flow_packets": flow.bidirectional_packets,
            "splt_directions": len(flow.splt_direction),
            "splt_packet_sizes": len(flow.splt_ps),
            "splt_inter_arrival_times": len(flow.splt_piat_ms),
        })

    elapsed_ms = (perf_counter() - start) * 1000

    return flow_results, elapsed_ms


def main():
    if not Path(PCAP_FILE).exists():
        raise FileNotFoundError(
            f"Cannot find {PCAP_FILE}. "
            "Place the capture in the current directory."
        )

    summary_rows = []
    detail_rows = []

    print("=== NFStream SPLT Experiment ===")
    print(f"Capture: {PCAP_FILE}")
    print(f"Repeats per configuration: {REPEATS}")

    for packet_limit in SPLT_CONFIGURATIONS:
        timings = []
        latest_flows = []

        for _ in range(REPEATS):
            flows, elapsed_ms = run_experiment(packet_limit)
            timings.append(elapsed_ms)
            latest_flows = flows

        flow_count = len(latest_flows)

        if flow_count:
            average_packets = sum(
                row["splt_packet_sizes"] for row in latest_flows
            ) / flow_count
        else:
            average_packets = 0

        median_ms = median(timings)

        summary_rows.append({
            "splt_packet_limit": packet_limit,
            "flow_count": flow_count,
            "average_splt_packets_per_flow": round(average_packets, 2),
            "median_processing_time_ms": round(median_ms, 3),
        })

        for row in latest_flows:
            detail_rows.append({
                "splt_packet_limit": packet_limit,
                **row,
            })

        print(
            f"SPLT limit={packet_limit:2d} | "
            f"flows={flow_count:2d} | "
            f"average SPLT packets/flow={average_packets:.2f} | "
            f"median time={median_ms:.3f} ms"
        )

    with open("results/splt_experiment_summary.csv", "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "splt_packet_limit",
                "flow_count",
                "average_splt_packets_per_flow",
                "median_processing_time_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    with open("results/splt_experiment_details.csv", "w", newline="") as file:
        fieldnames = [
            "splt_packet_limit",
            "flow_id",
            "src_ip",
            "dst_ip",
            "total_flow_packets",
            "splt_directions",
            "splt_packet_sizes",
            "splt_inter_arrival_times",
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(detail_rows)

    print("\nSaved:")
    print("- splt_experiment_summary.csv")
    print("- splt_experiment_details.csv")


if __name__ == "__main__":
    main()