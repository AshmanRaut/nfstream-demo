from pathlib import Path
from statistics import median
from time import perf_counter
import csv
import struct

from nfstream import NFStreamer

PCAP_FILE = "benchmark.pcap"
REPEATS = 7


def count_pcap_packets(path):
    """Count packets in a classic PCAP file without extra dependencies."""
    with open(path, "rb") as file:
        header = file.read(24)

        if len(header) != 24:
            raise ValueError("PCAP global header is incomplete.")

        magic = header[:4]

        byte_orders = {
            b"\xd4\xc3\xb2\xa1": "<",  # Little-endian, microseconds
            b"\xa1\xb2\xc3\xd4": ">",  # Big-endian, microseconds
            b"\x4d\x3c\xb2\xa1": "<",  # Little-endian, nanoseconds
            b"\xa1\xb2\x3c\x4d": ">",  # Big-endian, nanoseconds
        }

        if magic not in byte_orders:
            raise ValueError(
                "Unsupported PCAP format. Expected a classic PCAP file."
            )

        byte_order = byte_orders[magic]
        packet_count = 0

        while True:
            record_header = file.read(16)

            if not record_header:
                break

            if len(record_header) != 16:
                raise ValueError("Incomplete packet record header.")

            captured_length = struct.unpack(
                byte_order + "I",
                record_header[8:12],
            )[0]

            packet_data = file.read(captured_length)

            if len(packet_data) != captured_length:
                raise ValueError("Incomplete packet data in PCAP.")

            packet_count += 1

    return packet_count


def run_nfstream(statistical_analysis, splt_analysis):
    """Run NFStream and return elapsed time and extracted-flow statistics."""
    start = perf_counter()

    streamer = NFStreamer(
        source=PCAP_FILE,
        n_dissections=0,
        statistical_analysis=statistical_analysis,
        splt_analysis=splt_analysis,
        n_meters=1,
    )

    flow_count = 0
    packets_in_flows = 0

    for flow in streamer:
        flow_count += 1
        packets_in_flows += flow.bidirectional_packets

    elapsed_seconds = perf_counter() - start

    return elapsed_seconds, flow_count, packets_in_flows


def main():
    if not Path(PCAP_FILE).is_file():
        raise FileNotFoundError(f"Cannot find {PCAP_FILE}")

    total_packets = count_pcap_packets(PCAP_FILE)

    configurations = [
        {
            "name": "baseline",
            "statistical_analysis": False,
            "splt_analysis": 0,
        },
        {
            "name": "extended",
            "statistical_analysis": True,
            "splt_analysis": 10,
        },
    ]

    results = []

    print("=== NFStream Feature-Extraction Benchmark ===")
    print(f"Capture: {PCAP_FILE}")
    print(f"PCAP packets: {total_packets}")
    print(f"Measured repetitions per configuration: {REPEATS}")
    print("Layer 7 dissection: disabled")
    print("Metering processes: 1")

    for config in configurations:
        print(f"\nTesting: {config['name']}")

        # One unmeasured warm-up run.
        run_nfstream(
            config["statistical_analysis"],
            config["splt_analysis"],
        )

        timings = []
        last_flow_count = 0
        last_flow_packets = 0

        for repetition in range(REPEATS):
            elapsed, flow_count, flow_packets = run_nfstream(
                config["statistical_analysis"],
                config["splt_analysis"],
            )

            timings.append(elapsed)
            last_flow_count = flow_count
            last_flow_packets = flow_packets

            print(
                f"  Run {repetition + 1}: "
                f"{elapsed * 1000:.3f} ms, "
                f"{flow_count} flows"
            )

        median_seconds = median(timings)

        result = {
            "configuration": config["name"],
            "pcap_packets": total_packets,
            "flow_count": last_flow_count,
            "packets_counted_in_flows": last_flow_packets,
            "median_time_ms": round(median_seconds * 1000, 3),
            "input_packets_per_second": round(
                total_packets / median_seconds, 2
            ),
        }

        results.append(result)

        print(
            f"  Median: {result['median_time_ms']:.3f} ms"
        )
        print(
            f"  Input packet throughput: "
            f"{result['input_packets_per_second']:.2f} packets/s"
        )

    baseline = next(r for r in results if r["configuration"] == "baseline")
    extended = next(r for r in results if r["configuration"] == "extended")

    baseline_ms = baseline["median_time_ms"]
    extended_ms = extended["median_time_ms"]

    if baseline_ms > 0:
        overhead_percent = (
            (extended_ms - baseline_ms) / baseline_ms
        ) * 100
        print(f"\nMeasured time change: {overhead_percent:+.2f}%")
    else:
        print("\nCould not calculate time change.")

    with open("results/feature_benchmark_results.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print("\nResults saved to feature_benchmark_results.csv")


if __name__ == "__main__":
    main()