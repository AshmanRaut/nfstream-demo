from nfstream import NFStreamer
from pathlib import Path

PCAP_FILE = "sample.pcap"

if not Path(PCAP_FILE).exists():
    raise FileNotFoundError(
        f"Cannot find {PCAP_FILE}. Place it in this directory."
    )

print("Starting NFStream analysis...")

streamer = NFStreamer(
    source=PCAP_FILE,
    statistical_analysis=True,
    splt_analysis=10
)

df = streamer.to_pandas()

if df.empty:
    print("No network flows were extracted.")
else:
    print("\n=== NFStream Results ===")
    print(f"Total flows extracted: {len(df)}")

    columns = [
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "bidirectional_packets",
        "bidirectional_bytes",
        "bidirectional_duration_ms",
    ]

    available_columns = [
        column for column in columns if column in df.columns
    ]

    print("\n=== Flow Summary ===")
    print(df[available_columns].head(10).to_string(index=False))

    df.to_csv("results/network_flows.csv", index=False)

    print("\nSaved all extracted features to network_flows.csv")

    if "application_name" in df.columns:
        print("\n=== Application Distribution ===")
        print(df["application_name"].value_counts().head(10))