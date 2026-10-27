from pathlib import Path

from nfstream import NFPlugin, NFStreamer


class TCPSynCounter(NFPlugin):
    """Count TCP SYN packets in each network flow."""

    def on_init(self, packet, flow):
        # Initialise our custom feature for each new flow.
        flow.udps.tcp_syn_count = int(packet.syn)

    def on_update(self, packet, flow):
        # Increment the counter whenever a SYN packet appears.
        if packet.syn:
            flow.udps.tcp_syn_count += 1


pcap_file = "sample.pcap"

if not Path(pcap_file).exists():
    raise FileNotFoundError(f"Cannot find {pcap_file}")

streamer = NFStreamer(
    source=pcap_file,
    udps=TCPSynCounter(),
    statistical_analysis=True,
)

df = streamer.to_pandas()

if df.empty:
    print("No flows found.")
else:
    columns = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "bidirectional_packets",
        "bidirectional_bytes",
        "udps.tcp_syn_count",
    ]

    # Print the fields actually exported by this NFStream version.
    available = [column for column in columns if column in df.columns]

    print("\n=== NFStream with Custom TCP SYN Counter ===")
    print(df[available].to_string(index=False))

    df.to_csv("results/network_flows_with_plugin.csv", index=False)
    print("\nSaved results to network_flows_with_plugin.csv")