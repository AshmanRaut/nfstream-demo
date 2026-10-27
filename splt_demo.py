from nfstream import NFStreamer

PCAP_FILE = "sample.pcap"
N_PACKETS = 10

# Extract early flow features from the first 10 packets.
streamer = NFStreamer(
    source=PCAP_FILE,
    n_dissections=0,
    splt_analysis=N_PACKETS,
)

print("=== NFStream: Early Traffic Analysis (SPLT) ===")

flow_count = 0

for flow in streamer:
    flow_count += 1

    print(f"\nFlow {flow_count}")
    print(f"Source:      {flow.src_ip}:{flow.src_port}")
    print(f"Destination: {flow.dst_ip}:{flow.dst_port}")
    print(f"Protocol:    {flow.protocol}")
    print(f"Total packets in flow: {flow.bidirectional_packets}")

    print("\nFirst-packet sequence:")

    print(f"Directions:       {flow.splt_direction}")
    print(f"Packet sizes:     {flow.splt_ps}")
    print(f"Inter-arrival ms: {flow.splt_piat_ms}")

print(f"\nTotal flows analysed: {flow_count}")