"""Describe learned-model outputs; parsing success is not protocol validity."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader


def inspect(path, conditioning_ips):
    counts = Counter()
    times, sizes, flows, endpoints = [], [], set(), set()
    with PcapReader(str(path)) as reader:
        for packet in reader:
            counts["packets"] += 1
            times.append(float(packet.time))
            sizes.append(len(bytes(packet)))
            if IP not in packet:
                counts["non_ipv4"] += 1
                continue
            ip = packet[IP]
            counts["ipv4"] += 1
            endpoints.update((ip.src, ip.dst))
            if ip.version != 4 or ip.ihl < 5 or ip.len < ip.ihl * 4:
                counts["invalid_ipv4_header"] += 1
            if ip.len > len(bytes(ip)):
                counts["ipv4_length_exceeds_captured"] += 1
            if ip.frag or ip.flags.MF:
                counts["fragmented"] += 1
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            if transport is None:
                counts["no_tcp_udp"] += 1
                continue
            counts["tcp" if TCP in packet else "udp"] += 1
            if TCP in packet and packet[TCP].dataofs < 5:
                counts["invalid_tcp_header"] += 1
            flows.add((ip.proto, *sorted(((ip.src, transport.sport), (ip.dst, transport.dport)))))
    return dict(counts=counts, bytes=sum(sizes), unique_biflows=len(flows),
                nodes=len(endpoints), endpoints_in_conditioning=endpoints <= set(conditioning_ips),
                finite_timestamps=all(map(math.isfinite, times)),
                ordered_timestamps=all(a <= b for a, b in zip(times, times[1:])),
                duration_s=times[-1]-times[0] if times else 0,
                min_packet_bytes=min(sizes) if sizes else 0,
                max_packet_bytes=max(sizes) if sizes else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for path in sorted(args.batch.glob("*/generation.json")):
        metadata = json.loads(path.read_text())
        result = dict(directory=str(path.parent), **{key: metadata.get(key) for key in
                      ["status", "mode", "seed", "precision", "packets", "packet_target", "elapsed_s",
                       "load_elapsed_s", "model_calls", "generated_tokens", "error"]})
        pcap = path.with_name("generated.pcap")
        if not pcap.exists():
            pcap = path.with_name("partial.pcap")
        if pcap.exists():
            result["pcap_file"] = pcap.name
            result["pcap"] = inspect(pcap, metadata["conditioning_ips"])
        results.append(result)
    args.output.write_text(json.dumps(results, indent=2)+"\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
