"""Select existing windows by structure/duration, then export matched controls."""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tdsc_route_probe import read_records, shuffle_same_length, shift_flows
from scapy.all import RawPcapReader, RawPcapWriter


def describe(path):
    records, info = read_records(path, 20000)
    peers = defaultdict(set)
    for _, _, key, _ in records:
        a, b = key[1][0], key[2][0]
        peers[a].add(b)
        peers[b].add(a)
    info.update(path=str(path.resolve()), shared_nodes=sum(len(v) >= 2 for v in peers.values()),
                max_peers=max(map(len, peers.values()), default=0))
    return info


def export(path, destination, seeds):
    records, info = read_records(path, 20000)
    with RawPcapReader(str(path)) as reader:
        linktype = reader.linktype
        raw = list(reader)
    # All variants use the same eligible IPv4 TCP/UDP packets.
    variants = [("original", None, records)]
    for seed in seeds:
        variants.extend([
            ("length_shuffle", seed, shuffle_same_length(records, seed)),
            ("flow_shift", seed, shift_flows(records, seed)),
            ("peer_shift", seed, shift_flows(records, seed, by_peer=True)),
        ])
    manifest = []
    for kind, seed, sample in variants:
        name = kind if seed is None else f"{kind}_s{seed}"
        out = destination / f"{name}.pcap"
        out.parent.mkdir(parents=True, exist_ok=True)
        # Integer nanoseconds and a common fixed epoch avoid float epoch loss.
        with RawPcapWriter(str(out), linktype=linktype, nano=True) as writer:
            writer.write_header(None)
            for t, _, _, index in sample:
                payload, metadata = raw[index]
                ns = round(t * 1_000_000_000)
                sec, nano = divmod(ns, 1_000_000_000)
                writer.write_packet(payload, sec=1600000000 + sec, usec=nano,
                                    caplen=metadata.caplen, wirelen=metadata.wirelen)
        manifest.append(dict(path=str(out.resolve()), source=str(path.resolve()),
                             scenario=destination.name, variant=kind, seed=seed, **info))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2])
    parser.add_argument("--count", type=int, default=4)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    inventory = [describe(p) for p in sorted(args.data.glob("*.pcap"))]
    with (args.output / "window_inventory.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(inventory[0]))
        writer.writeheader()
        writer.writerows(inventory)
    eligible = [i for i in inventory if i["shared_nodes"] and i["distinct_biflows"] >= 3]
    eligible.sort(key=lambda i: (-i["duration_s"], -i["distinct_biflows"], i["path"]))
    chosen = []
    groups = set()
    for item in eligible:
        # Distinct prefix is an operational grouping, not a verified capture ID.
        stem = Path(item["path"]).stem
        group = "_".join(stem.split("_")[:3])
        if group in groups:
            continue
        chosen.append(item)
        groups.add(group)
        if len(chosen) == args.count:
            break
    manifest = []
    for index, item in enumerate(chosen):
        manifest.extend(export(Path(item["path"]), args.output / f"scenario_{index}", args.seeds))
    (args.output / "selection.json").write_text(json.dumps({
        "command": sys.argv, "selection": "shared_nodes >= 1, biflows >= 3; descending duration; distinct filename prefix",
        "split": "development only; original capture IDs not verified; no held-out claim",
        "selected": chosen, "variants": manifest,
        "notes": ["all variants contain identical eligible packet bytes", "timestamp epoch normalized equally",
                  "packet-level shuffle breaks flow order; grouped shifts change aggregate timing"]}, indent=2) + "\n")
    print(json.dumps({"scanned": len(inventory), "eligible": len(eligible), "selected": chosen,
                      "exported": len(manifest)}, indent=2))


if __name__ == "__main__":
    main()
