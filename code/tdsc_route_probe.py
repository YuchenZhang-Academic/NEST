"""Bounded offline route-selection probe; this is not a TCP/firewall emulator."""

import argparse
from collections import Counter, defaultdict
import heapq
import json
import math
from pathlib import Path
import platform
import random
import sys
import time

import scapy
from scapy.all import IP, TCP, UDP, PcapReader


PATTERNS = ["*Active*", "*tor_browsing*", "*P2P*", "*doh*", "*FTP_transfer*", "*TCPFlood*"]


def read_records(path, limit):
    records = []
    excluded = Counter()
    read_count = 0
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            if index >= limit:
                break
            read_count += 1
            if IP not in packet:
                excluded["non_ipv4"] += 1
                continue
            ip = packet[IP]
            if ip.frag or ip.flags.MF:
                excluded["ipv4_fragment"] += 1
                continue
            transport = ip.payload
            if not isinstance(transport, (TCP, UDP)):
                excluded["non_tcp_udp"] += 1
                continue
            timestamp = float(packet.time)
            if not math.isfinite(timestamp):
                excluded["nonfinite_time"] += 1
                continue
            ends = sorted(((ip.src, transport.sport), (ip.dst, transport.dport)))
            key = (ip.proto, ends[0], ends[1])
            records.append((timestamp, len(packet), key, index))
    ordered = sorted(records, key=lambda r: (r[0], r[3]))
    if ordered:
        origin = ordered[0][0]
        ordered = [(t - origin, size, key, index) for t, size, key, index in ordered]
    return ordered, {"read_packets": read_count, "eligible_packets": len(ordered),
                     "excluded": dict(excluded), "distinct_biflows": len({r[2] for r in ordered}),
                     "nodes": len({end[0] for r in ordered for end in r[2][1:]}),
                     "ip_pairs": len({tuple(sorted((r[2][1][0], r[2][2][0]))) for r in ordered}),
                     "duration_s": ordered[-1][0] if ordered else 0}


def shuffle_same_length(records, seed):
    """Keep each packet intact and keep the exact global (time, length) multiset."""
    groups = defaultdict(list)
    for record in records:
        groups[record[1]].append(record)
    rng = random.Random(seed)
    output = []
    for group in groups.values():
        times = [r[0] for r in group]
        rng.shuffle(times)
        output.extend((t, r[1], r[2], r[3]) for t, r in zip(times, group))
    assert Counter((r[0], r[1]) for r in output) == Counter((r[0], r[1]) for r in records)
    assert Counter(r[1:] for r in output) == Counter(r[1:] for r in records)
    return sorted(output, key=lambda r: (r[0], r[3]))


def shift_flows(records, seed, by_peer=False):
    """Preserve each biflow's packet order and relative timing, change its start.

    Each flow fits inside the original observation horizon. Aggregate packet/byte
    timing is NOT preserved by this second null. No circular wrap or packet loss.
    """
    if not records:
        return []
    groups = defaultdict(list)
    for record in records:
        key = tuple(sorted((record[2][1][0], record[2][2][0]))) if by_peer else record[2]
        groups[key].append(record)
    rng = random.Random(seed)
    horizon = records[-1][0]
    output = []
    for group in groups.values():
        duration = group[-1][0] - group[0][0]
        start = rng.uniform(0., max(0., horizon - duration))
        shifted = [(start + (r[0] - group[0][0]), r[1], r[2], r[3]) for r in group]
        assert all(math.isclose(a[0] - group[0][0], b[0] - shifted[0][0], abs_tol=1e-9)
                   for a, b in zip(group, shifted))
        output.extend(shifted)
    assert Counter(r[1:] for r in output) == Counter(r[1:] for r in records)
    return sorted(output, key=lambda r: (r[0], r[3]))


def flow_table(records, timeout, capacity=None):
    """Bidirectional 5-tuple cache. Expire at last_seen + timeout <= now.

    No TCP state, active timeout, replacement, payload inspection, or CPU model.
    On a full table, an unseen key's packet is untracked; existing keys refresh.
    """
    active = {}
    expiry = []
    peak = admissions = untracked = 0
    for serial, (now, _, key, _) in enumerate(records):
        while expiry and expiry[0][0] <= now:
            deadline, _, expired_key = heapq.heappop(expiry)
            if active.get(expired_key) == deadline:
                del active[expired_key]
        if key not in active:
            if capacity is not None and len(active) >= capacity:
                untracked += 1
                continue
            admissions += 1
        deadline = now + timeout
        active[key] = deadline
        heapq.heappush(expiry, (deadline, serial, key))
        peak = max(peak, len(active))
    return {"peak_entries": peak, "admissions": admissions,
            "untracked_packets": untracked}


def check_model():
    a, b = (6, ("a", 1), ("b", 2)), (17, ("c", 1), ("d", 2))
    records = [(0., 60, a, 0), (0.5, 60, b, 1), (1., 60, a, 2)]
    assert flow_table(records, 0.5) == dict(peak_entries=1, admissions=3, untracked_packets=0)
    assert flow_table(records, 2.) == dict(peak_entries=2, admissions=2, untracked_packets=0)
    assert flow_table(records, 2., 1) == dict(peak_entries=1, admissions=1, untracked_packets=1)
    assert flow_table([], 1.) == dict(peak_entries=0, admissions=0, untracked_packets=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--real-dir", type=Path, required=True)
    parser.add_argument("--generated-dir", type=Path)
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    parser.add_argument("--timeouts", type=float, nargs="+", default=[0.01, 0.1, 1., 10.])
    parser.add_argument("--real-caps", type=int, nargs="+", default=[100, 1000])
    parser.add_argument("--flow-shift", action="store_true")
    parser.add_argument("--peer-shift", action="store_true")
    parser.add_argument("--patterns", nargs="+", default=PATTERNS)
    parser.add_argument("--skip-legacy", action="store_true")
    args = parser.parse_args()
    if not args.skip_legacy and args.generated_dir is None:
        parser.error("--generated-dir is required unless --skip-legacy is set")
    if any(t <= 0 or not math.isfinite(t) for t in args.timeouts):
        parser.error("timeouts must be finite and positive")
    started = time.monotonic()
    check_model()
    rows, inputs = [], []
    for pattern in args.patterns:
        name = sorted(args.real_dir.glob(pattern + ".pcap"))[0].name
        # The existing batch generator truncates names at the first dot.
        generated_name = name.split(".")[0] + ".pcap"
        cases = [("real", args.real_dir / name, limit) for limit in args.real_caps]
        if not args.skip_legacy:
            cases.append(("legacy_generated", args.generated_dir / generated_name, 100))
        for source, path, limit in cases:
            records, metadata = read_records(path, limit)
            item = {"path": str(path.resolve()), "source": source,
                    "packet_cap": limit, **metadata}
            inputs.append(item)
            variants = [("original", None, records)]
            variants.extend(("same_length_time_shuffle", s, shuffle_same_length(records, s))
                            for s in args.seeds)
            if args.flow_shift:
                variants.extend(("whole_flow_shift", s, shift_flows(records, s)) for s in args.seeds)
            if args.peer_shift:
                variants.extend(("whole_peer_shift", s, shift_flows(records, s, by_peer=True))
                                for s in args.seeds)
            for variant, seed, sample in variants:
                old_times = {r[3]: r[0] for r in records}
                moved = sum(r[0] != old_times[r[3]] for r in sample)
                for timeout in args.timeouts:
                    rows.append({"path": item["path"], "source": source, "packet_cap": limit,
                                 "variant": variant,
                                 "seed": seed, "timeout_s": timeout,
                                 "moved_time_fraction": moved / len(sample) if sample else 0,
                                 **flow_table(sample, timeout),
                                 "capacity_tests": {str(c): flow_table(sample, timeout, c)
                                                    for c in [8, 32, 128]}})
    report = {"task": "NEST | TDSC extension", "stage": "exploratory route selection",
              "command": sys.argv, "python": platform.python_version(), "scapy": scapy.__version__,
              "seed_list": args.seeds, "timeouts_s": args.timeouts, "real_caps": args.real_caps,
              "selection": "lexicographically first file for each predefined pattern",
              "patterns": args.patterns, "split": "exploratory only; no training or held-out claim",
              "model": "empty bidirectional 5-tuple cache; idle expiry <= t; drop-new-entry when full",
              "invariants": {"same_length_time_shuffle": "exact (time, length) and packet identity/flow-key multisets",
                             "whole_flow_shift": "packet identity/flow-key multiset; within-flow order and IATs",
                             "whole_peer_shift": "packet identity/flow-key multiset; within-IP-pair order and timing"},
              "limitations": ["not a real security engine", "no TCP handshake or sequence semantics",
                              "file prefixes are left/right censored", "legacy generation provenance not audited",
                              "shuffle breaks within-flow order and is only a diagnostic null"],
              "analytic_checks": "passed", "inputs": inputs, "rows": rows,
              "elapsed_s": time.monotonic() - started}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as f:
        json.dump(report, f, indent=2, allow_nan=False)
        f.write("\n")
    print(f"analytic_checks=passed inputs={len(inputs)} metric_rows={len(rows)} elapsed_s={report['elapsed_s']:.3f}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
