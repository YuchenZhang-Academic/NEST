"""Sequential, offline Suricata capacity experiment. No live capture or rules."""
import argparse
from collections import Counter
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def flatten(value, prefix=""):
    result = {}
    for key, child in value.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(child, dict):
            result.update(flatten(child, name))
        else:
            result[name] = child
    return result


def metrics(path):
    latest = None
    count = packets = classified = 0
    keys = Counter()
    reasons = Counter()
    for line in path.open():
        event = json.loads(line)
        if event["event_type"] == "stats":
            latest = flatten(event["stats"])
        elif event["event_type"] == "flow":
            count += 1
            ends = sorted(((event["src_ip"], event.get("src_port", 0)),
                           (event["dest_ip"], event.get("dest_port", 0))))
            keys[(event["proto"], *ends)] += 1
            flow = event["flow"]
            packets += flow["pkts_toserver"] + flow["pkts_toclient"]
            reasons[flow["reason"]] += 1
            classified += event.get("app_proto", "failed") not in ("failed", "unknown")
    if latest is None:
        raise RuntimeError(f"No terminal stats in {path}")
    selected = {key: latest.get(key, 0) for key in [
        "decoder.pkts", "decoder.invalid", "flow.memcap", "flow.get_used",
        "flow.get_used_failed", "flow.emerg_mode_entered", "flow.memuse",
        "flow.wrk.flows_evicted", "flow.wrk.flows_evicted_needs_work",
        "tcp.no_flow", "tcp.invalid_checksum", "tcp.reassembly_gap",
        "tcp.ssn_memcap_drop", "tcp.segment_memcap_drop"]}
    selected.update(flow_records=count, unique_exported_biflows=len(keys),
                    extra_flow_records=count-len(keys), exported_packet_count=packets,
                    classified_flow_records=classified,
                    export_accounting_gap=latest["decoder.pkts"]-packets,
                    app_transactions=sum(v for k, v in latest.items() if k.startswith("app_layer.tx.")))
    return selected, latest, dict(reasons)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selection", type=Path, required=True)
    p.add_argument("--engine-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--memcaps", nargs="+", type=int, default=[32768, 65536, 131072, 1048576])
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--idle", type=int, default=60)
    p.add_argument("--checksums", choices=["yes", "no"], default="yes")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.engine_root.resolve() / "usr/bin/suricata"
    env = dict(os.environ, LD_LIBRARY_PATH=str(args.engine_root.resolve() / "usr/lib/x86_64-linux-gnu"))
    version = subprocess.check_output([str(binary), "-V"], env=env, text=True).strip()
    selection = json.loads(args.selection.read_text())
    config = Path(__file__).with_name("suricata.yaml")
    rows = []
    consecutive_failures = 0
    with (args.output / "runs.jsonl").open("w") as record:
        for item in selection["variants"]:
            # Resolve packaged PCAPs relative to selection.json on any machine.
            pcap = args.selection.resolve().parent / item["scenario"] / Path(item["path"]).name
            for cap in args.memcaps:
                for repeat in range(args.repeats):
                    run_id = f'{item["scenario"]}/{pcap.stem}/cap{cap}_r{repeat}'
                    destination = args.output / run_id
                    destination.mkdir(parents=True)
                    command = [str(binary), "-c", str(config.resolve()), "-r", str(pcap),
                               "-l", str(destination.resolve()), "--runmode", "single", "--disable-detection",
                               "--set", f"flow.memcap={cap}",
                               "--set", f"stream.checksum-validation={args.checksums}"]
                    for proto in ["default", "tcp", "udp", "icmp"]:
                        for state in ["new", "established", "emergency-new", "emergency-established"]:
                            command.extend(["--set", f"flow-timeouts.{proto}.{state}={args.idle}"])
                    start = time.monotonic()
                    with (destination / "console.log").open("w") as log:
                        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=60)
                    details = dict(command=command, engine=version, elapsed_s=time.monotonic()-start,
                                   returncode=result.returncode, scenario=item["scenario"], variant=item["variant"],
                                   seed=item["seed"], memcap=cap, repeat=repeat, idle=args.idle,
                                   checksum_validation=args.checksums, run_id=run_id)
                    if result.returncode:
                        record.write(json.dumps(details)+"\n")
                        record.flush()
                        rows.append({k: details[k] for k in ["scenario", "variant", "seed", "memcap", "repeat", "idle", "returncode"]})
                        consecutive_failures += 1
                        if consecutive_failures >= 3:
                            raise RuntimeError("Three consecutive engine failures; inspect saved logs before continuing")
                        continue
                    consecutive_failures = 0
                    values, native, reasons = metrics(destination / "eve.json")
                    details.update(metrics=values, native_stats=native, flow_end_reasons=reasons)
                    record.write(json.dumps(details)+"\n")
                    record.flush()
                    rows.append({k: details[k] for k in ["scenario", "variant", "seed", "memcap", "repeat", "idle", "returncode"]} | values)
            print(f'completed {item["scenario"]} {pcap.stem}', flush=True)
    with (args.output / "metrics.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for row in rows for k in row)))
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "experiment.json").write_text(json.dumps(dict(
        command=sys.argv, engine=version, runs=len(rows), failures=sum(r["returncode"] != 0 for r in rows), memcaps=args.memcaps, idle=args.idle,
        repeats=args.repeats, checksum_validation=args.checksums,
        mode="offline single packet worker, detection disabled, midstream enabled",
        limitations=["no attack labels or detection accuracy", "export accounting gap is not packet loss",
                     "management threads and flow hash seed not controlled; repeat variability retained",
                     "development windows; filename prefixes do not certify independent source captures"]), indent=2)+"\n")
    print(f"runs={len(rows)} output={args.output}")


if __name__ == "__main__":
    main()
