"""Export native-engine summaries and figures; never infer IDS accuracy."""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

METRICS = ["flow.emerg_mode_entered", "flow.get_used", "extra_flow_records",
           "export_accounting_gap", "app_transactions", "tcp.reassembly_gap"]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runs", type=Path, nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    groups = defaultdict(list)
    failures = []
    for directory in args.runs:
        for line in (directory / "runs.jsonl").open():
            run = json.loads(line)
            if run["returncode"]:
                failures.append(dict(directory=str(directory), run_id=run["run_id"], returncode=run["returncode"]))
                continue
            key = (run["scenario"], run["idle"], run["variant"], run["seed"], run["memcap"])
            groups[key].append(run)
    seed_rows = []
    for key, runs in groups.items():
        row = dict(zip(["scenario", "idle", "variant", "seed", "memcap"], key))
        row["engine_repeats"] = len(runs)
        for metric in METRICS:
            values = [r["metrics"][metric] for r in runs]
            row[metric] = statistics.median(values)
            row[metric+"_min"] = min(values)
            row[metric+"_max"] = max(values)
        seed_rows.append(row)
    buckets = defaultdict(list)
    for row in seed_rows:
        buckets[(row["scenario"], row["idle"], row["variant"], row["memcap"])].append(row)
    summary = []
    for key, rows in sorted(buckets.items()):
        item = dict(zip(["scenario", "idle", "variant", "memcap"], key))
        item["variant_seeds"] = len(rows)
        for metric in METRICS:
            item[metric] = statistics.median(r[metric] for r in rows)
            item[metric+"_min"] = min(r[metric+"_min"] for r in rows)
            item[metric+"_max"] = max(r[metric+"_max"] for r in rows)
        summary.append(item)
    for name, rows in [("by_seed.csv", seed_rows), ("summary.csv", summary)]:
        with (args.output/name).open("w") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    (args.output/"failures.json").write_text(json.dumps(failures, indent=2)+"\n")
    labels = {"original": "Original", "length_shuffle": "Length-stratified shuffle",
              "flow_shift": "Flow shift", "peer_shift": "Peer-pair shift"}
    scenarios = sorted({r["scenario"] for r in summary})
    idles = sorted({r["idle"] for r in summary})
    for metric, ylabel in [("export_accounting_gap", "Flow-export accounting gap\n(packets)"),
                           ("flow.get_used", "Suricata flow.get_used counter"),
                           ("app_transactions", "Application transactions reported")]:
        fig, axes = plt.subplots(len(idles), len(scenarios), figsize=(13, 3*len(idles)), squeeze=False)
        for row_index, idle in enumerate(idles):
            for col, scenario in enumerate(scenarios):
                ax = axes[row_index][col]
                for variant, label in labels.items():
                    data = sorted((r for r in summary if r["scenario"]==scenario and r["idle"]==idle
                                   and r["variant"]==variant), key=lambda r:r["memcap"])
                    x = [r["memcap"]/1024 for r in data]
                    ax.plot(x, [r[metric] for r in data], marker="o", ms=3, label=label)
                    ax.fill_between(x, [r[metric+"_min"] for r in data],
                                    [r[metric+"_max"] for r in data], alpha=.12)
                ax.set_xscale("log", base=2)
                ticks = sorted({r["memcap"]/1024 for r in data})
                ax.set_xticks(ticks, labels=[str(int(x)) for x in ticks])
                ax.set_ylim(bottom=0)
                if all(r[metric+"_max"] == 0 for r in summary if r["scenario"]==scenario and r["idle"]==idle):
                    ax.set_ylim(0, 1)
                ax.set_title(f"{scenario}; timeout {idle}s")
                ax.set_xlabel("Flow memcap (KiB)")
                if col == 0:
                    ax.set_ylabel(ylabel)
                ax.grid(alpha=.2)
        handles, legend_labels = axes[0][0].get_legend_handles_labels()
        fig.legend(handles, legend_labels, loc="lower center", ncol=4)
        fig.suptitle("Suricata 6.0.4 offline development experiment; checksums disabled", fontsize=11)
        fig.tight_layout(rect=(0,.06,1,.94))
        fig.savefig(args.output / (metric.replace(".","_")+".pdf"))
        fig.savefig(args.output / (metric.replace(".","_")+".png"), dpi=150)
        plt.close(fig)
    print(f"seed_rows={len(seed_rows)} summary_rows={len(summary)} failures={len(failures)}")


if __name__ == "__main__":
    main()
