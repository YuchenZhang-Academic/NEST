"""Export target-complete neural outputs for the existing offline engine runner."""
import argparse
import json
from pathlib import Path
import shutil

from inspect_generated import inspect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    variants, excluded = [], []
    for run in json.loads((args.batch / "batch.json").read_text()):
        name = f'scenario_{run["scenario"]}_{run["mode"]}_s{run["seed"]}'
        source = args.batch / name
        metadata = json.loads((source / "generation.json").read_text())
        if run["returncode"] or metadata["status"] != "complete":
            excluded.append(dict(run=name, status=metadata["status"], error=metadata.get("error")))
            continue
        info = inspect(source / "generated.pcap", metadata["conditioning_ips"])
        if info["counts"]["packets"] != metadata["packet_target"]:
            raise ValueError(f"Completed target/count mismatch: {name}")
        if not info["finite_timestamps"] or not info["ordered_timestamps"]:
            raise ValueError(f"Non-finite or unordered timestamps: {name}")
        scenario = f'scenario_{run["scenario"]}'
        destination = args.output / scenario / f'{run["mode"]}_s{run["seed"]}.pcap'
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / "generated.pcap", destination)
        variants.append(dict(path=str(destination.resolve()), scenario=scenario,
                             variant=run["mode"], seed=run["seed"], inspection=info,
                             generation=metadata))
    if not variants:
        raise ValueError("No target-complete samples; partial PCAPs are diagnostic only")
    (args.output / "selection.json").write_text(json.dumps(dict(
        variants=variants, excluded=excluded,
        purpose="Pipeline validation; short outputs do not establish capacity utility",
        timestamps="Original generated timestamps retained; no duration normalization",
    ), indent=2)+"\n")
    print(f"Prepared {len(variants)} completed samples; excluded {len(excluded)} failed runs")


if __name__ == "__main__":
    main()
