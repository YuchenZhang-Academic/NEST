"""Single-GPU sequential feasibility/ablation runs. No implicit use of all GPUs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import torch


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selection", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--device", default="cuda:0")
    p.add_argument("--scenarios", nargs="+", type=int, default=[1])
    p.add_argument("--seeds", nargs="+", type=int, default=[0])
    p.add_argument("--packets", type=int, default=10)
    p.add_argument("--seconds", type=int, default=600)
    p.add_argument("--precision", choices=["float32", "bfloat16"], default="float32")
    args = p.parse_args()
    if not args.device.startswith("cuda:") or not torch.cuda.is_available():
        raise SystemExit("A usable, explicitly selected CUDA device is required; no CPU fallback")
    if torch.cuda.device_count() != 1 or args.device != "cuda:0":
        raise SystemExit("Set CUDA_VISIBLE_DEVICES to one physical GPU, then use --device cuda:0")
    args.output.mkdir(parents=True, exist_ok=False)
    selection = json.loads(args.selection.read_text())
    results = []
    for index in args.scenarios:
        source = Path(selection["selected"][index]["path"])
        if not source.is_absolute():
            source = args.selection.resolve().parent / source
        if not source.exists():
            raise FileNotFoundError(source)
        for seed in args.seeds:
            for mode in ["nest", "no_receiver"]:
                destination = args.output / f"scenario_{index}_{mode}_s{seed}"
                command = [sys.executable, str(Path(__file__).with_name("run_generate.py")),
                           "--source", str(source), "--checkpoint", str(args.checkpoint.resolve()),
                           "--output", str(destination), "--device", args.device, "--mode", mode,
                           "--seed", str(seed), "--packets", str(args.packets), "--seconds", str(args.seconds),
                           "--precision", args.precision]
                with destination.with_suffix(".log").open("w") as log:
                    proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                          timeout=args.seconds+120)
                results.append(dict(scenario=index, mode=mode, seed=seed, returncode=proc.returncode,
                                    command=command, metadata=str(destination/"generation.json")))
                (args.output/"batch.json").write_text(json.dumps(results, indent=2)+"\n")
                if proc.returncode:
                    raise SystemExit("Generation failed; recorded log and metadata. Inspect before expanding the batch")
    print(f"completed {len(results)} bounded runs")


if __name__ == "__main__":
    main()
