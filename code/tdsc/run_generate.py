"""Bounded NEST generation with receiver-history ablation and full provenance."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import random
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "multi_trace"))
sys.path.insert(0, str(HERE))
sys.path.insert(2, str(HERE.parent))
import numpy as np
import torch
from scapy.all import PcapReader, PcapWriter
from model import get_model
from run_smoke_experiments import load_state_dict_compat
from tdsc_route_probe import read_records
import scheduler


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--checkpoint", type=Path, default=HERE.parent / "multi_trace/parameters/test_111.pt")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--mode", choices=["nest", "no_receiver"], default="nest")
    p.add_argument("--device", default="cpu")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--packets", type=int, default=100)
    p.add_argument("--nodes", type=int, default=0, help="0 uses all source nodes; positive values are feasibility subsets")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--threads", type=int, default=2)
    p.add_argument("--precision", choices=["float32", "bfloat16"], default="float32")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    torch.set_num_threads(args.threads)
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if args.device.startswith("cuda"):
        torch.cuda.manual_seed_all(args.seed)
    report = dict(command=sys.argv, source=str(args.source.resolve()), checkpoint=str(args.checkpoint.resolve()),
                  mode=args.mode, device=args.device, seed=args.seed, packet_target=args.packets,
                  precision=args.precision,
                  max_seq_len=12032, max_payload_tokens=1600, wall_time_budget_s=args.seconds,
                  torch=torch.__version__, status="started", model_calls=0, generated_tokens=0, events=[])
    report["cuda_visible_devices"] = os.environ.get("CUDA_VISIBLE_DEVICES")
    if args.device.startswith("cuda"):
        report["gpu_name"] = torch.cuda.get_device_name(args.device)
    start = time.monotonic()
    def expired(signum, frame):
        raise TimeoutError("Generation wall-time budget exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(args.seconds)
    original_next = scheduler.gen_next_k_token
    def counted(*a, **kw):
        report["model_calls"] += 1
        result = original_next(*a, **kw)
        report["generated_tokens"] += len(result)
        return result
    scheduler.gen_next_k_token = counted
    partial = args.output / "partial.pcap"
    def save_packet(packet):
        with PcapWriter(str(partial), append=True, sync=True) as writer:
            writer.write(packet)
        report["events"][-1]["elapsed_s"] = time.monotonic()-start
    try:
        records, info = read_records(args.source, 20000)
        ips = sorted({end[0] for r in records for end in r[2][1:]})
        if args.nodes:
            ips = ips[:args.nodes]
        if len(ips) < 2:
            raise ValueError("At least two conditioning nodes required")
        report.update(conditioning_ips=ips, source_info=info, node_subset=bool(args.nodes))
        with PcapReader(str(args.source)) as reader:
            start_time = float(next(reader).time)
        report["conditioning_start_time"] = start_time
        model = get_model(num_tokens=260, max_len=12032).to(args.device)
        load_state_dict_compat(model, args.checkpoint, args.device)
        model.eval()
        report["load_elapsed_s"] = time.monotonic()-start
        if args.precision == "bfloat16" and not args.device.startswith("cuda"):
            raise ValueError("bfloat16 benchmark requires CUDA")
        precision = torch.autocast("cuda", dtype=torch.bfloat16) if args.precision == "bfloat16" else nullcontext()
        with precision:
            packets = scheduler.generate(model, ips, start_time, max_packet_num=args.packets,
                                         device=args.device, update_receiver=args.mode == "nest",
                                         max_attempts=max(10, args.packets*10), events=report["events"],
                                         on_packet=save_packet)
        partial.rename(args.output / "generated.pcap")
        report.update(status="complete", packets=len(packets))
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__, error=str(error))
    finally:
        signal.alarm(0)
        report["completed_events"] = len(report["events"])
        report["elapsed_s"] = time.monotonic()-start
        (args.output / "generation.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("events", "conditioning_ips")}, indent=2))
    if report["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
