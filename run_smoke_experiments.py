import argparse
import importlib
import os
import pickle
import struct
import sys
from contextlib import contextmanager
from pathlib import Path

import torch


ROOT = Path(__file__).resolve().parent
CODE_DIR = Path(__file__).resolve().parent


@contextmanager
def local_module_dir(path):
    stale_modules = [
        "dataset",
        "model",
        "myautowrapper",
        "generate_many",
        "generate_many_mgpu",
        "generate_lib",
    ]
    for name in stale_modules:
        sys.modules.pop(name, None)

    sys.path.insert(0, str(path))
    try:
        yield
    finally:
        if sys.path and sys.path[0] == str(path):
            sys.path.pop(0)
        for name in stale_modules:
            sys.modules.pop(name, None)


def load_state_dict_compat(model, checkpoint_path, device):
    state_dict = torch.load(checkpoint_path, map_location=device)
    state_dict = {
        key.replace("weights_0", "weights.0").replace("weights_1", "weights.1"): value
        for key, value in state_dict.items()
    }
    model.load_state_dict(state_dict)


def run_ip(args):
    module_dir = CODE_DIR / "ip_generator"
    with local_module_dir(module_dir):
        model_module = importlib.import_module("model")
        generate_many = importlib.import_module("generate_many")

        model = model_module.get_model(num_tokens=260, max_len=args.max_len).to(args.device)
        load_state_dict_compat(model, args.checkpoint or module_dir / "parameters" / "ip_generator.pt", args.device)
        model.eval()

        inp = torch.tensor([256]).long().to(args.device)
        sample = model.module.generate(inp, args.ip_tokens, eos_token=256)
        ips = generate_many.restore_ip_from_bytes(sample)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "wb") as f:
        pickle.dump(ips, f)

    print(f"generated_ips={ips}")
    print(f"output={args.output}")


def build_single_header(pkl_path):
    with open(pkl_path, "rb") as f:
        data = pickle.load(f)

    start_time = data[0]
    all_ips = ([data[1]] + data[2])[:64]
    header = [259]
    header.extend(list(struct.pack(">d", start_time)))
    for ip in all_ips:
        header.append(259)
        header.extend([int(i) for i in ip.split(".")])
    header.append(256)
    return header


def run_single(args):
    module_dir = CODE_DIR / "single_trace"
    with local_module_dir(module_dir):
        model_module = importlib.import_module("model")
        generator = importlib.import_module("generate_many_mgpu")

        model = model_module.get_model(num_tokens=260, max_len=args.max_len).to(args.device)
        load_state_dict_compat(model, args.checkpoint or module_dir / "parameters" / "single_trace.pt", args.device)
        model.eval()

        header = build_single_header(args.single_pkl)
        inp = torch.tensor(header).long().to(args.device)
        sample = model.module.generate(inp, args.trace_tokens, eos_token=257)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        generator.restore_pcap_from_bytes(sample, str(args.output))

    print(f"header_tokens={len(header)}")
    print(f"generated_tokens={sample.numel()}")
    print(f"output={args.output}")
    print(f"output_bytes={args.output.stat().st_size}")


def run_multi(args):
    module_dir = CODE_DIR / "multi_trace"
    with local_module_dir(module_dir):
        model_module = importlib.import_module("model")
        generate_lib = importlib.import_module("generate_lib")
        from scapy.all import wrpcap

        model = model_module.get_model(num_tokens=260, max_len=args.max_len).to(args.device)
        load_state_dict_compat(model, args.checkpoint or module_dir / "parameters" / "test_111.pt", args.device)
        model.eval()

        original_gen_next = generate_lib.gen_next_k_token

        def capped_gen_next(model, inp, k, device="cpu", eos_token=257, eos_token2=257):
            if k == 1600:
                k = args.multi_payload_tokens
            return original_gen_next(
                model,
                inp,
                k,
                device=device,
                eos_token=eos_token,
                eos_token2=eos_token2,
            )

        generate_lib.gen_next_k_token = capped_gen_next
        packets = generate_lib.generate(
            model,
            args.multi_ips,
            args.start_time,
            max_packet_num=args.multi_packets,
            device=args.device,
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(args.output), packets)

    print(f"packets={len(packets)}")
    print(f"output={args.output}")
    print(f"output_bytes={args.output.stat().st_size}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=["ip", "single", "multi"])
    parser.add_argument("--device", default="cuda:0" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--max-len", type=int, default=12032)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--checkpoint", type=Path)

    parser.add_argument("--ip-tokens", type=int, default=16)

    parser.add_argument("--single-pkl", type=Path)
    parser.add_argument("--trace-tokens", type=int, default=64)

    parser.add_argument("--multi-ips", nargs="+", default=["192.168.137.5", "8.8.8.8"])
    parser.add_argument("--multi-packets", type=int, default=1)
    parser.add_argument("--multi-payload-tokens", type=int, default=1600)
    parser.add_argument("--start-time", type=float, default=1605012765.3969844)

    args = parser.parse_args()
    if args.target == "single" and args.single_pkl is None:
        parser.error("--single-pkl is required for the single target")
    if args.output is None:
        output_dir = ROOT / "outputs" / "smoke"
        suffix = "pkl" if args.target == "ip" else "pcap"
        args.output = output_dir / f"{args.target}.{suffix}"
    return args


def main():
    args = parse_args()
    if args.target == "ip":
        run_ip(args)
    elif args.target == "single":
        run_single(args)
    elif args.target == "multi":
        run_multi(args)


if __name__ == "__main__":
    main()
