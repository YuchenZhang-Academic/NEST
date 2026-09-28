# NEST

**Node-Interactive Emulation for Synthetic Traffic Generation and Security Testing**

This repository contains the source code for NEST and its unpublished journal-extension draft. NEST generates traffic from node-local packet histories and coordinates the nodes with an event-driven scheduler. The extension constructs offline test workloads from generated PCAP episodes: it keeps a node's identity consistent across flows, builds matched controls, and plans the number of episode copies for a requested peak in an idle-timeout flow model.

## Contents

| Path | Purpose |
| --- | --- |
| `code/ip_generator/` | IP-address-set dataset, model, training, and generation code. |
| `code/single_trace/` | Single-node trace tokenization, model, and training code. |
| `code/multi_trace/` | Multi-node model, packet generation, event scheduling, and address mapping. |
| `code/tdsc/` | Bounded generation, workload construction, phase planning, input checks, and offline Suricata experiments. |
| `code/tdsc/coverage/` | Scripts for the draft's extended input selection and result analysis. |
| `code/run_smoke_experiments.py` | Small checkpoint-dependent generation entry point for the three model components. |
| `code/tdsc_route_probe.py` | Flow-state proxy and controlled timing transformations used by the extension scripts. |

The workload builder and host-policy runner use the later corrected source versions: packet address rewriting preserves captured bytes outside IP addresses and checksums, and missing Suricata `host.memcap` statistics remain unavailable rather than being reported as zero.

## Requirements and inputs

The development environment used Python 3.10, PyTorch 2.4.1, and Scapy 2.6.1. Source imports also require `linear-attention-transformer`, NumPy, pandas, matplotlib, tqdm, and dpkt. Larger neural-generation runs need a suitable CUDA GPU. The engine scripts expect a compatible Suricata 6.0.4 tree containing `usr/bin/suricata`, `usr/lib/x86_64-linux-gnu/`, and, for rule runs, `etc/suricata/`.

**This is a source-only repository.** It does not contain training or evaluation PCAPs, generated traffic, processed datasets, model checkpoints, Suricata binaries, experimental results, or the manuscript. Supply your own inputs and checkpoints. The historical training and generation scripts in `ip_generator/`, `single_trace/`, and `multi_trace/` retain local path assumptions; set their dataset and checkpoint paths for your environment. The commands below use entry points that accept external paths.

## Example workflow

Run commands from the repository root. Use fresh output directories; the scripts create them.

```bash
python code/tdsc/check_scheduler.py

python code/tdsc/run_generate.py \
  --source /path/to/source.pcap \
  --checkpoint /path/to/multi_trace.pt \
  --output /path/to/outputs/nest \
  --device cuda:0 --packets 10 --seconds 600

python code/tdsc/compose_workload.py \
  --episodes /path/to/outputs/nest/generated.pcap \
  --output /path/to/outputs/workloads \
  --targets 64 256
```

`run_generate.py` requires at least two conditioning nodes in the source capture. It records completed packets and metadata; interrupted runs can leave a partial PCAP. `compose_workload.py` admits complete observed biflows under its packet checks and writes episode, replay, and independent-flow controls with a `selection.json` manifest. A direct episode can also come from another NEST generation run. For the historical selection workflow, pass `--selection` and `--episode-dir` instead of `--episodes`; generated PCAP names must match the selected source filename stems.

To plan fixed launch intervals, first construct one-copy units, then run the planner:

```bash
python code/tdsc/compose_workload.py \
  --episodes /path/to/outputs/nest/generated.pcap \
  --output /path/to/outputs/units --replicas 1
python code/tdsc/phase_plan.py \
  --units /path/to/outputs/units/selection.json \
  --output /path/to/outputs/phases --targets 64 256
```

With your own Suricata tree, the generated manifest can be passed to the offline engine runners:

```bash
python code/tdsc/run_engine.py \
  --selection /path/to/outputs/workloads/selection.json \
  --engine-root /path/to/suricata-root \
  --output /path/to/outputs/engine --checksums no --idle 60

python code/tdsc/run_host_policy.py \
  --selections /path/to/outputs/workloads/selection.json \
  --engine-root /path/to/suricata-root \
  --output /path/to/outputs/host-policy
```

These are offline PCAP runs. The peak-flow guarantee is for the specified idle-timeout proxy and fixed episode/launch policy; it does not predict Suricata memory occupancy. The host-policy code tests specific UDP threshold rules. Its alert counts are not attack-detection accuracy. Exact manuscript figures and tables require the original inputs, checkpoints, engine environment, and results, none of which are distributed here.

## License

GNU General Public License v3.0; see [LICENSE](LICENSE).
