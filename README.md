# NEST: A Node-Interactive Generative Emulation Framework for Synthetic Traffic Generation

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue" alt="GPLv3 license"></a>
  <a href="https://ieeexplore.ieee.org/abstract/document/11571483"><img src="https://img.shields.io/badge/IEEE%20INFOCOM-2026-blue" alt="IEEE INFOCOM 2026"></a>
  <a href="https://ieeexplore.ieee.org/abstract/document/11571483"><img src="https://img.shields.io/badge/Paper-IEEE%20Xplore-black" alt="Paper on IEEE Xplore"></a>
</p>

## Overview

This repository contains the source code for **NEST**, presented in:

> **Jianfeng Li**, **Yuchen Zhang**, **Jian Qu**, **Jialong Zhang**, and **Xiaobo Ma**<br>
> **NEST: A Node-Interactive Generative Emulation Framework for Synthetic Traffic Generation**<br>
> *IEEE INFOCOM 2026* · [Paper](https://ieeexplore.ieee.org/abstract/document/11571483)

Many traffic generators model isolated flows, making it difficult to reproduce the interactions among clients, servers, and other nodes in an application. **NEST** addresses this by learning each node's behavior from its local packet history and coordinating the nodes to generate a coherent, multi-node traffic trace.

The paper evaluates traffic statistics, compatibility with analysis and emulation tools, and the structure of generated node-interaction graphs. It reports **97.7% average similarity** for the evaluated graph metrics.

## Framework

NEST has three stages:

1. **IP address set generation** learns which node addresses tend to occur together and instantiates a network scenario.
2. **Per-node trace generation** models a node's packet sequence using the history of packets it sent or received.
3. **Multi-node orchestration** schedules the next packet across nodes, updates the affected local histories, and merges the packets into a time-ordered trace.

The node-centric design keeps model inputs local while allowing interactions to emerge through the shared scheduler.

## Repository Structure

```text
code/
├── ip_generator/    # IP address set modeling
├── single_trace/    # Single-node trace training and generation support
├── multi_trace/     # Multi-node trace model and orchestration
└── tdsc/            # Separate follow-up workload and engine experiments
```

The `tdsc/` code supports ongoing work on offline workload construction and security-engine testing. It is separate from the results reported in the INFOCOM 2026 paper.

## Code and Data

This is a **source-only** repository. It does not include datasets, PCAP captures, generated traffic, model checkpoints, or experiment results. Running the models and reproducing the paper's experiments require separately supplied inputs and an appropriate Python environment.

## Citation

If you use NEST in academic work, please cite:

```bibtex
@inproceedings{li2026nest,
  title     = {NEST: A Node-Interactive Generative Emulation Framework for Synthetic Traffic Generation},
  author    = {Li, Jianfeng and Zhang, Yuchen and Qu, Jian and Zhang, Jialong and Ma, Xiaobo},
  booktitle = {IEEE INFOCOM 2026},
  year      = {2026},
  url       = {https://ieeexplore.ieee.org/abstract/document/11571483}
}
```

## License

This code is available under the [GNU General Public License v3.0](LICENSE).
