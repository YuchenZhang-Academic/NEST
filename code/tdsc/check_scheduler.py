"""Focused scheduler checks with deterministic packet predictions, no checkpoint."""
import contextlib
import io
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "multi_trace"))
sys.path.insert(0, str(HERE))
import scheduler
from scapy.all import Ether, IP, TCP
import torch
import myautowrapper


def predict(model, inp, k, **kwargs):
    src = '.'.join(map(str, inp[10:14]))
    dst = '10.0.0.2' if src == '10.0.0.1' else '10.0.0.1'
    raw = bytes(Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src=src, dst=dst) / TCP(sport=1000, dport=80))
    if k == 47:
        return [3] + list(struct.pack('>d', 1. if src.endswith('.1') else 2.)) + list(raw[:38])
    return list(raw[38:]) + [256]


def main():
    ips = ['10.0.0.1', '10.0.0.2']
    scheduler.gen_next_k_token = predict
    for enabled in [True, False]:
        events = []
        saved = []
        with contextlib.redirect_stdout(io.StringIO()):
            packets = scheduler.generate(None, ips, 0., max_packet_num=3,
                                         update_receiver=enabled, events=events, on_packet=saved.append)
        assert len(packets) == 3 and all(IP in p for p in packets)
        assert [bytes(p) for p in saved] == [bytes(p) for p in packets]
        assert [float(p.time) for p in packets] == sorted(float(p.time) for p in packets)
        header_length = len(scheduler.cal_header(ips, ips[1], 0.))
        assert (events[0]['receiver_tokens'] > header_length) == enabled
    scheduler.gen_next_k_token = lambda *a, **kw: []
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            scheduler.generate(None, ips, 0., max_packet_num=1, max_attempts=2)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Invalid predictions must terminate at the attempt budget')
    class FixedNet(torch.nn.Module):
        max_seq_len = 128
        def forward(self, x):
            logits = torch.full((*x.shape, 260), -1e6)
            logits[:, :, 257] = 0
            return logits
    original_pad = myautowrapper.Autopadder
    myautowrapper.Autopadder = lambda net: net
    wrapper = myautowrapper.AutoregressiveWrapper(FixedNet())
    myautowrapper.Autopadder = original_pad
    result = wrapper.generate(torch.tensor([256]), 5, eos_token=256, eos_token2=257)
    assert result.tolist() == [257]
    print('PASS: decoded IP packets, per-packet callback, chronological output, receiver ablation, bounded failure, second terminator')


if __name__ == '__main__':
    main()
