"""Compose NEST episodes into offline state-pressure workloads; no live traffic."""
import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import ipaddress
import json
import math
from pathlib import Path
import sys
import time
import struct
from scapy.utils import checksum

from scapy.all import Ether, IP, TCP, UDP, PcapReader, RawPcapWriter
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tdsc_route_probe import flow_table


def key_of(packet):
    ip = packet[IP]
    tr = ip.payload
    return (int(ip.proto), *sorted(((ip.src, int(tr.sport)), (ip.dst, int(tr.dport)))))


def load_episode(path, allow_empty=False):
    groups = defaultdict(list)
    bad = set()
    rejected = Counter()
    total = 0
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            total += 1
            if Ether not in packet or IP not in packet or not isinstance(packet[IP].payload, (TCP, UDP)):
                rejected['unsupported_packet'] += 1
                continue
            ip, tr = packet[IP], packet[IP].payload
            key = key_of(packet)
            groups[key].append((index, packet))
            reason = None
            if ip.frag or ip.flags.MF:
                reason = 'fragment'
            elif not math.isfinite(float(packet.time)):
                reason = 'nonfinite_time'
            elif ip.version != 4 or ip.ihl < 5 or ip.len < ip.ihl*4 or ip.len > len(bytes(ip)):
                reason = 'ipv4_length_or_header'
            elif isinstance(tr, TCP) and (tr.dataofs < 5 or tr.dataofs*4 > ip.len-ip.ihl*4):
                reason = 'tcp_header'
            elif isinstance(tr, UDP) and (tr.len < 8 or tr.len > ip.len-ip.ihl*4):
                reason = 'udp_length'
            if reason:
                rejected[reason] += 1
                bad.add(key)
    # Discard the entire affected biflow, rather than invent missing bytes.
    kept = sorted((item for key, items in groups.items() if key not in bad for item in items),
                  key=lambda item: (float(item[1].time), item[0]))
    if not kept and not allow_empty:
        raise ValueError(f'No admissible biflows in {path}')
    origin = Decimal(str(kept[0][1].time)) if kept else Decimal(0)
    rows = [(int((Decimal(str(p.time))-origin)*10**9), p, key_of(p)) for _, p in kept]
    keys = sorted({row[2] for row in rows})
    ips = sorted({end[0] for key in keys for end in key[1:]})
    return rows, keys, ips, dict(source=str(path.resolve()), input_packets=total,
        retained_packets=len(rows), excluded_biflows=len(bad), retained_biflows=len(keys),
        retained_nodes=len(ips), packet_rejection_reasons=rejected,
        excluded_packets=total-len(rows), duration_s=rows[-1][0]/1e9 if rows else 0)


def rewrite(packet, src, dst):
    # Patch original bytes: Scapy reserialization can normalize TCP options
    # after EOL and shorten an otherwise admitted captured header.
    original = bytes(packet)
    raw = bytearray(original)
    ip = packet[IP]
    offset = len(original)-len(bytes(ip))
    header = ip.ihl*4
    source, destination = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    raw[offset+12:offset+20] = source+destination
    raw[offset+10:offset+12] = b'\0\0'
    raw[offset+10:offset+12] = struct.pack('!H', checksum(bytes(raw[offset:offset+header])))
    transport = offset+header
    length = int(ip.payload.len) if isinstance(ip.payload, UDP) else int(ip.len)-header
    check_offset = transport+(6 if isinstance(ip.payload, UDP) else 16)
    raw[check_offset:check_offset+2] = b'\0\0'
    pseudo = struct.pack('!4s4sBBH',source,destination,0,int(ip.proto),length)
    value = checksum(pseudo+bytes(raw[transport:transport+length]))
    if isinstance(ip.payload,UDP) and value==0:value=65535
    raw[check_offset:check_offset+2] = struct.pack('!H',value)
    allowed=set(range(offset+10,offset+20))|set(range(check_offset,check_offset+2))
    assert len(raw)==len(original) and all(a==b or i in allowed for i,(a,b) in enumerate(zip(original,raw)))
    raw=bytes(raw)
    decoded = Ether(raw)
    assert bytes(decoded[IP].payload.payload) == bytes(packet[IP].payload.payload)
    return raw, key_of(decoded)


def build(rows, keys, ips, replicas, method, stride):
    stride_ns = round(stride*1e9)
    ip_index = {ip: i for i, ip in enumerate(ips)}
    flow_index = {key: i for i, key in enumerate(keys)}
    network = int(ipaddress.IPv4Address('10.0.0.1'))
    output = []
    for replica in range(replicas):
        for index, (ns, packet, key) in enumerate(rows):
            if method == 'replay':
                src, dst = packet[IP].src, packet[IP].dst
            elif method == 'episode':
                src = str(ipaddress.IPv4Address(network + replica*len(ips) + ip_index[packet[IP].src]))
                dst = str(ipaddress.IPv4Address(network + replica*len(ips) + ip_index[packet[IP].dst]))
            else:
                # Independent-flow baseline: a private pair of nodes per biflow.
                base = network + 2*(replica*len(keys) + flow_index[key])
                forward = (packet[IP].src, int(packet[IP].payload.sport)) == key[1]
                src = str(ipaddress.IPv4Address(base + (0 if forward else 1)))
                dst = str(ipaddress.IPv4Address(base + (1 if forward else 0)))
            raw, new_key = rewrite(packet, src, dst)
            output.append((ns + replica*stride_ns, replica, index, raw, new_key))
    return sorted(output, key=lambda row: row[:3])


def export(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with RawPcapWriter(str(path), linktype=1, nano=True) as writer:
        writer.write_header(None)
        for ns, _, _, raw, _ in rows:
            sec, nano = divmod(ns, 10**9)
            writer.write_packet(raw, sec=1600000000+sec, usec=nano, caplen=len(raw), wirelen=len(raw))


def describe(rows, idle):
    records = [(ns, len(raw), key, i) for i, (ns, _, _, raw, key) in enumerate(rows)]
    peers = defaultdict(set)
    for _, _, key, _ in records:
        a,b = key[1][0],key[2][0]
        peers[a].add(b); peers[b].add(a)
    return dict(packets=len(rows), bytes=sum(len(row[3]) for row in rows),
                biflows=len({row[4] for row in rows}), nodes=len(peers),
                shared_nodes=sum(len(v)>1 for v in peers.values()),
                proxy_peak=flow_table(records, round(idle*1e9))['peak_entries'],
                proxy_idle_s=idle, duration_s=rows[-1][0]/1e9)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path)
    parser.add_argument('--episode-dir', type=Path, help='Directory of NEST-generated PCAPs named after selected source stems')
    parser.add_argument('--episodes', type=Path, nargs='+', help='NEST-generated PCAPs supplied directly')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--replicas', type=int, nargs='+', default=[1,4,16,64])
    parser.add_argument('--targets', type=int, nargs='+', help='Requested idle-model peak; round up by one episode peak')
    parser.add_argument('--sources', type=int, nargs='+', default=[0,1,2,3])
    parser.add_argument('--stride', type=float, default=0.)
    parser.add_argument('--idle', type=float, default=60.)
    parser.add_argument('--fresh', type=Path)
    args = parser.parse_args()
    if bool(args.selection) == bool(args.episodes):
        parser.error('Provide exactly one of --selection or --episodes')
    if args.selection and args.episode_dir is None:
        parser.error('--episode-dir is required with --selection')
    if min(args.replicas)<1 or args.stride<0 or args.idle<=0 or (args.targets and min(args.targets)<1):
        parser.error('Require positive replicas/idle and nonnegative stride')
    if args.targets and args.stride:
        parser.error('The target guarantee applies to synchronized instances (stride=0)')
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    if args.episodes:
        sources = [(f'episode_{i}', path) for i, path in enumerate(args.episodes)]
    else:
        selection = json.loads(args.selection.read_text())
        sources = [(f'archive_{i}', args.episode_dir /
                    (Path(selection['selected'][i]['path']).name.split('.')[0]+'.pcap')) for i in args.sources]
    if args.fresh:
        sources.append(('fresh', args.fresh))
    variants, episodes = [], []
    for label, source in sources:
        original, keys, ips, provenance = load_episode(source)
        base = describe([(ns,0,i,bytes(p),k) for i,(ns,p,k) in enumerate(original)],args.idle)
        episodes.append(dict(label=label, **provenance, admitted=base))
        jobs = [(math.ceil(target/base['proxy_peak']), target) for target in args.targets] if args.targets else [(r,None) for r in args.replicas]
        for replicas, target in jobs:
            time_lengths = None
            for method in ['episode','replay','flow_split']:
                start = time.monotonic()
                rows = build(original, keys, ips, replicas, method, args.stride)
                actual = describe(rows,args.idle)
                expected_flows = len(keys)*(1 if method=='replay' else replicas)
                assert actual['biflows'] == expected_flows
                if not args.stride:
                    assert actual['proxy_peak'] == base['proxy_peak']*(1 if method=='replay' else replicas)
                    if target is not None and method != 'replay':
                        assert target <= actual['proxy_peak'] < target+base['proxy_peak']
                invariant = Counter((row[0],len(row[3])) for row in rows)
                if time_lengths is None:
                    time_lengths = invariant
                assert invariant == time_lengths
                case = f'{label}_target{target}' if target is not None else f'{label}_r{replicas}'
                path = args.output/case/f'{method}.pcap'
                export(path, rows)
                # Re-read every serialized file; checks apply to the actual engine input.
                checked, checked_keys, _, check = load_episode(path)
                assert check['excluded_packets']==0 and len(checked)==len(rows)
                assert len(checked_keys)==expected_flows
                assert [ns for ns,_,_ in checked] == [row[0]-rows[0][0] for row in rows]
                variants.append(dict(path=str(path.resolve()),scenario=path.parent.name,
                    variant=method,seed=0,source=label,replicas=replicas,target_peak=target,stride_s=args.stride,
                    **actual, elapsed_s=time.monotonic()-start))
            print(f'completed {label} replicas={replicas}',flush=True)
    (args.output/'selection.json').write_text(json.dumps(dict(command=sys.argv,
        episodes=episodes,variants=variants,elapsed_s=time.monotonic()-started,
        invariant='All methods share packet count, length/time multiset and application payload copies',
        qualification='Derived NEST episode composition; no diversity or inter-replica neural interaction claim',
        proxy='Idle-only canonical-biflow model; not actual Suricata occupancy'),indent=2)+'\n')


if __name__=='__main__':
    main()
