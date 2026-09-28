"""Verify serialized checksums and characterize the exact host partition change."""
from collections import defaultdict
import ipaddress
import json
from pathlib import Path
import struct
import sys
from scapy.all import IP,UDP,PcapReader

root=Path(sys.argv[1]).resolve()
directory=root/'inputs/constructed'
items=json.loads((directory/'selection.json').read_text())['variants']
def read(path):
    with PcapReader(str(path)) as reader:return list(reader)
def residual(data):
    data+=b'\0'*(len(data)%2)
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>>16:value=(value&65535)+(value>>16)
    return value
count=0
for item in items:
    packets=read(directory/item['scenario']/Path(item['path']).name)
    for p in packets:
        ip=p[IP];raw=bytes(ip);header=int(ip.ihl)*4
        assert residual(raw[:header])==65535
        length=int(ip.payload.len) if isinstance(ip.payload,UDP) else int(ip.len)-header
        pseudo=struct.pack('!4s4sBBH',ipaddress.IPv4Address(ip.src).packed,
            ipaddress.IPv4Address(ip.dst).packed,0,int(ip.proto),length)
        assert residual(pseudo+raw[header:header+length])==65535
        count+=1
structure={}
for source in sorted({r['source'] for r in items}):
    scenario=source+'_r1'
    episode=read(directory/scenario/'episode.pcap')
    split=read(directory/scenario/'flow_split.pcap')
    replay=read(directory/scenario/'replay.pcap')
    maps={method:{} for method in ['episode','flow_split','replay']}
    groups={track:defaultdict(set) for track in ['src','dst']}
    totals={track:defaultdict(int) for track in ['src','dst']}
    for ep,fl,rp in zip(episode,split,replay):
        for track in ['src','dst']:
            original=ep[IP].getfieldval(track)
            for method,p in [('episode',ep),('flow_split',fl),('replay',rp)]:
                renamed=p[IP].getfieldval(track)
                assert renamed not in maps[method] or maps[method][renamed]==original
                maps[method][renamed]=original
            if isinstance(ep[IP].payload,UDP):
                groups[track][original].add(fl[IP].getfieldval(track));totals[track][original]+=1
    metadata=next(r for r in items if r['source']==source and r['variant']=='episode' and r['target_peak'] is None)
    structure[source]=dict(unit_node_count=metadata['nodes'],unit_biflows=metadata['biflows'],maps=maps,
        tracks={t:dict(split_hosts=sum(len(v)>1 for v in groups[t].values()),
            max_host_packets=max(totals[t].values(),default=0),host_packets=totals[t],
            groups={k:sorted(v) for k,v in groups[t].items()}) for t in groups})
(root/'structure.json').write_text(json.dumps(structure,indent=2)+'\n')
report=dict(command=sys.argv,pcaps=len(items),packets_with_valid_ip_and_transport_checksums=count,
    checksum_failures=0,host_mapping_checks='Exact mapping from paired unit input packet addresses',
    construction_readback='prepare_coverage.py checked exact bytes and integer nanosecond times for all PCAPs')
(root/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
