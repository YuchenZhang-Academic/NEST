"""Apply unchanged admission and build matched controls for all frozen selections."""
from collections import Counter,defaultdict
import json
import math
from pathlib import Path
import sys
import time
from scapy.all import IP, UDP, PcapReader
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compose_workload import load_episode,build,describe,export,key_of

root=Path(sys.argv[1]).resolve()
selection=json.loads((root/'selection.json').read_text())
dest=root/'inputs/constructed';dest.mkdir(parents=True,exist_ok=False)
admission=[];variants=[];started=time.monotonic()
for item in selection['selected']:
    source=item['source'];path=root/'inputs/original'/item['filename']
    rows,keys,ips,meta=load_episode(path,allow_empty=True)
    meta.update(source=source,filename=item['filename'],usable=bool(rows))
    if not rows:
        admission.append(meta);print(f'{source}: no admissible biflow',flush=True);continue
    base=describe([(ns,0,i,bytes(p),k) for i,(ns,p,k) in enumerate(rows)],60)
    direction={track:defaultdict(set) for track in ['src','dst']}
    udp=[]
    for ns,p,k in rows:
        if not isinstance(p[IP].payload,UDP):continue
        udp.append(dict(ns=ns,src=p[IP].src,dst=p[IP].dst,key=k))
        for track in direction:direction[track][p[IP].getfieldval(track)].add(k)
    meta.update(base=base,udp_packets=len(udp),udp_shared_src=sum(len(v)>1 for v in direction['src'].values()),
        udp_shared_dst=sum(len(v)>1 for v in direction['dst'].values()),
        udp_max_src_biflows=max(map(len,direction['src'].values()),default=0),
        udp_max_dst_biflows=max(map(len,direction['dst'].values()),default=0))
    admission.append(meta)
    (dest/f'{source}_udp_events.json').write_text(json.dumps(udp,indent=2)+'\n')
    for target in [None,64,256]:
        replicas=1 if target is None else math.ceil(target/base['proxy_peak'])
        scenario=f'{source}_r1' if target is None else f'{source}_target{target}'
        invariant=None
        for method in ['episode','replay','flow_split']:
            sample=build(rows,keys,ips,replicas,method,0)
            actual=describe(sample,60)
            expected=1 if method=='replay' else replicas
            assert actual['biflows']==base['biflows']*expected
            assert actual['proxy_peak']==base['proxy_peak']*expected
            if method=='episode':assert actual['shared_nodes']==base['shared_nodes']*replicas
            counts=Counter((t,len(raw)) for t,_,_,raw,_ in sample)
            if invariant is None:invariant=counts
            assert counts==invariant
            output=dest/scenario/f'{method}.pcap';export(output,sample)
            with PcapReader(str(output)) as reader:packets=list(reader)
            readback=[(int(round((p.time-packets[0].time)*10**9)),0,i,bytes(p),key_of(p)) for i,p in enumerate(packets)]
            assert [(x[0],x[3]) for x in readback]==[(x[0],x[3]) for x in sample]
            assert describe(readback,60)==actual
            variants.append(dict(path=str(output.resolve()),scenario=scenario,variant=method,seed=0,
                source=source,replicas=replicas,target_peak=target,**actual))
    print(f'{source}: admitted {len(rows)}/{meta["input_packets"]}, UDP {len(udp)}, shared src/dst {meta["udp_shared_src"]}/{meta["udp_shared_dst"]}',flush=True)
(root/'admission.json').write_text(json.dumps(dict(command=sys.argv,episodes=admission,elapsed_s=time.monotonic()-started),indent=2)+'\n')
(dest/'selection.json').write_text(json.dumps(dict(variants=variants),indent=2)+'\n')
print(f'{sum(x["usable"] for x in admission)}/{len(admission)} usable; {len(variants)} PCAPs passed byte/timestamp readback')
