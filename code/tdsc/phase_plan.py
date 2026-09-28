"""Plan episode copies for an idle-state peak under a prescribed launch interval."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

from scapy.all import PcapReader
from compose_workload import build, describe, export, key_of


def profile(rows, idle_ns):
    groups=defaultdict(list)
    for ns,_,key in rows:groups[key].append(ns)
    events=defaultdict(int)
    for times in groups.values():
        start=times[0];end=start+idle_ns
        for ns in times[1:]:
            if ns<=end:end=max(end,ns+idle_ns)
            else:
                events[start]+=1;events[end]-=1;start=ns;end=ns+idle_ns
        events[start]+=1;events[end]-=1
    return sorted(events.items())


def peak(events, replicas, stride_ns):
    shifted=defaultdict(int)
    for replica in range(replicas):
        for ns,change in events:shifted[ns+replica*stride_ns]+=change
    active=maximum=0
    for _,change in sorted(shifted.items()):
        active+=change;maximum=max(maximum,active)
    return maximum


def plan(events, target, stride_ns, max_replicas):
    base=peak(events,1,0)
    if not stride_ns:
        copies=(target+base-1)//base
        return dict(status='feasible' if copies<=max_replicas else 'budget_exhausted',
                    replicas=copies if copies<=max_replicas else None,
                    achieved_peak=copies*base if copies<=max_replicas else None,
                    global_maximum=None)
    span=events[-1][0]-events[0][0]
    overlap=(span+stride_ns-1)//stride_ns
    # Beyond this many equally spaced identical episodes, the peak cannot grow.
    maximum=peak(events,overlap,stride_ns)
    if maximum<target:
        return dict(status='infeasible_at_stride',replicas=None,achieved_peak=None,
                    global_maximum=maximum,saturation_replicas=overlap)
    hi=min(max_replicas,overlap)
    if peak(events,hi,stride_ns)<target:
        return dict(status='budget_exhausted',replicas=None,achieved_peak=None,
                    global_maximum=maximum,saturation_replicas=overlap)
    lo=1
    while lo<hi:
        mid=(lo+hi)//2
        if peak(events,mid,stride_ns)>=target:hi=mid
        else:lo=mid+1
    achieved=peak(events,lo,stride_ns)
    assert target<=achieved<target+base
    assert lo==1 or peak(events,lo-1,stride_ns)<target
    return dict(status='feasible',replicas=lo,achieved_peak=achieved,
                global_maximum=maximum,saturation_replicas=overlap)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--units',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--targets',type=int,nargs='+',default=[64,256])
    p.add_argument('--idle',type=int,default=60)
    p.add_argument('--max-replicas',type=int,default=2048)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(a.units.read_text());results=[];variants=[]
    for unit in manifest['variants']:
        if unit['variant']!='episode':continue
        path=a.units.resolve().parent/unit['scenario']/Path(unit['path']).name
        with PcapReader(str(path)) as reader:packets=list(reader)
        origin=packets[0].time
        rows=[(int(round((pkt.time-origin)*10**9)),pkt,key_of(pkt)) for pkt in packets]
        keys=sorted({r[2] for r in rows});ips=sorted({e[0] for key in keys for e in key[1:]})
        events=profile(rows,a.idle*10**9);base=peak(events,1,0)
        span=rows[-1][0]+a.idle*10**9
        strides={'aligned':0,'dense':(span+15)//16,'half_span':(span+1)//2,'separated':span+10**9}
        for phase,stride in strides.items():
            for target in a.targets:
                result=plan(events,target,stride,a.max_replicas)
                naive=(target+base-1)//base
                row=dict(source=unit['source'],phase=phase,stride_ns=stride,target=target,
                         base_peak=base,naive_replicas=naive,naive_peak=peak(events,naive,stride),**result)
                methods=[('naive_sync_formula',naive)]
                if result['status']=='feasible':methods.append(('phase_aware',result['replicas']))
                for method,copies in methods:
                    sample=build(rows,keys,ips,copies,'episode',stride/1e9)
                    actual=describe(sample,a.idle)
                    predicted=peak(events,copies,stride)
                    # The interval planner and packet-driven idle-cache simulator are independent implementations.
                    assert actual['proxy_peak']==predicted
                    if method=='phase_aware':assert target<=predicted<target+base
                    scenario=f'{unit["source"]}_{phase}_q{target}'
                    dest=a.output/scenario/f'{method}.pcap';export(dest,sample)
                    variants.append(dict(path=str(dest.resolve()),scenario=scenario,variant=method,seed=0,
                        source=unit['source'],phase=phase,target_peak=target,replicas=copies,
                        stride_ns=stride,predicted_peak=predicted,**actual))
                if stride:
                    k=result['saturation_replicas']
                    assert peak(events,k+2,stride)==result['global_maximum']
                results.append(row)
        print(f'completed {unit["source"]}',flush=True)
    (a.output/'plans.json').write_text(json.dumps(dict(command=sys.argv,idle=a.idle,plans=results),indent=2)+'\n')
    (a.output/'selection.json').write_text(json.dumps(dict(variants=variants,
        purpose='Startup-spacing boundary and phase-aware planning; idle model is not native memory occupancy'),indent=2)+'\n')
    print(f'{len(results)} plans; {len(variants)} serialized validation workloads')


if __name__=='__main__':main()
