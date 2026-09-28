"""Read serialized phase workloads and check the independent packet-cache model."""
import argparse
import json
from pathlib import Path
import sys
from scapy.all import PcapReader
from compose_workload import describe, key_of
from phase_plan import plan


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selection',type=Path,required=True)
    a=p.parse_args();items=json.loads(a.selection.read_text())['variants']
    for item in items:
        path=a.selection.parent/item['scenario']/Path(item['path']).name
        with PcapReader(str(path)) as reader:packets=list(reader)
        rows=[(int(round((pkt.time-packets[0].time)*10**9)),0,i,bytes(pkt),key_of(pkt))
              for i,pkt in enumerate(packets)]
        observed=describe(rows,item['proxy_idle_s'])
        for key in ['proxy_peak','packets','bytes','biflows','nodes','shared_nodes']:
            assert observed[key]==item[key],(path,key,observed[key],item[key])
        assert observed['proxy_peak']==item['predicted_peak']
    # Explicit infeasibility versus an insufficient replica budget.
    events=[(0,1),(10,-1)]
    assert plan(events,2,11,100)['status']=='infeasible_at_stride'
    assert plan(events,3,1,2)['status']=='budget_exhausted'
    assert plan(events,3,1,3)['replicas']==3
    assert plan(events,3,0,2)['status']=='budget_exhausted'
    report=dict(command=sys.argv,serialized_workloads_checked=len(items),
        fields_checked=['proxy_peak','packets','bytes','biflows','nodes','shared_nodes'],
        timing='Integer nanoseconds, read back from PCAP; independent packet-driven idle cache',
        explicit_status_checks=4,failures=0)
    (a.selection.parent/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
