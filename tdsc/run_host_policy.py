"""Offline UDP threshold-rule regression test; not attack-label evaluation."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from run_engine import flatten


def rules(count, seconds):
    result=['alert udp any any -> any any (flow:stateless; msg:"TDSC UDP control"; sid:9900000; rev:1;)']
    for sid, track in [(9900001,'by_src'),(9900002,'by_dst'),(9900003,'by_rule')]:
        result.append(f'alert udp any any -> any any (flow:stateless; msg:"TDSC {track} threshold"; threshold:type both,track {track},count {count},seconds {seconds}; sid:{sid}; rev:1;)')
    return '\n'.join(result)+'\n'


def read_result(path):
    alerts=Counter(); hosts={sid:Counter() for sid in [9900001,9900002]}; latest=None
    for line in path.read_text().splitlines():
        event=json.loads(line)
        if event['event_type']=='stats': latest=flatten(event['stats'])
        elif event['event_type']=='alert':
            sid=event['alert']['signature_id'];alerts[sid]+=1
            if sid in hosts:hosts[sid][event['src_ip'] if sid==9900001 else event['dest_ip']]+=1
    if latest is None:raise RuntimeError('No terminal stats')
    return dict(packets=latest['decoder.pkts'],udp_packets=latest.get('decoder.udp',0),
        decoder_invalid=latest.get('decoder.invalid',0),udp_control=alerts[9900000],
        src_alerts=alerts[9900001],dst_alerts=alerts[9900002],global_alerts=alerts[9900003],
        src_hosts=len(hosts[9900001]),dst_hosts=len(hosts[9900002]),
        src_by_host=dict(hosts[9900001]),dst_by_host=dict(hosts[9900002]),
        flow_get_used=latest['flow.get_used'],host_memcap=latest.get('host.memcap')),latest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selections',type=Path,nargs='+',required=True)
    p.add_argument('--engine-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--counts',type=int,nargs='+',default=[2,4,8,16])
    p.add_argument('--windows',type=int,nargs='+',default=[1,10,60])
    p.add_argument('--targets',type=int,nargs='+',default=[64,256])
    p.add_argument('--repeats',type=int,default=2)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    config=a.output/'suricata.yaml'
    config.write_text(Path(__file__).with_name('suricata.yaml').read_text().replace('        - anomaly','        - anomaly\n        - alert'))
    binary=a.engine_root.resolve()/'usr/bin/suricata'
    env=dict(os.environ,LD_LIBRARY_PATH=str(a.engine_root.resolve()/'usr/lib/x86_64-linux-gnu'))
    version=subprocess.check_output([str(binary),'-V'],env=env,text=True).strip()
    configs=a.engine_root.resolve()/'etc/suricata'
    (a.output/'empty_threshold.config').write_text('')
    for count in a.counts:
        for window in a.windows:(a.output/f'c{count}_w{window}.rules').write_text(rules(count,window))
    items=[]
    for selection in a.selections:
        for item in json.loads(selection.read_text())['variants']:
            if item.get('target_peak') is not None and item['target_peak'] not in a.targets:continue
            path=selection.resolve().parent/item['scenario']/Path(item['path']).name
            items.append((path,item))
    (a.output/'experiment.json').write_text(json.dumps(dict(command=sys.argv,engine=version,
        inputs=len(items),counts=a.counts,windows=a.windows,repeats=a.repeats,
        purpose='Regression workload for native UDP host threshold semantics; no malicious labels',
        config='Custom rules enabled; flow/host memcap 16 MiB; TCP checksum validation disabled',
        udp_control='Unthresholded stateless UDP rule must match every decoder UDP packet'),indent=2)+'\n')
    with (a.output/'runs.jsonl').open('w') as record:
        for path,item in items:
            for count in a.counts:
                for window in a.windows:
                    for repeat in range(a.repeats):
                        dest=a.output/item['scenario']/item['variant']/f'c{count}_w{window}_r{repeat}'
                        dest.mkdir(parents=True)
                        cmd=[str(binary),'-c',str(config.resolve()),'-S',str((a.output/f'c{count}_w{window}.rules').resolve()),
                            '-r',str(path),'-l',str(dest.resolve()),'--runmode','single']
                        settings={'flow.memcap':16777216,'host.memcap':16777216,'stream.checksum-validation':'no',
                            'classification-file':configs/'classification.config','reference-config-file':configs/'reference.config',
                            'threshold-file':(a.output/'empty_threshold.config').resolve()}
                        for key,value in settings.items():cmd+=['--set',f'{key}={value}']
                        started=time.monotonic()
                        with (dest/'console.log').open('w') as log:proc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=60)
                        row=dict(command=cmd,returncode=proc.returncode,elapsed_s=time.monotonic()-started,
                            scenario=item['scenario'],source=item['source'],method=item['variant'],replicas=item['replicas'],
                            target=item.get('target_peak'),count=count,window=window,repeat=repeat)
                        if not proc.returncode:
                            metrics,native=read_result(dest/'eve.json');row.update(metrics=metrics,native_stats=native)
                        record.write(json.dumps(row)+'\n');record.flush()
                        if proc.returncode:raise RuntimeError(f'Engine failure in {dest}')
                        if metrics['decoder_invalid'] or metrics['udp_control']!=metrics['udp_packets']:
                            raise RuntimeError(f'UDP match/decode control failed in {dest}')
            print(f'completed {item["scenario"]} {item["variant"]}',flush=True)


if __name__=='__main__':main()
