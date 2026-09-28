"""Reparse native logs, preserving an unavailable host counter as null, not zero."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_host_policy import read_result

root=Path(sys.argv[1]).resolve()
directory=root/'raw/host_policy'
changed=missing=total=0
with (directory/'reparsed_runs.jsonl').open('w') as output:
    for line in (directory/'runs.jsonl').open():
        row=json.loads(line)
        path=directory/row['scenario']/row['method']/f'c{row["count"]}_w{row["window"]}_r{row["repeat"]}'/'eve.json'
        metrics,native=read_result(path)
        assert native==row['native_stats']
        for field,value in metrics.items():
            if field!='host_memcap':assert value==row['metrics'][field],(path,field)
        changed+=row['metrics']['host_memcap']!=metrics['host_memcap']
        missing+=metrics['host_memcap'] is None
        row['metrics']=metrics;output.write(json.dumps(row)+'\n');total+=1
(root/'reparse_verification.json').write_text(json.dumps(dict(command=sys.argv,runs=total,
    missing_host_counter_runs=missing,corrected_missing_counter_values=changed,
    all_alert_and_other_metrics_unchanged=True,
    reason='This engine does not export host.memcap; null means unavailable. Original runs.jsonl is preserved.'),indent=2)+'\n')
print(f'Reparsed {total}; missing host counter {missing}; all other metrics unchanged')
