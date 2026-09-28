"""Freeze filename-only selection before admission or engine observations."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

project=Path(sys.argv[1]).resolve()
out=Path(sys.argv[2]).resolve()
out.mkdir(parents=True,exist_ok=False)
archive=project/'old/graph/code_12k/gen_output'
prior=project/'new/experiments/tdsc'
used={}
def walk(value,manifest):
    if isinstance(value,str) and ('gen_output/' in value or 'trace_dataset_pre1_1MB_100/' in value):
        name=Path(value).name.split('.')[0]+'.pcap'
        if (archive/name).exists():used.setdefault(name,[]).append(str(manifest.relative_to(project)))
    elif isinstance(value,dict):
        for v in value.values():walk(v,manifest)
    elif isinstance(value,list):
        for v in value:walk(v,manifest)
for directory in ['route_probe_20260909','iteration1','iteration2','iteration3','iteration4']:
    for path in (prior/directory).rglob('*.json'):
        if path.name in ['selection.json','results.json','archived_availability.json','generation.json','experiment.json']:
            walk(json.loads(path.read_text()),path)
names=sorted(p.name for p in archive.glob('*.pcap'))
salt='NEST-TDSC-coverage-v1\n'
ranked=sorted((hashlib.sha256((salt+n).encode()).hexdigest(),n) for n in names if n not in used)
selected=[dict(source=f'new_{i:02d}',filename=n,rank_digest=h) for i,(h,n) in enumerate(ranked[:20])]
manifest=dict(command=sys.argv,rule='Ascending SHA256 of fixed salt plus filename; first 20 eligible files; no replacement after admission',
    salt=salt,archive_files=len(names),excluded={k:sorted(set(v)) for k,v in sorted(used.items())},
    eligible=len(ranked),selected=selected,
    design=dict(targets=[64,256],unit_replicas=1,methods=['episode','replay','flow_split'],
        counts=[2,4,8,16],windows_s=[1,10,60],repeats=2,flow_and_host_memcap=16777216),
    scope='New experimental files from the same historical library, not independent held-out captures')
(out/'selection.json').write_text(json.dumps(manifest,indent=2)+'\n')
(out/'inputs/original').mkdir(parents=True,exist_ok=False)
for row in selected:shutil.copy2(archive/row['filename'],out/'inputs/original'/row['filename'])
old={hashlib.sha256((archive/n).read_bytes()).hexdigest():n for n in used}
seen={};duplicates=[]
for row in selected:
    digest=hashlib.sha256((out/'inputs/original'/row['filename']).read_bytes()).hexdigest()
    if digest in old or digest in seen:
        duplicates.append(dict(source=row['source'],duplicate_of=old.get(digest,seen.get(digest))))
    seen[digest]=row['source']
(out/'input_identity.json').write_text(json.dumps(dict(
    purpose='Check selected PCAP bytes are new relative to prior inputs and one another',
    selected=len(selected),duplicates=duplicates),indent=2)+'\n')
print(f'{len(names)} total, {len(used)} excluded, {len(selected)} selected before reading packet content')
