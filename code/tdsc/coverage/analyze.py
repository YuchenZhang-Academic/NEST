"""Report all frozen templates, including zero-admission and no-effect cases."""
from collections import Counter,defaultdict
import ipaddress
import json
from pathlib import Path
import sys
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

root=Path(sys.argv[1]).resolve();out=root/'analysis';out.mkdir(exist_ok=True)
figdir=root/'figures';figdir.mkdir(exist_ok=True)
admitted=json.loads((root/'admission.json').read_text())['episodes']
structure=json.loads((root/'structure.json').read_text())
runs=[json.loads(s) for s in (root/'raw/host_policy/reparsed_runs.jsonl').read_text().splitlines()]
assert len(runs)==sum(r['usable'] for r in admitted)*3*3*4*3*2
assert all(r['returncode']==0 for r in runs)
index={};flat=[]
fields=['udp_packets','udp_control','src_alerts','dst_alerts','global_alerts','src_by_host','dst_by_host']
for r in runs:
    key=(r['source'],r['target'] or 0,r['method'],r['count'],r['window'])
    if key in index:assert all(index[key]['metrics'][f]==r['metrics'][f] for f in fields)
    else:index[key]=r
    assert r['metrics']['decoder_invalid']==0 and r['metrics']['udp_control']==r['metrics']['udp_packets']
    assert r['metrics']['flow_get_used']==0
    assert r['metrics']['host_memcap'] is None or r['metrics']['host_memcap']==0
    flat.append({**{k:r[k] for k in ['source','scenario','method','target','replicas','count','window','repeat','elapsed_s']},
        **{k:v for k,v in r['metrics'].items() if not isinstance(v,dict)}})
pd.DataFrame(flat).to_csv(out/'runs.csv',index=False)
base=int(ipaddress.IPv4Address('10.0.0.1'))
def fold(row,track,by_replica=False):
    method=row['method'];s=structure[row['source']];result=Counter()
    for host,n in row['metrics'][track+'_by_host'].items():
        if method=='replay':replica=0;unit=host
        else:
            span=s['unit_node_count'] if method=='episode' else 2*s['unit_biflows']
            replica,offset=divmod(int(ipaddress.IPv4Address(host))-base,span)
            assert 0<=replica<row['replicas']
            unit=str(ipaddress.IPv4Address(base+offset))
        original=s['maps'][method][unit]
        result[(replica,original) if by_replica else original]+=n
    return result
def distance(a,b):return sum(abs(a.get(k,0)-b.get(k,0)) for k in a.keys()|b.keys())
conditions=[];tracks=[]
for source in sorted(structure):
    for target in [64,256]:
        for count in [2,4,8,16]:
            for window in [1,10,60]:
                rows={m:index[source,target,m,count,window] for m in ['episode','replay','flow_split']}
                for f in ['udp_packets','udp_control','global_alerts']:
                    assert len({r['metrics'][f] for r in rows.values()})==1
                item=dict(source=source,target=target,count=count,window=window,replicas=rows['episode']['replicas'])
                for track in ['src','dst']:
                    unit=index[source,0,'episode',count,window];reference=fold(unit,track)
                    expected={h:n*item['replicas'] for h,n in reference.items()}
                    expected_each={(i,h):n for i in range(item['replicas']) for h,n in reference.items()}
                    assert distance(fold(rows['episode'],track,True),expected_each)==0
                    for method,row in rows.items():
                        observed=fold(row,track)
                        item[f'{track}_{method}_l1']=distance(observed,expected)
                        item[f'{track}_{method}_alerts']=sum(observed.values())
                    st=structure[source]['tracks'][track]
                    ep=item[f'{track}_episode_alerts'];fl=item[f'{track}_flow_split_alerts']
                    l1=item[f'{track}_flow_split_l1']
                    if not st['host_packets']:reason='no_udp'
                    elif st['split_hosts']==0:reason='host_history_not_split'
                    elif l1:reason='host_response_differs'
                    elif st['max_host_packets']<count:reason='below_count_even_without_window'
                    elif ep==fl==0:reason='zero_response_at_this_window'
                    else:reason='nonzero_response_equal_despite_split'
                    if reason in ['no_udp','host_history_not_split']:assert l1==0
                    tracks.append(dict(source=source,target=target,count=count,window=window,track=track,
                        replicas=item['replicas'],split_hosts=st['split_hosts'],
                        episode_alerts=ep,flow_split_alerts=fl,host_l1=l1,
                        total_delta=fl-ep,reason=reason))
                conditions.append(item)
df=pd.DataFrame(conditions);td=pd.DataFrame(tracks)
df.to_csv(out/'conditions.csv',index=False);td.to_csv(out/'host_conditions.csv',index=False)
coverage=[]
for a in admitted:
    source=a['source'];part=df[df.source==source];host=td[td.source==source]
    different=part[(part.src_flow_split_l1>0)|(part.dst_flow_split_l1>0)]
    aggregate=part[(part.src_flow_split_alerts!=part.src_episode_alerts)|(part.dst_flow_split_alerts!=part.dst_episode_alerts)]
    row=dict(source=source,filename=a['filename'],usable=a['usable'],input_packets=a['input_packets'],
        admitted_packets=a['retained_packets'],retention=a['retained_packets']/a['input_packets'],
        admitted_biflows=a['retained_biflows'],udp_packets=a.get('udp_packets',0),
        shared_nodes=a.get('base',{}).get('shared_nodes',0),
        split_src_hosts=structure.get(source,{}).get('tracks',{}).get('src',{}).get('split_hosts',0),
        split_dst_hosts=structure.get(source,{}).get('tracks',{}).get('dst',{}).get('split_hosts',0),
        settings=len(part),different_host_settings=len(different),different_total_settings=len(aggregate),
        informative_settings=int(((part.src_episode_alerts>0)|(part.dst_episode_alerts>0)).sum()),
        max_host_l1_per_copy=float((host.host_l1/host.replicas).max()) if len(host) else 0)
    coverage.append(row)
cv=pd.DataFrame(coverage);cv.to_csv(out/'coverage.csv',index=False)
td.groupby('reason').size().rename('direction_settings').to_csv(out/'no_effect_and_effect.csv')
report=dict(command=sys.argv,selected=len(cv),usable=int(cv.usable.sum()),
    retained_packets=int(cv.admitted_packets.sum()),input_packets=int(cv.input_packets.sum()),
    median_retention_all_selected=float(cv.retention.median()),udp_templates=int((cv.udp_packets>0).sum()),
    templates_with_split_udp_histories=int(((cv.split_src_hosts>0)|(cv.split_dst_hosts>0)).sum()),
    templates_with_host_effect=int((cv.different_host_settings>0).sum()),
    engine_runs=len(runs),unique_input_policy_settings=len(index),scaled_conditions=len(df),
    episode_host_replication_failures=0,matched_udp_global_controls=True,repeat_host_maps_identical=True,
    invalid_packets=0,flow_get_used_total=0,
    host_memcap_counter_available_runs=sum(r['metrics']['host_memcap'] is not None for r in runs),
    flow_split_host_difference_conditions=int(((df.src_flow_split_l1>0)|(df.dst_flow_split_l1>0)).sum()),
    flow_split_total_difference_conditions=int(((df.src_flow_split_alerts!=df.src_episode_alerts)|(df.dst_flow_split_alerts!=df.dst_episode_alerts)).sum()),
    equal_totals_but_different_hosts_direction_settings=int(((td.total_delta==0)&(td.host_l1>0)).sum()),
    replay_host_difference_conditions=int(((df.src_replay_l1>0)|(df.dst_replay_l1>0)).sum()),
    direction_setting_reasons=td.reason.value_counts().to_dict(),
    elapsed_engine_process_s=sum(r['elapsed_s'] for r in runs),
    limits='Fixed filename sample from one historical library; settings/repeats are not independent captures or detection accuracy')
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
witnesses=[]
for source,track in [('new_11','src'),('new_19','src'),('new_10','src')]:
    ep=index[source,256,'episode',2,60];fl=index[source,256,'flow_split',2,60]
    witnesses.append(dict(source=source,track=track,count=2,window=60,target=256,
        replicas=ep['replicas'],episode_by_original_host=fold(ep,track),
        flow_split_by_original_host=fold(fl,track),
        note='Illustrative cases chosen after observing results; all settings are reported in CSV'))
(out/'witnesses.json').write_text(json.dumps(witnesses,indent=2)+'\n')
plt.rcParams.update({'font.size':9,'pdf.fonttype':42})
def save(fig,name):
    fig.savefig(figdir/f'{name}.pdf',bbox_inches='tight');fig.savefig(figdir/f'{name}.png',dpi=180,bbox_inches='tight');plt.close(fig)
fig,ax=plt.subplots(figsize=(10,3.2),layout='constrained')
ax.bar(cv.source,cv.admitted_packets,color='#0072B2',label='Admitted other packets')
ax.bar(cv.source,cv.udp_packets,color='#E69F00',label='Admitted UDP (included)')
ax.axhline(100,color='gray',ls=':',label='100 original packets per template')
ax.set(ylabel='Packets',xlabel='Fixed selected template',ylim=(0,110));ax.tick_params(axis='x',rotation=60)
ax.legend(ncols=3,loc='upper center',fontsize=8);save(fig,'admission_coverage')
active=list(cv[cv.udp_packets>0].source)
fig,axes=plt.subplots(1,2,figsize=(11,4.6),layout='constrained')
for ax,track in zip(axes,['src','dst']):
    part=td[(td.target==256)&(td.track==track)].copy()
    part['setting']=part['count'].astype(str)+'/'+part.window.astype(str)
    part['delta_per_copy']=part.total_delta/part.replicas
    order=[str(c)+'/'+str(w) for c in [2,4,8,16] for w in [1,10,60]]
    mat=part.pivot(index='source',columns='setting',values='delta_per_copy').loc[active,order]
    bound=max(1,abs(mat.to_numpy()).max());im=ax.imshow(mat,aspect='auto',cmap='RdBu_r',vmin=-bound,vmax=bound)
    for i,source in enumerate(active):
        for j,setting in enumerate(order):
            cell=part[(part.source==source)&(part.setting==setting)].iloc[0]
            if cell.total_delta==0 and cell.host_l1>0:ax.text(j,i,'*',ha='center',va='center',fontsize=14)
    ax.set_xticks(range(12),order,rotation=90);ax.set_yticks(range(len(active)),active)
    ax.set(title=track+' host tracking; target 256',xlabel='Count / window (s)')
    fig.colorbar(im,ax=ax,label='Independent-flow minus episode alerts / copy')
fig.supxlabel('* Equal totals, different per-original-host responses',fontsize=9)
save(fig,'udp_host_effect_grid')
fig,ax=plt.subplots(figsize=(8,3),layout='constrained')
labels={'no_udp':'No UDP observations','host_history_not_split':'Matching host history unchanged',
    'host_response_differs':'Split history: response differs',
    'below_count_even_without_window':'Split history: count threshold too high',
    'zero_response_at_this_window':'Split history: zero response in window',
    'nonzero_response_equal_despite_split':'Split history: same nonzero response'}
totals=td.reason.value_counts().reindex(list(labels))
ax.barh([labels[k] for k in totals.index],totals.values,color='#0072B2')
for i,n in enumerate(totals.values):ax.text(n+2,i,str(n),va='center')
ax.set(xlabel='Directional settings (source/destination counted separately)',xlim=(0,max(totals.values)*1.17));save(fig,'effect_boundaries')
print(json.dumps(report,indent=2))
