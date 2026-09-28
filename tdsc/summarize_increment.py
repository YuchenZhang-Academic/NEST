"""Summarize native host-policy controls and phase-planning validation."""
import argparse
import json
from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from summarize_pressure import METHODS, LABELS, COLORS, STYLES


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    a=p.parse_args();out=a.root/'summary';out.mkdir(exist_ok=True)
    runs=[json.loads(s) for s in (a.root/'host_policy/runs.jsonl').read_text().splitlines()]
    data=pd.DataFrame([{**{k:v for k,v in r.items() if k not in ['metrics','native_stats','command']},
                        **r['metrics']} for r in runs])
    data['target']=data.target.fillna(0).astype(int)
    data.to_csv(out/'host_runs.csv',index=False)
    keys=['source','target','method','replicas','count','window']
    fields=['udp_packets','udp_control','src_alerts','dst_alerts','global_alerts','src_hosts','dst_hosts']
    variation=data.groupby(keys)[fields].nunique().max().max()
    assert variation==1, 'Unexpected repeat variation: inspect before aggregating'
    summary=data.groupby(keys,as_index=False)[fields].first()
    summary.to_csv(out/'host_summary.csv',index=False)
    pairs=summary.pivot(index=['source','target','count','window'],columns='method',values=fields)
    for metric in ['udp_packets','udp_control','global_alerts']:
        assert (pairs[metric].nunique(axis=1)==1).all()
    units=summary[(summary.target==0)&(summary.method=='episode')].set_index(['source','count','window'])
    replication=[]
    for _,row in summary[summary.target>0].iterrows():
        ref=units.loc[(row.source,row['count'],row.window)]
        item={key:row[key] for key in keys}
        for track in ['src','dst']:
            metric=track+'_alerts';expected=int(ref[metric]*row.replicas)
            item[track+'_expected']=expected;item[track+'_actual']=int(row[metric])
            item[track+'_difference']=int(row[metric])-expected
        replication.append(item)
    checks=pd.DataFrame(replication);checks.to_csv(out/'host_replication.csv',index=False)
    own=checks[checks.method=='episode']
    assert (own[['src_difference','dst_difference']]==0).all().all()
    compare=[]
    for method in ['replay','flow_split']:
        part=checks[checks.method==method]
        compare.append(dict(method=method,conditions=len(part),
            source_differences=int((part.src_difference!=0).sum()),
            destination_differences=int((part.dst_difference!=0).sum()),
            either_differences=int(((part.src_difference!=0)|(part.dst_difference!=0)).sum())))
    phase=json.loads((a.root/'phase_inputs_ns/plans.json').read_text())['plans']
    pd.DataFrame(phase).to_csv(out/'phase_plans.csv',index=False)
    feasible=[r for r in phase if r['status']=='feasible']
    rescued=[r for r in feasible if r['naive_peak']<r['target']]
    report=dict(host_runs=len(data),host_unique_settings=len(summary),
        decode_invalid_total=int(data.decoder_invalid.sum()),
        flow_pressure_total=int(data.flow_get_used.sum()),host_memcap_total=int(data.host_memcap.sum()),
        repeat_identical=True,matched_udp_and_global_controls=True,
        episode_replication_conditions=len(own),episode_replication_mismatches=0,
        paired_baseline_deviations=compare,phase_plans=len(phase),
        phase_status_counts=pd.Series([r['status'] for r in phase]).value_counts().to_dict(),
        naive_target_misses=sum(r['naive_peak']<r['target'] for r in phase),
        feasible_naive_misses=len(rescued),rescued_plans=rescued,
        scope='Native UDP threshold regression and idle-model planning; no attack labels or detection accuracy')
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    plt.rcParams.update({'font.size':9,'pdf.fonttype':42,'ps.fonttype':42})
    def save(fig,name):
        fig.savefig(out/f'{name}.pdf',bbox_inches='tight')
        fig.savefig(out/f'{name}.png',dpi=180,bbox_inches='tight');plt.close(fig)
    fig,axes=plt.subplots(1,3,figsize=(10,3.1),layout='constrained')
    for ax,metric,title in zip(axes,['src_alerts','dst_alerts','global_alerts'],['Source tracking','Destination tracking','Global control']):
        for method in METHODS:
            rows=summary[(summary.source=='archive_0')&(summary.method==method)&(summary['count']==2)&(summary.window==60)].sort_values('replicas')
            ax.plot(rows.replicas,rows[metric],label=LABELS[method],color=COLORS[method],**STYLES[method])
        ax.set(title=title,xlabel='Episode copies',ylabel='Native UDP rule alerts');ax.grid(alpha=.2)
    fig.legend(*axes[0].get_legend_handles_labels(),loc='outside lower center',ncols=3,frameon=False)
    save(fig,'host_policy_example')
    fig,axes=plt.subplots(1,2,figsize=(9,3.5),layout='constrained')
    for ax,track in zip(axes,['src','dst']):
        rows=checks[(checks.method=='flow_split')&(checks.target==256)].copy()
        rows['setting']=rows['count'].astype(str)+' / '+rows.window.astype(str)
        rows['normalized_difference']=rows[track+'_difference']/rows.replicas
        matrix=rows.pivot(index='source',columns='setting',values='normalized_difference')
        order=[str(c)+' / '+str(w) for c in [2,4,8,16] for w in [1,10,60]]
        matrix=matrix[order];bound=max(1,abs(matrix.to_numpy()).max())
        im=ax.imshow(matrix,aspect='auto',cmap='RdBu_r',vmin=-bound,vmax=bound)
        ax.set_xticks(range(len(order)),order,rotation=90);ax.set_yticks(range(len(matrix)),matrix.index)
        ax.set(title=track+' tracking',xlabel='Count / window (s)')
        fig.colorbar(im,ax=ax,label='Independent-flow minus episode alerts / copy')
    save(fig,'host_policy_grid')
    fig,axes=plt.subplots(1,2,figsize=(9,3.4),layout='constrained')
    for ax,target in zip(axes,[64,256]):
        sources=list(dict.fromkeys(r['source'] for r in phase));phases=['aligned','dense','half_span','separated']
        matrix=[[next(r['naive_peak']/target for r in phase if r['source']==s and r['phase']==h and r['target']==target) for h in phases] for s in sources]
        im=ax.imshow(matrix,aspect='auto',vmin=0,vmax=1.2,cmap='viridis')
        for i,s in enumerate(sources):
            for j,h in enumerate(phases):
                r=next(r for r in phase if r['source']==s and r['phase']==h and r['target']==target)
                label=str(r['naive_peak'])+('/'+str(r['achieved_peak']) if r['status']=='feasible' else '/X')
                ax.text(j,i,label,ha='center',va='center',color='white' if matrix[i][j]<.6 else 'black',fontsize=8)
        ax.set_xticks(range(4),phases,rotation=20);ax.set_yticks(range(5),sources)
        ax.set(title=f'Target {target}: naive / planned peak')
        fig.colorbar(im,ax=ax,label='Naive peak / target')
    save(fig,'phase_feasibility')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
