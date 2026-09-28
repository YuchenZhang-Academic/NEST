"""Summarize the composed-workload experiment without treating repeats as datasets."""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
from statistics import median
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

METHODS = ['episode','replay','flow_split']
LABELS = dict(episode='Episode composition', replay='Repeated replay', flow_split='Independent flows')
COLORS = dict(episode='#0072B2',replay='#D55E00',flow_split='#009E73')
STYLES = dict(episode=dict(marker='o', markersize=8, markerfacecolor='none', linestyle='-', zorder=3),
              replay=dict(marker='s', markersize=5, linestyle=':'),
              flow_split=dict(marker='x', markersize=5, linestyle='--'))


def write_csv(path, rows):
    with path.open('w') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader();writer.writerows(rows)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection',type=Path,required=True)
    parser.add_argument('--runs',type=Path,nargs='+',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    manifest=json.loads(args.selection.read_text())
    inputs={(r['scenario'],r['variant']):r for r in manifest['variants']}
    groups=defaultdict(list);failed=[]
    for directory in args.runs:
        for line in (directory/'runs.jsonl').read_text().splitlines():
            row=json.loads(line)
            if row['returncode']:
                failed.append(row);continue
            item=inputs[row['scenario'],row['variant']]
            key=(item['source'],item['target_peak'],row['variant'],row['idle'],row['memcap'])
            groups[key].append(row['metrics'])
    fields=['decoder.invalid','unique_exported_biflows','flow.get_used',
            'flow.emerg_mode_entered','extra_flow_records','export_accounting_gap','app_transactions']
    summary=[]
    for key, values in sorted(groups.items()):
        row=dict(zip(['source','target','method','idle','memcap'],key));row['repeats']=len(values)
        for field in fields:
            numbers=[v[field] for v in values]
            row[field]=median(numbers);row[field+'_min']=min(numbers);row[field+'_max']=max(numbers)
        summary.append(row)
    write_csv(args.output/'engine_summary.csv',summary)
    design=[{key: row[key] for key in ['source','target_peak','variant','replicas','packets','bytes',
            'biflows','nodes','shared_nodes','proxy_peak','duration_s','elapsed_s']} for row in manifest['variants']]
    write_csv(args.output/'construction.csv',design)
    write_csv(args.output/'admission.csv',[dict(source=e['label'],input_packets=e['input_packets'],
        retained_packets=e['retained_packets'],excluded_packets=e['excluded_packets'],
        retained_biflows=e['retained_biflows'],excluded_biflows=e['excluded_biflows']) for e in manifest['episodes']])
    sources=[e['label'] for e in manifest['episodes']]
    high=max(row['memcap'] for row in summary)
    idles=sorted({row['idle'] for row in summary})
    lookup={(r['source'],r['target'],r['method'],r['idle'],r['memcap']):r for r in summary}
    excess=[]
    for row in summary:
        reference=lookup[row['source'],row['target'],row['method'],row['idle'],high]
        excess.append({key:row[key] for key in ['source','target','method','idle','memcap']} |
            dict(additional_accounting_gap=row['export_accounting_gap']-reference['export_accounting_gap'],
                 high_capacity_invalid=reference['decoder.invalid']))
    write_csv(args.output/'additional_gap.csv',excess)
    plt.rcParams.update({'font.size':9,'pdf.fonttype':42,'ps.fonttype':42})
    def panels():
        fig,axes=plt.subplots(2,3,figsize=(11,6),layout='constrained')
        for ax in axes.flat[len(sources):]:ax.set_visible(False)
        return fig,list(axes.flat)[:len(sources)]
    def finish(fig,name):
        handles,labels=fig.axes[0].get_legend_handles_labels()
        fig.legend(handles,labels,loc='outside lower center',ncols=3,frameon=False)
        fig.savefig(args.output/f'{name}.pdf');fig.savefig(args.output/f'{name}.png',dpi=180);plt.close(fig)
    fig,axes=panels()
    for source,ax in zip(sources,axes):
        for method in METHODS:
            rows=sorted([r for r in summary if r['source']==source and r['method']==method and r['memcap']==high and r['idle']==60],key=lambda r:r['target'])
            ax.plot([r['target'] for r in rows],[r['unique_exported_biflows'] for r in rows],label=LABELS[method],color=COLORS[method],**STYLES[method])
        ax.set(xscale='log',yscale='log',title=source,xlabel='Requested idle-model peak',ylabel='Exported distinct biflows')
        ax.grid(alpha=.2)
    finish(fig,'target_to_engine_flows')
    fig,axes=panels()
    for source,ax in zip(sources,axes):
        for method in METHODS:
            rows=sorted([r for r in design if r['source']==source and r['variant']==method],key=lambda r:r['target_peak'])
            ax.plot([r['target_peak'] for r in rows],[r['shared_nodes'] for r in rows],label=LABELS[method],color=COLORS[method],**STYLES[method])
        ax.set(xscale='log',title=source,xlabel='Requested idle-model peak',ylabel='Nodes with multiple peers');ax.grid(alpha=.2)
    finish(fig,'shared_nodes')
    for idle in idles:
        fig,axes=panels()
        for source,ax in zip(sources,axes):
            for method in METHODS:
                rows=sorted([r for r in summary if r['source']==source and r['method']==method and r['target']==1024 and r['idle']==idle],key=lambda r:r['memcap'])
                x=[r['memcap']/1024 for r in rows]
                ax.plot(x,[r['flow.get_used'] for r in rows],color=COLORS[method],label=LABELS[method],**STYLES[method])
                ax.fill_between(x,[r['flow.get_used_min'] for r in rows],[r['flow.get_used_max'] for r in rows],color=COLORS[method],alpha=.15)
            ax.set(xscale='log',yscale='symlog',title=source,xlabel='Flow memcap (KiB)',ylabel='Native flow.get_used');ax.grid(alpha=.2)
        finish(fig,f'pressure_idle{idle}')
    report=dict(runs=sum(len(v) for v in groups.values()),failures=len(failed),
        decoder_invalid_max=max(v['decoder.invalid'] for vs in groups.values() for v in vs),
        sources=len(sources),inputs=len(inputs),high_memcap=high,
        high_capacity_unique_flow_matches=sum(v['unique_exported_biflows']==inputs[r['scenario'],r['variant']]['biflows']
          for directory in args.runs for r in [json.loads(line) for line in (directory/'runs.jsonl').read_text().splitlines()]
          if not r['returncode'] and r['memcap']==high for v in [r['metrics']]),
        high_capacity_runs=sum(len(values) for key,values in groups.items() if key[-1]==high),
        range_definition='Observed min/max of three engine repeats; not a confidence interval',
        claim='Capability of derived episode composition, not neural scale or generation diversity')
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    (args.output/'failures.json').write_text(json.dumps(failed,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
