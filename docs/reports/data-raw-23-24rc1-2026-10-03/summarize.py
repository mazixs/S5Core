import collections,json,pathlib,statistics
root=pathlib.Path(__file__).resolve().parent
groups=collections.defaultdict(list)
records=[]
for f in sorted((root/'cells').glob('*/*/result.json')):
 d=f.parent
 result=json.loads(f.read_text());run=json.loads((d/'run.json').read_text());spec=json.loads((d/'spec.json').read_text())
 rec={k:spec[k] for k in ('id','series','variant','transport','round')}
 rec.update(result=result['result'],run=run)
 records.append(rec)
 groups[(spec['series'],spec['variant'],spec['transport'])].append(rec)
out={'groups':{},'counts':dict(collections.Counter(r['run']['status'] for r in records)),'errors':sum(s['errors'] for r in records for s in r['result'].values()),'samples':sum(s['n'] for r in records for s in r['result'].values()),'cells':records}
for key,rows in groups.items():
 g={'rounds':len(rows),'scenarios':{}}
 for name in rows[0]['result']:
  metrics=collections.defaultdict(list)
  for r in rows:
   s=r['result'][name]
   for k in ('p50_ms','p90_ms','p99_ms','mbps','n','errors'):
    if k in s:metrics[k].append(s[k])
   for k,v in s.get('extra',{}).items():metrics['extra.'+k].append(v)
  g['scenarios'][name]={k:{'median':statistics.median(v),'min':min(v),'max':max(v),'values':v} for k,v in metrics.items()}
 if key[1]!='raw':
  cpu=[sum(r['run']['after'][p]['cpu_s']-r['run']['before'][p]['cpu_s'] for p in ('server','client')) for r in rows]
  g['proxy_cpu_s']={'median':statistics.median(cpu),'min':min(cpu),'max':max(cpu),'values':cpu}
 out['groups']['/'.join(key)]=g
(root/'comparison-summary.json').write_text(json.dumps(out,indent=2)+'\n')
print('counts',out['counts'],'errors',out['errors'],'samples',out['samples'])
for key,g in out['groups'].items():
 if key.startswith('game-loss'):
  m=g['scenarios']['game/64hz-200b']
  print(key,{k:round(v['median'],3) for k,v in m.items() if k in ('p50_ms','p99_ms','extra.loss_pct','extra.breaks')})
