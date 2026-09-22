import collections,json,math,random,re,statistics as st
from pathlib import Path
D=Path(__file__).resolve().parent
state=json.loads((D/'state.json').read_text())
assert state['completed'] and not state['cleanup_errors'],'incomplete run'
rows=[json.loads(x) for x in (D/'samples.jsonl').read_text().splitlines()]
def pct(a,p):return sorted(a)[max(0,math.ceil(len(a)*p)-1)]
def snap(s):
 lines=s.splitlines();out={'system':[int(x) for x in lines[0].split()[1:]],'processes':{},'swap':{}}
 current=None
 for line in lines[1:]:
  if line.startswith('PROCESS '):current=line.split()[1];out['processes'][current]={}
  elif re.match(r'^\d+ \(',line) and current:
   f=line[line.rfind(')')+2:].split();out['processes'][current].update(pid=int(line.split()[0]),ticks=int(f[11])+int(f[12]))
  elif current and line.startswith(('VmRSS:','VmHWM:','VmSwap:')):
   k,v,*_=line.split();out['processes'][current][k[:-1]]=int(v)*1024
  elif line.startswith(('pswpin ','pswpout ')):
   k,v=line.split();out['swap'][k]=int(v)
 return out
output={'commit':state['commit'],'throughput':{},'latency':{},'paired':{},'failures':[],'transfers':[]}
for r in rows:
 if r['kind']!='throughput':continue
 if not r['ok']:output['failures'].append(r)
 if r['stage']!='measure':continue
 rec={k:r[k] for k in ('mode','direction','round','mib_s')};rec['hosts']={}
 for host in ('router','amsterdam'):
  b,a=[snap(r[key][host]) for key in ('resources_before','resources_after')]
  delta=[y-x for x,y in zip(b['system'],a['system'])];total=sum(delta[:8]);cpus=3 if host=='router' else 1
  v={'system_busy_percent':100*(total-delta[3]-delta[4])/total,'system_busy_cores':cpus*(total-delta[3]-delta[4])/total,'softirq_cores':cpus*delta[6]/total,'processes':{},'swap_delta':{k:a['swap'][k]-b['swap'][k] for k in b['swap']}}
  for name,bp in b['processes'].items():
   ap=a['processes'].get(name,{})
   if not bp.get('pid') or bp.get('pid')!=ap.get('pid'):continue
   v['processes'][name]={'cpu_seconds_per_gib':(ap['ticks']-bp['ticks'])/100/.25,'rss_mib':ap.get('VmRSS',0)/2**20,'peak_rss_mib':ap.get('VmHWM',0)/2**20,'swap_mib':ap.get('VmSwap',0)/2**20}
  rec['hosts'][host]=v
 output['transfers'].append(rec)
for mode in ('raw','v2','current'):
 for direction in ('down','up'):
  records=[r for r in output['transfers'] if r['mode']==mode and r['direction']==direction];v=[r['mib_s'] for r in records]
  assert len(v)==6
  output['throughput'][mode+'_'+direction]={'n':len(v),'median_mib_s':st.median(v),'median_mbit_s':st.median(v)*2**20*8/1e6,'min_mib_s':min(v),'max_mib_s':max(v),'values':v}
  if mode!='raw':
   cpu=[r['hosts']['router']['processes']['client.pid']['cpu_seconds_per_gib']+r['hosts']['amsterdam']['processes']['server.pid']['cpu_seconds_per_gib'] for r in records]
   output['throughput'][mode+'_'+direction]['median_proxy_cpu_seconds_per_gib']=st.median(cpu)
 samples=[r['measurement'] for r in rows if r['kind']=='latency' and r['mode']==mode]
 assert len(samples)==300
 output['latency'][mode]={'n':len(samples)}
 for field in ('connect_setup_ms','http_first_response_ms','total_ms'):
  v=[s[field] for s in samples];output['latency'][mode][field]={'p50':st.median(v),'p95':pct(v,.95),'p99':pct(v,.99),'max':max(v)}
rng=random.Random(20260922)
for direction in ('down','up'):
 indexed={(r['round'],r['mode']):r['mib_s'] for r in output['transfers'] if r['direction']==direction}
 ratios=[100*(indexed[i,'current']/indexed[i,'v2']-1) for i in range(1,7)]
 boot=[st.median(rng.choices(ratios,k=6)) for _ in range(10000)]
 output['paired'][direction]={'current_vs_v2_percent':ratios,'median_percent':st.median(ratios),'paired_median_bootstrap_95ci':[pct(boot,.025),pct(boot,.975)]}
(D/'summary.json').write_text(json.dumps(output,indent=2)+'\n')
for k,v in output['throughput'].items():print(k,v)
print('latency',output['latency'])
print('paired',output['paired'])
