import json,statistics,collections,gzip
from pathlib import Path
D=Path(__file__).resolve().parent
def read(name):
 p=D/name
 return p.read_text() if p.exists() else gzip.decompress(p.with_suffix(p.suffix+'.gz').read_bytes()).decode()
samples=[json.loads(x) for x in read('samples.jsonl').splitlines()]
data={host:[json.loads(x) for x in read(host+'-tcp.jsonl').splitlines()] for host in ('router','node-A')}
out=[]
for tr in samples:
 if tr['kind']!='throughput' or tr['stage']=='warm':continue
 port=47943 if tr['mode']=='raw' else 47941
 # Select the large transfer by receiver port and lifetime; a warm flow is <5 MiB.
 candidates=[s for r in data['node-A'] if tr['start']-.5<=r['time']<=tr['finish']+.5 for s in r['sockets'] or [] if s['sport']==port and s['state']==1 and s['dst']!='127.0.0.1' and s['tcp']['bytes_received']>8<<20]
 progress=collections.defaultdict(list)
 for s in candidates:progress[s['dport']].append(s['tcp']['bytes_received'])
 peer=max(progress,key=lambda p:max(progress[p])-min(progress[p]))
 assert max(progress[peer])-min(progress[peer])>int(tr['size'].removesuffix('MB'))*(1<<20)*.5,(tr,progress)
 # Match both ends by the TCP four-tuple, not by wall-clock equality.
 sender=[dict(s,time=r['time']) for r in data['router'] for s in r['proc_sockets'] or [] if s['sport']==peer and s['dport']==port and s['state']=='01']
 recv=[dict(s,time=r['time']) for r in data['node-A'] for s in r['sockets'] or [] if s['sport']==port and s['dport']==peer and s['state']==1 and s['dst']!='127.0.0.1']
 rows={host:[r for r in data[host] if records[0]['time']-.2<=r['time']<=records[-1]['time']+.2] for host,records in [('router',sender),('node-A',recv)]}
 r=dict(mode=tr['mode'],round=tr['round'],stage=tr['stage'],mib_s=tr.get('mib_s'),ok=tr['ok'],start=tr['start'],finish=tr['finish'],sender_samples=len(sender),receiver_samples=len(recv))
 if sender:
  r.update(sender_ports=sorted(set(s['sport'] for s in sender)),cwnd_range=[min(int(s['cwnd']) for s in sender),max(int(s['cwnd']) for s in sender)],max_tx_queue=max(int(s['queues'].split(':')[0],16) for s in sender),max_unrecovered_rto=max(int(s['unrecovered_rto'],16) for s in sender),zero_window_timer_samples=sum(s['timer'].startswith('04:') for s in sender))
 if recv:
  tcp=[s['tcp'] for s in recv];r.update(receiver_ports=sorted(set(s['dport'] for s in recv)),max_rx_queue=max(s['rqueue'] for s in recv),rcv_wnd_range=[min(s.get('rcv_wnd',-1) for s in tcp),max(s.get('rcv_wnd',-1) for s in tcp)],rcv_ooopack=max(s.get('rcv_ooopack',-1) for s in tcp),received_last=max(s['bytes_received'] for s in tcp),max_last_data_recv_ms=max(s['last_data_recv_ms'] for s in tcp),rtt_us=statistics.median(s['rtt_us'] for s in tcp))
  windows=[s.get('rcv_wnd',-1) for s in tcp if s['bytes_received']>1<<20];r['data_rcv_wnd_range']=[min(windows),max(windows)] if windows else None
  flat=[]
  for a,b in zip(recv,recv[1:]):
   if a['dport']==b['dport'] and a['tcp']['bytes_received']==b['tcp']['bytes_received']:flat.append((a['time'],b['time'],a['tcp']['bytes_received']))
  r['flat_intervals']=flat
 for host,rs in rows.items():
  procs=collections.defaultdict(list)
  for row in rs:
   for name,p in row['processes'].items():
    f=p['stat'].split();procs[name].append((int(f[0]),int(f[13])+int(f[14]),int(f[11]),p['memory']))
  r[host+'_process_deltas']={n:{'ticks':v[-1][1]-v[0][1],'major_faults':v[-1][2]-v[0][2],'memory_last':v[-1][3]} for n,v in procs.items() if v[0][0]==v[-1][0]}
 memory=[row for row in samples if row['kind']=='memory' and row['mode']==tr['mode'] and row['round']==tr['round']]
 if len(memory)==2:
  fields=[m['output'].splitlines()[0].split() for m in memory]
  r['server_full_transfer_ticks']=int(fields[1][13])+int(fields[1][14])-int(fields[0][13])-int(fields[0][14])
  r['server_full_transfer_major_faults']=int(fields[1][11])-int(fields[0][11])
 if recv and 'skmem' in recv[0]:
  r['rcv_buf_range']=[min(s['skmem']['rcv_buf'] for s in recv),max(s['skmem']['rcv_buf'] for s in recv)]
  r['local_socket_drops']=max(s['skmem']['drops'] for s in recv)
 out.append(r)
(D/'summary.json').write_text(json.dumps(out,indent=2)+'\n')
for r in out:print({k:v for k,v in r.items() if k in ['mode','round','stage','mib_s','cwnd_range','max_unrecovered_rto','zero_window_timer_samples','max_rx_queue','data_rcv_wnd_range','rcv_ooopack','flat_intervals']})
for mode in ['raw','v2','current']:
 vals=[r['mib_s'] for r in out if r['mode']==mode and r['ok']];print(mode,len(vals),statistics.median(vals),min(vals),max(vals))
