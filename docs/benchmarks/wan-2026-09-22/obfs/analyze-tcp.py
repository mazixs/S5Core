import collections,gzip,json,statistics as st
from pathlib import Path
D=Path(__file__).resolve().parent
cal=json.loads((D/'clock-calibration.json').read_text())
offset=cal['amsterdam']['best']['remote_minus_local_seconds']
rows=[]
path=D/'amsterdam-monitor.log'
text=path.read_text() if path.exists() else gzip.decompress(path.with_suffix('.log.gz').read_bytes()).decode()
for line in text.splitlines():
 try:rows.append(json.loads(line))
 except ValueError:pass
samples=[json.loads(x) for x in (D/'samples.jsonl').read_text().splitlines()]
out=[]
for tr in samples:
 if tr['kind']!='throughput' or tr['stage']!='measure':continue
 port=47943 if tr['mode']=='raw' else 47941
 grouped=collections.defaultdict(list)
 for r in rows:
  t=r['time']-offset
  if not tr['start']-.3<=t<=tr['finish']+.3:continue
  for s in r.get('sockets') or []:
   if s['sport']==port and s['state']==1 and s['dst'] not in ('127.0.0.1','::1') and s.get('tcp'):
    grouped[s['dport']].append(s)
 metric='bytes_acked' if tr['direction']=='down' else 'bytes_received'
 if not grouped:continue
 stream=max(grouped.values(),key=lambda ss:max(x['tcp'].get(metric,0) for x in ss))
 progress=max(x['tcp'].get(metric,0) for x in stream)
 if progress<128*2**20:continue
 tcp=[s['tcp'] for s in stream]
 row={k:tr[k] for k in ('mode','direction','round','mib_s')}
 row.update(peer_port=stream[0]['dport'],samples=len(tcp),sampled_bytes_max=progress,rtt_ms_median=st.median(x['rtt_us'] for x in tcp)/1000,
            cwnd_range=[min(x['cwnd'] for x in tcp),max(x['cwnd'] for x in tcp)],
            rcv_wnd_range=[min(x.get('rcv_wnd',0) for x in tcp),max(x.get('rcv_wnd',0) for x in tcp)],
            max_receiver_queue=max(x['rqueue'] for x in stream))
 if tr['direction']=='down':
  row['sampled_sender_total_retrans_max']=max(x['total_retrans'] for x in tcp)
  row['sampled_sender_bytes_retrans_max']=max(x.get('bytes_retrans',0) for x in tcp)
  row['sampled_sender_rwnd_limited_us_max']=max(x.get('rwnd_limited_us',0) for x in tcp)
 else:row['receiver_out_of_order_packets_max']=max(x.get('rcv_ooopack',0) for x in tcp)
 out.append(row)
(D/'tcp-summary.json').write_text(json.dumps(out,indent=2)+'\n')
print('Matched',len(out),'of 36 complete bulk transfers; counters are sampled, not final connection totals.')
