import os,pathlib,resource,socket,subprocess,time
base=pathlib.Path(__file__).parent
reserve=socket.socket();reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1];reserve.close()
env=os.environ.copy();env.update(CLIENT_LISTEN_ADDR=f'127.0.0.1:{port}',SERVER_ADDR='127.0.0.1:1',OBFS_PSK='01234567890123456789012345678901',LOG_LEVEL='warn',SHUTDOWN_TIMEOUT='100ms')
def limits():resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
connections=[]
with (base/'client-accept.log').open('w') as log:
 p=subprocess.Popen([str(base/'s5client')],env=env,stdout=log,stderr=log,preexec_fn=limits)
 try:
  deadline=time.monotonic()+3
  while True:
   try:
    c=socket.create_connection(('127.0.0.1',port),timeout=.1);connections.append(c);break
   except OSError:
    if time.monotonic()>deadline:raise
    time.sleep(.01)
  for _ in range(72):
   try:connections.append(socket.create_connection(('127.0.0.1',port),timeout=.01))
   except OSError:break
  def cpu():
   fields=pathlib.Path(f'/proc/{p.pid}/stat').read_text().split()
   return (int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK')
  a=cpu();start=time.monotonic();time.sleep(.2);used=cpu()-a;wall=time.monotonic()-start
  print(f'client_NOFILE=64 open_client_sockets={len(connections)} observed_wall={wall:.3f}s child_CPU={used:.3f}s utilization_one_core={used/wall:.0%}')
 finally:
  p.terminate()
  for c in connections:c.close()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait()
lines=(base/'client-accept.log').read_text().splitlines()
errors=[s for s in lines if 'Accept failed' in s]
print(f'accept_errors={len(errors)} log_bytes={(base/"client-accept.log").stat().st_size}')
print(errors[0] if errors else '\n'.join(lines[:4]))
