import os, pathlib, socket, subprocess, time
base=pathlib.Path(__file__).parent
reserve=socket.socket(); reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]; reserve.close()
env=os.environ.copy(); env.update(CLIENT_LISTEN_ADDR=f'127.0.0.1:{port}',CLIENT_MAX_CONNECTIONS='2',HANDSHAKE_TIMEOUT='250ms',SERVER_ADDR='127.0.0.1:1',OBFS_PSK='01234567890123456789012345678901',LOG_LEVEL='error',SHUTDOWN_TIMEOUT='100ms')
connections=[]
p=subprocess.Popen([str(base/'s5client')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
 deadline=time.monotonic()+3
 while True:
  try:
   c=socket.create_connection(('127.0.0.1',port),timeout=.1); connections.append(c); break
  except OSError:
   if time.monotonic()>deadline: raise
   time.sleep(.01)
 # Greeting confirms that each connection owns a slot before opening another.
 for index in range(2):
  if index: c=socket.create_connection(('127.0.0.1',port),timeout=1); connections.append(c)
  c.sendall(bytes([5,1,0])); assert c.recv(2)==bytes([5,0])
 extra=socket.create_connection(('127.0.0.1',port),timeout=1); connections.append(extra)
 try: assert extra.recv(1)==b''
 except ConnectionResetError: pass
 print('CLIENT_MAX_CONNECTIONS=2: third connection rejected')
 time.sleep(.35)
 for c in connections[:2]: assert c.recv(1)==b''
 print('HANDSHAKE_TIMEOUT=250ms: incomplete requests closed')
 recovered=socket.create_connection(('127.0.0.1',port),timeout=1); connections.append(recovered)
 recovered.sendall(bytes([5,1,0])); assert recovered.recv(2)==bytes([5,0])
 print('slot released: next connection completed greeting')
finally:
 p.terminate()
 for c in connections: c.close()
 try: p.wait(timeout=2)
 except subprocess.TimeoutExpired: p.kill(); p.wait()
