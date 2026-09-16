#!/usr/bin/env python3
"""Loopback-only MCP parser-differential probes.

Synthetic requests only. The target and upstream counters are hard-coded to
127.0.0.1 so this demo cannot be repointed at a remote service.
"""
import http.client, json, socket, urllib.request

HOST='127.0.0.1'; PORT=18787
HITS_URL='http://127.0.0.1:19000/hits'

def hits():
    with urllib.request.urlopen(HITS_URL, timeout=3) as r:
        return json.load(r)['hits']

def post_raw(body: bytes, path='/mcp', headers=None):
    c=http.client.HTTPConnection(HOST, PORT, timeout=5)
    h={'Content-Type':'application/json','X-Heraclitus-Agent':'parser-lab',
       'X-Heraclitus-Run':'parser-lab','X-Heraclitus-User':'sandbox',
       'X-Heraclitus-Server':'safe-stub','X-Heraclitus-Environment':'lab',
       'mcp-method':'tools/call'}
    if headers: h.update(headers)
    c.request('POST', path, body=body, headers=h)
    try:
        r=c.getresponse(); data=r.read(1<<20)
        return r.status, data.decode('utf-8','replace')
    finally:
        c.close()

def raw_socket(req: bytes):
    s=socket.create_connection((HOST,PORT),timeout=5)
    s.sendall(req); s.shutdown(socket.SHUT_WR); out=b''
    while True:
        try: chunk=s.recv(65536)
        except socket.timeout: break
        if not chunk: break
        out+=chunk
    s.close(); return out

def probe(name, body, **kw):
    before=hits()
    try: status,response=post_raw(body,**kw)
    except Exception as exc: status=None; response=repr(exc)
    delta=hits()-before
    safe=delta==0 and status not in {200,201,202,204}
    row={'probe':name,'safe':safe,'status':status,'upstream_delta':delta,'response':response[:240]}
    print(json.dumps(row,ensure_ascii=False)); return safe

def main():
    rows=[]
    rows.append(probe('dup-tool-safe-then-dangerous',b'{"jsonrpc":"2.0","id":"d1","method":"tools/call","params":{"name":"lookup_vendor","name":"exec","arguments":{"command":"echo SAFE"}}}'))
    rows.append(probe('dup-tool-dangerous-then-safe',b'{"jsonrpc":"2.0","id":"d2","method":"tools/call","params":{"name":"exec","name":"lookup_vendor","arguments":{"vendor":"x"}}}'))
    rows.append(probe('dup-method-ping-then-tool',b'{"jsonrpc":"2.0","id":"d3","method":"ping","method":"tools/call","params":{"name":"exec","arguments":{"command":"echo SAFE"}}}'))
    rows.append(probe('dup-method-tool-then-ping',b'{"jsonrpc":"2.0","id":"d4","method":"tools/call","method":"ping","params":{"name":"exec","arguments":{"command":"echo SAFE"}}}'))
    dangerous=json.dumps({'jsonrpc':'2.0','id':'p','method':'tools/call','params':{'name':'exec','arguments':{'command':'echo SAFE'}}}).encode()
    for path in ['/anything','//mcp','/mcp/../x','/%6dcp','/mcp?x=../']:
        rows.append(probe('path:'+path,dangerous,path=path))
    rows.append(probe('content-encoding-gzip-uncompressed',dangerous,headers={'Content-Encoding':'gzip'}))

    body=dangerous
    request=(b'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:18787\r\nContent-Type: application/json\r\n'
             b'mcp-method: tools/call\r\nX-Heraclitus-Agent: first\r\nX-Heraclitus-Agent: second\r\n'
             b'Content-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
    before=hits(); out=raw_socket(request); delta=hits()-before
    safe=delta==0
    print(json.dumps({'probe':'duplicate-agent-header','safe':safe,'status_line':out.split(b'\r\n',1)[0].decode(errors='replace'),'upstream_delta':delta}))
    rows.append(safe)

    request=(b'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:18787\r\nContent-Type: application/json\r\n'
             b'Content-Length: '+str(len(body)).encode()+b'\r\nContent-Length: 1\r\nConnection: close\r\n\r\n'+body)
    before=hits(); out=raw_socket(request); delta=hits()-before
    safe=delta==0 and b' 400 ' in out.split(b'\r\n',1)[0]
    print(json.dumps({'probe':'duplicate-content-length','safe':safe,'status_line':out.split(b'\r\n',1)[0].decode(errors='replace'),'upstream_delta':delta}))
    rows.append(safe)
    print(f'PARSER-DIFFERENTIAL {sum(rows)}/{len(rows)} safe')
    return 0 if all(rows) else 2

if __name__=='__main__': raise SystemExit(main())
