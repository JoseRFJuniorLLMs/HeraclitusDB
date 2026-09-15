#!/usr/bin/env python3
"""Inofensivo MCP upstream para laboratório HeraclitusDB.

Nunca executa shell, filesystem, rede ou subprocessos. Apenas conta requests e
retorna JSON sintético para provar se o Gateway encaminhou uma ação. O endpoint
/stats também conta se algum Authorization chegou ao stub, sem persistir o
valor da credencial.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse, json, threading

LOCK=threading.Lock(); HITS=0; AUTH_SEEN=0

def bump(auth_present=False):
    global HITS, AUTH_SEEN
    with LOCK:
        HITS += 1
        if auth_present: AUTH_SEEN += 1
        return HITS

def stats():
    with LOCK: return {'hits':HITS,'authorization_seen':AUTH_SEEN}

class H(BaseHTTPRequestHandler):
    server_version='HeraclitusSafeMCPStub/2'
    def log_message(self, fmt, *args): pass
    def out(self, status, obj):
        b=json.dumps(obj,separators=(',',':')).encode(); self.send_response(status)
        self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path=='/hits': return self.out(200,{'hits':stats()['hits']})
        if self.path=='/stats': return self.out(200,stats())
        return self.out(404,{'error':'not_found'})
    def do_POST(self):
        n=int(self.headers.get('Content-Length') or 0)
        if n>8*1024*1024: return self.out(413,{'error':'body_too_large'})
        raw=self.rfile.read(n)
        try: req=json.loads(raw)
        except Exception: return self.out(400,{'error':'bad_json'})
        bump(bool(self.headers.get('Authorization')))
        if isinstance(req,list):
            return self.out(200,[{'jsonrpc':'2.0','id':x.get('id'),'result':{'stub':True}} for x in req if isinstance(x,dict)])
        method=req.get('method') if isinstance(req,dict) else None
        rid=req.get('id') if isinstance(req,dict) else None
        if method=='tools/call':
            params=req.get('params') or {}; name=params.get('name')
            if name=='send_payment': result={'content':[{'type':'text','text':'synthetic payment accepted'}],'external_effect_id':'stub-payment-1'}
            elif name=='lookup_vendor': result={'content':[{'type':'text','text':'synthetic vendor ok'}],'external_effect_id':'stub-read-1'}
            else: result={'content':[{'type':'text','text':'stub tool response'}]}
            return self.out(200,{'jsonrpc':'2.0','id':rid,'result':result})
        return self.out(200,{'jsonrpc':'2.0','id':rid,'result':{'stub':True,'method':method}})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--bind',default='127.0.0.1'); ap.add_argument('--port',type=int,default=19000); a=ap.parse_args()
    if a.bind not in {'127.0.0.1','::1','localhost'}: raise SystemExit('stub recusou bind não-loopback')
    print(f'SAFE MCP stub em http://{a.bind}:{a.port}  hits=/hits stats=/stats',flush=True)
    ThreadingHTTPServer((a.bind,a.port),H).serve_forever()
if __name__=='__main__': main()
