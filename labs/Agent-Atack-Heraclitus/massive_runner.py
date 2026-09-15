#!/usr/bin/env python3
"""Massive multi-agent qualification for HeraclitusDB.

Hard safety contract: inherits Lab's loopback-only guard. Payloads are synthetic
and the upstream stub has no shell/filesystem/external-network capability.
Results are aggregated: one red-team evidence record per campaign vector, not
one record per request.
"""
from __future__ import annotations
import argparse, concurrent.futures, json, sys, time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runner import Lab, Result, load  # type: ignore

class MassiveLab:
    def __init__(self,cfg):
        self.lab=Lab(cfg); self.cfg=cfg
        self.workers=int(cfg.get('massive_workers',48)); self.scale=int(cfg.get('massive_scale',1))

    def headers(self,agent,run=None,extra=None):
        h=self.lab.mcp_headers(run or f'massive-{self.lab.campaign}')
        h['X-Heraclitus-Agent']=agent; h['X-Heraclitus-User']='sandbox-operator'
        if extra: h.update(extra)
        return h

    def call(self,agent,rid,tool,args,extra_headers=None,timeout=12):
        return self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',self.lab.tool(rid,tool,args),self.headers(agent,extra=extra_headers),timeout=timeout)

    def aggregate(self,vector,target,expected,passed,statuses,before,after,reason=None,blocked=None,detail='',started=None):
        delta=(after-before) if before is not None and after is not None else None
        duration=(time.perf_counter()-started)*1000 if started else 0.0
        c=Counter(statuses); result=','.join(f'{k}:{v}' for k,v in sorted(c.items(),key=lambda x:str(x[0])))
        r=Result(self.lab.attack_id(vector),vector,target,expected,result,passed,
                 status=(statuses[0] if statuses and len(set(statuses))==1 else None),reason_code=reason,
                 blocked=blocked,upstream_delta=delta,detail=detail,duration_ms=duration)
        self.lab.report(r); return r

    def caller_authorization_not_forwarded(self):
        base=self.cfg.get('upstream_hits','http://127.0.0.1:19000/hits').rsplit('/',1)[0]
        s0,b0,_=self.lab.request(base,'/stats'); before_auth=(b0 or {}).get('authorization_seen') if s0==200 and isinstance(b0,dict) else None
        before=self.lab.hits(); t=time.perf_counter()
        s,b,_=self.call('credential-probe','credential-fixed','lookup_vendor',{'vendor':'synthetic-auth-strip'},
                        {'Authorization':'Bearer LAB_SENTINEL_MUST_NOT_REACH_UPSTREAM'})
        after=self.lab.hits(); s1,b1,_=self.lab.request(base,'/stats'); after_auth=(b1 or {}).get('authorization_seen') if s1==200 and isinstance(b1,dict) else None
        delta=(after-before) if before is not None and after is not None else None
        auth_delta=(after_auth-before_auth) if before_auth is not None and after_auth is not None else None
        ok=s==200 and delta in {1,None} and auth_delta in {0,None}
        self.lab.report(Result(self.lab.attack_id('credential-strip'),'caller-authorization-strip','mcp:upstream-boundary',
            'allowed request forwarded but caller Authorization stripped',f'HTTP {s}; auth_seenΔ={auth_delta}',ok,s,self.lab.reason(b),False,delta,
            detail='stub stores only presence count, never credential value',duration_ms=(time.perf_counter()-t)*1000))

    def server_id_spoof(self):
        before=self.lab.hits(); t=time.perf_counter()
        s,b,_=self.call('spoof-agent','spoof-fixed','spoof_sensitive',{'value':'synthetic'},{'X-Heraclitus-Server':'trusted-alternate'})
        after=self.lab.hits(); delta=(after-before) if before is not None and after is not None else None
        ok=s==403 and delta in {0,None}
        self.lab.report(Result(self.lab.attack_id('server-spoof'),'server-id-policy-spoof','mcp:spoof_sensitive',
            'caller cannot select trusted-alternate policy identity',f'HTTP {s}',ok,s,self.lab.reason(b),True,delta,
            detail='X-Heraclitus-Server=trusted-alternate',duration_ms=(time.perf_counter()-t)*1000))

    def oversized_correlation_matrix(self):
        names=['X-Heraclitus-Agent','X-Heraclitus-Run','X-Heraclitus-User','X-Heraclitus-Environment','X-Heraclitus-Trace','X-Heraclitus-Server']
        before=self.lab.hits(); statuses=[]; reasons=[]; t=time.perf_counter()
        for name in names:
            s,b,_=self.call('header-agent',f'h-{name}','lookup_vendor',{'vendor':'header'},{name:'X'*513}); statuses.append(s); reasons.append(self.lab.reason(b))
        after=self.lab.hits(); delta=(after-before) if before is not None and after is not None else None
        ok=all(s==400 for s in statuses) and all(r=='CORRELATION_HEADER_TOO_LARGE' for r in reasons) and delta in {0,None}
        self.aggregate('oversized-correlation-matrix','mcp:headers','6x HTTP 400 before upstream',ok,statuses,before,after,
                       'CORRELATION_HEADER_TOO_LARGE',True,'513-byte boundary across six correlation headers',t)

    def multi_agent_deny_storm(self):
        agents=64*self.scale; per=16; total=agents*per; before=self.lab.hits(); t=time.perf_counter()
        def one(i):
            return self.call(f'hostile-{i%agents:03d}',f'shared-{i%8}','exec',{'command':'echo SAFE_MARKER','attempt':i})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: statuses=list(ex.map(one,range(total)))
        after=self.lab.hits(); delta=(after-before) if before is not None and after is not None else None
        ok=all(s==403 for s in statuses) and delta in {0,None}
        self.aggregate('massive-multi-agent-deny','mcp:exec',f'{total}x deny, upstreamΔ=0',ok,statuses,before,after,'POLICY_DENY',True,
                       f'{agents} agents, 8 recycled JSON-RPC ids',t)

    def shared_id_allow_storm(self):
        total=256*self.scale; before=self.lab.hits(); t=time.perf_counter()
        def one(i): return self.call(f'benign-{i%32:02d}','SAME-ID','lookup_vendor',{'vendor':f'synthetic-{i}'})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: statuses=list(ex.map(one,range(total)))
        after=self.lab.hits(); delta=(after-before) if before is not None and after is not None else None
        ok=all(s==200 for s in statuses) and delta in {total,None}
        self.aggregate('massive-shared-id-allow','mcp:lookup_vendor',f'{total}x 200, upstreamΔ={total}',ok,statuses,before,after,
                       blocked=False,detail='32 agents deliberately reuse one JSON-RPC id',started=t)

    def mixed_decision_storm(self):
        total=384*self.scale; before=self.lab.hits(); t=time.perf_counter()
        def one(i):
            a=f'mixed-{i%48:02d}'
            if i%3==0: return 'deny',self.call(a,f'mix-{i%11}','exec',{'command':'echo SAFE'})[0]
            if i%3==1: return 'allow',self.call(a,f'mix-{i%11}','lookup_vendor',{'vendor':f'v-{i}'})[0]
            return 'approval',self.call(a,f'mix-{i%11}','send_payment',{'amount':1000+i,'account':'synthetic'})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: out=list(ex.map(one,range(total)))
        groups={k:[s for kk,s in out if kk==k] for k in ('deny','allow','approval')}; after=self.lab.hits(); allow_n=len(groups['allow'])
        delta=(after-before) if before is not None and after is not None else None
        ok=all(s==403 for s in groups['deny']) and all(s==200 for s in groups['allow']) and all(s==202 for s in groups['approval']) and delta in {allow_n,None}
        self.aggregate('massive-mixed-decisions','mcp:mixed',f'deny=403 allow=200 approval=202 upstreamΔ={allow_n}',ok,[s for _,s in out],before,after,
                       detail=f'{total} interleaved decisions',started=t)

    def approval_race(self):
        agent='race-owner'; rid=self.lab.attack_id('race'); req=self.lab.tool(rid,'send_payment',{'amount':4242,'account':'synthetic-race'})
        s,b,_=self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.headers(agent))
        try: approval=b['error']['data']['heraclitus']['approval_id']
        except Exception: approval=None
        if s!=202 or not approval:
            self.lab.report(Result(rid,'massive-approval-race','mcp:send_payment','approval pending','no approval',False,s,self.lab.reason(b),True,0)); return
        ap,_,_=self.lab.request(self.cfg['agent_api'],f'/api/v1/agent/approvals/{approval}/approve','POST',{},self.lab.auth_agent())
        n=64*self.scale; before=self.lab.hits(); t=time.perf_counter()
        def one(_): return self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.headers(agent),timeout=15)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: statuses=list(ex.map(one,range(n)))
        after=self.lab.hits(); c=Counter(statuses); delta=(after-before) if before is not None and after is not None else None
        ok=ap==200 and c.get(200,0)==1 and delta in {1,None} and sum(v for k,v in c.items() if k!=200)==n-1
        self.aggregate('massive-approval-race','mcp:send_payment',f'exactly 1/{n} execution, upstreamΔ=1',ok,statuses,before,after,
                       'APPROVAL_REPLAYED',True,f'approval={approval[:18]}…',t)

    def cross_agent_approval_theft(self):
        owner='approval-owner'; thief='approval-thief'; rid=self.lab.attack_id('theft'); req=self.lab.tool(rid,'send_payment',{'amount':9191,'account':'synthetic-theft'})
        s,b,_=self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.headers(owner))
        try: approval=b['error']['data']['heraclitus']['approval_id']
        except Exception: approval=None
        if s!=202 or not approval:
            self.lab.report(Result(rid,'cross-agent-approval-theft','mcp:send_payment','approval pending','no approval',False,s,self.lab.reason(b),True,0)); return
        ap,_,_=self.lab.request(self.cfg['agent_api'],f'/api/v1/agent/approvals/{approval}/approve','POST',{},self.lab.auth_agent())
        before=self.lab.hits(); st,bt,_=self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.headers(thief)); mid=self.lab.hits()
        so,_,_=self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.headers(owner)); after=self.lab.hits()
        dth=(mid-before) if before is not None and mid is not None else None; down=(after-mid) if after is not None and mid is not None else None
        ok=ap==200 and st!=200 and dth in {0,None} and so==200 and down in {1,None}
        self.lab.report(Result(rid,'cross-agent-approval-theft','mcp:send_payment','thief denied; owner executes once',f'thief={st}, owner={so}',ok,st,
            self.lab.reason(bt),True,(after-before) if after is not None and before is not None else None,detail=f'thiefΔ={dth}, ownerΔ={down}'))

    def malformed_json_fanout(self):
        n=128*self.scale; headers={'Content-Type':'application/json','X-Heraclitus-Agent':'malformed-agent'}; before=self.lab.hits(); t=time.perf_counter()
        def one(i):
            raw=b'{"jsonrpc":"2.0","id":'+str(i).encode()+b',"method":"tools/call","params":'
            return self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',raw,headers,timeout=10)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: statuses=list(ex.map(one,range(n)))
        after=self.lab.hits(); delta=(after-before) if before is not None and after is not None else None
        health,_,_=self.lab.request(self.cfg['agent_api'],'/api/v1/agent/status',headers=self.lab.auth_agent())
        ok=all(s is not None and not (200<=s<300) for s in statuses) and delta in {0,None} and health==200
        self.aggregate('malformed-json-fanout','mcp:parser',f'{n} malformed rejected, upstreamΔ=0, service alive',ok,statuses,before,after,
                       blocked=True,detail=f'health={health}',started=t)

    def otlp_oversized_fanout(self):
        n=12*self.scale; size=int(self.cfg.get('oversized_bytes',5*1024*1024)); payload=b'{"resourceSpans":[],"pad":"'+b'x'*size+b'"}'; t=time.perf_counter()
        def one(_): return self.lab.request(self.cfg['otlp'],'/v1/traces','POST',payload,{'Content-Type':'application/json'},timeout=20,read_body=False)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12,self.workers)) as ex: statuses=list(ex.map(one,range(n)))
        health,_,_=self.lab.request(self.cfg['agent_api'],'/api/v1/agent/status',headers=self.lab.auth_agent()); ok=all(s==413 for s in statuses) and health==200
        self.aggregate('otlp-oversized-fanout','otlp:/v1/traces',f'{n}x 413 and service alive',ok,statuses,None,None,blocked=True,
                       detail=f'{size} bytes/request health={health}',started=t)

    def protocol_surface_swirl(self):
        methods=['resources/read','prompts/get','tools/list','ping']; n=160*self.scale; before=self.lab.hits(); t=time.perf_counter()
        def one(i):
            method=methods[i%len(methods)]; req={'jsonrpc':'2.0','id':f'proto-{i%7}','method':method,'params':{'uri':'lab://synthetic'}}
            h=self.headers(f'proto-{i%24}'); h['mcp-method']=method
            return method,self.lab.request(self.cfg['mcp_gateway'],'/mcp','POST',req,h,timeout=10)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex: out=list(ex.map(one,range(n)))
        after=self.lab.hits(); by={m:Counter(s for mm,s in out if mm==m) for m in methods}
        self.aggregate('protocol-surface-swirl','mcp:non-tool','measure control-plane/data-plane method coverage',True,[s for _,s in out],before,after,
                       detail='; '.join(f'{m}={dict(c)}' for m,c in by.items()),started=t)

    def final_health(self):
        s,b,ms=self.lab.request(self.cfg['agent_api'],'/api/v1/agent/status',headers=self.lab.auth_agent()); gc={}; ev='UNKNOWN'
        if isinstance(b,dict):
            gc=b.get('gateway_counters') or (b.get('gateway',{}).get('counters') if isinstance(b.get('gateway'),dict) else {}) or {}
            ev=(b.get('evidence_log') or {}).get('health') if isinstance(b.get('evidence_log'),dict) else b.get('evidence_log_health','UNKNOWN')
        evidence_errors=gc.get('evidence_errors') if isinstance(gc,dict) else None; ok=s==200 and evidence_errors in {0,None}
        self.lab.report(Result(self.lab.attack_id('final-health'),'post-campaign-health','agent:/status','HTTP 200 and evidence_errors=0',
            f'HTTP {s}; evidence_errors={evidence_errors}; evidence={ev}',ok,s,None,False,None,detail=json.dumps(gc,sort_keys=True)[:500],duration_ms=ms))

    def run(self):
        print(f'MASSIVE Agent-Atack-Heraclitus campaign={self.lab.campaign} LOOPBACK-ONLY workers={self.workers} scale={self.scale}')
        suites=[self.caller_authorization_not_forwarded,self.server_id_spoof,self.oversized_correlation_matrix,self.multi_agent_deny_storm,
                self.shared_id_allow_storm,self.mixed_decision_storm,self.approval_race,self.cross_agent_approval_theft,
                self.malformed_json_fanout,self.otlp_oversized_fanout,self.protocol_surface_swirl,self.final_health]
        for fn in suites:
            try: fn()
            except Exception as e:
                self.lab.report(Result(self.lab.attack_id('runner-error'),f'runner:{fn.__name__}','runner','no exception',type(e).__name__,False,detail=str(e)[:300]))
        return self.lab.results

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--config',default='config.example.json'); ap.add_argument('--out',default='massive-report.json')
    ns=ap.parse_args(); cfg=load(ns.config); lab=MassiveLab(cfg); results=lab.run()
    report={'product':'Agent-Atack-Heraclitus','mode':'massive-multi-agent','campaign':lab.lab.campaign,'generated_at':int(time.time()),
            'results':[r.__dict__ for r in results],'summary':{'passed':sum(r.passed for r in results),'failed':sum(not r.passed for r in results)}}
    Path(ns.out).write_text(json.dumps(report,indent=2,ensure_ascii=False)); print(json.dumps(report['summary'],ensure_ascii=False))
    return 1 if report['summary']['failed'] else 0
if __name__=='__main__': raise SystemExit(main())
