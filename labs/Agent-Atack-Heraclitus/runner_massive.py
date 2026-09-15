#!/usr/bin/env python3
"""Massive multi-agent qualification for Agent-Atack-Heraclitus.

This extends runner.py but remains hard locked to loopback by Lab.__init__.
All payloads are synthetic. The upstream stub never executes commands.
"""
from __future__ import annotations
import argparse, concurrent.futures, json, os, time, uuid
from dataclasses import asdict
from pathlib import Path
from runner import Lab, Result, load


class MassiveLab(Lab):
    def agent_headers(self, agent: str, run: str | None = None, method: str = 'tools/call'):
        h = self.mcp_headers(run)
        h['X-Heraclitus-Agent'] = agent
        h['mcp-method'] = method
        return h

    def status_snapshot(self):
        s, b, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/status', headers=self.auth_agent())
        return b if s == 200 and isinstance(b, dict) else {}

    def credential_separation(self):
        aid = self.attack_id('credential-separation')
        core_on_agent = self.core_auth(True)
        s1, _, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/status', headers=core_on_agent)
        agent_on_core = self.auth_agent()
        s2, _, ms = self.request(self.cfg['core_rest'], '/stats', headers=agent_on_core)
        ok = s1 in {401, 403} and s2 in {401, 403}
        self.report(Result(aid, 'credential-plane-separation', 'core↔agent', 'cross-plane credentials rejected',
                           f'agent={s1} core={s2}', ok, s2, blocked=ok,
                           detail='Core Basic must not authenticate Agent; Agent token must not authenticate Core', duration_ms=ms))

    def multi_agent_same_rpc_id(self):
        agents = int(self.cfg.get('massive_agents', 128))
        shared = 'shared-jsonrpc-id'
        before = self.hits()
        def one(i):
            agent = f'redteam-agent-{i:04d}'
            req = self.tool(shared, 'exec', {'command': 'echo SAFE_MARKER', 'agent_index': i})
            return self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req,
                                self.agent_headers(agent, f'{self.campaign}-sameid'), timeout=12)[0]
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, agents)) as ex:
            statuses = list(ex.map(one, range(agents)))
        after = self.hits()
        delta = (after-before) if before is not None and after is not None else None
        denied = sum(x == 403 for x in statuses)
        ok = denied == agents and delta in {0, None}
        self.report(Result(self.attack_id('same-id-result'), 'multi-agent-same-jsonrpc-id', 'mcp:exec',
                           f'{agents} agents denied; no upstream', f'{denied}/{agents} denied', ok, 403 if denied else None,
                           'POLICY_DENY', blocked=ok, upstream_delta=delta,
                           detail=f'shared id across {agents} identities; {(time.perf_counter()-started)*1000:.0f}ms'))

    def identity_confusion_matrix(self):
        variants = [
            'agent', 'Agent', 'agent ', ' agent', 'agent/../other', 'agent%2Fother',
            'agent\u2215other', 'agent\u2044other', 'agent\u0000suffix', 'a'*512
        ]
        before = self.hits()
        statuses=[]
        for i, agent in enumerate(variants):
            req = self.tool(f'ident-{i}', 'exec', {'command': 'echo SAFE_MARKER', 'variant': i})
            s, _, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req,
                                   self.agent_headers(agent, f'{self.campaign}-identity'))
            statuses.append(s)
        after = self.hits(); delta=(after-before) if before is not None and after is not None else None
        bypass = sum(x == 200 for x in statuses)
        ok = bypass == 0 and delta in {0, None}
        self.report(Result(self.attack_id('identity-matrix'), 'identity-confusion-matrix', 'mcp:identity',
                           'no identity spelling bypasses deny', f'200-bypass={bypass}/{len(variants)}', ok,
                           statuses[-1] if statuses else None, blocked=ok, upstream_delta=delta,
                           detail='case/space/path/unicode/NUL/long identity variants'))

    def jsonrpc_shape_matrix(self):
        cases = [
            ('null-id', {'jsonrpc':'2.0','id':None,'method':'tools/call','params':{'name':'exec','arguments':{'command':'echo SAFE'}}}),
            ('missing-id', {'jsonrpc':'2.0','method':'tools/call','params':{'name':'exec','arguments':{'command':'echo SAFE'}}}),
            ('numeric-id', {'jsonrpc':'2.0','id':7,'method':'tools/call','params':{'name':'exec','arguments':{'command':'echo SAFE'}}}),
            ('bad-version', {'jsonrpc':'1.0','id':'x','method':'tools/call','params':{'name':'exec','arguments':{'command':'echo SAFE'}}}),
            ('args-array', {'jsonrpc':'2.0','id':'x','method':'tools/call','params':{'name':'exec','arguments':['echo','SAFE']}}),
            ('args-string', {'jsonrpc':'2.0','id':'x','method':'tools/call','params':{'name':'exec','arguments':'echo SAFE'}}),
            ('missing-params', {'jsonrpc':'2.0','id':'x','method':'tools/call'}),
        ]
        before=self.hits(); unsafe=[]; observed=[]
        for label, req in cases:
            s,b,_=self.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.agent_headers(f'shape-{label}',f'{self.campaign}-shape'))
            observed.append((label,s,self.reason(b)))
            if s == 200: unsafe.append(label)
        after=self.hits(); delta=(after-before) if before is not None and after is not None else None
        ok = not unsafe and delta in {0,None}
        self.report(Result(self.attack_id('shape-matrix'),'jsonrpc-shape-confusion','mcp:tools/call',
                           'malformed dangerous calls never reach upstream', f'unsafe={unsafe or "none"}',ok,
                           blocked=ok,upstream_delta=delta,detail=json.dumps(observed,ensure_ascii=False)[:500]))

    def method_confusion_matrix(self):
        methods=['Tools/Call','TOOLS/CALL','tools\\call','tools%2Fcall','tools//call',' tools/call','tools/call ','tools/call\u2215']
        before=self.hits(); forwarded=[]; obs=[]
        for i,m in enumerate(methods):
            req={'jsonrpc':'2.0','id':f'method-{i}','method':m,'params':{'name':'exec','arguments':{'command':'echo SAFE_MARKER'}}}
            s,b,_=self.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.agent_headers(f'method-{i}',f'{self.campaign}-method',m))
            obs.append((m,s,self.reason(b)))
            if s == 200: forwarded.append(m)
        after=self.hits(); delta=(after-before) if before is not None and after is not None else None
        # A safe stub makes observation harmless, but forwarding a near-miss of tools/call is a hardening finding.
        ok = not forwarded and delta in {0,None}
        self.report(Result(self.attack_id('method-matrix'),'mcp-method-confusion','mcp:method',
                           'near-miss tools/call forms not forwarded',f'forwarded={len(forwarded)}',ok,
                           blocked=ok,upstream_delta=delta,detail=json.dumps(obs,ensure_ascii=False)[:500]))

    def content_type_confusion(self):
        variants=['text/plain','application/octet-stream','application/json; charset=utf-8','application/problem+json']
        before=self.hits(); bypass=[]; obs=[]
        req=self.tool(self.attack_id('ctype-id'),'exec',{'command':'echo SAFE_MARKER'})
        raw=json.dumps(req,separators=(',',':')).encode()
        for ct in variants:
            h=self.agent_headers(f'ctype-{ct[:8]}',f'{self.campaign}-ctype'); h['Content-Type']=ct
            s,b,_=self.request(self.cfg['mcp_gateway'],'/mcp','POST',raw,h)
            obs.append((ct,s,self.reason(b)))
            if s==200:bypass.append(ct)
        after=self.hits(); delta=(after-before) if before is not None and after is not None else None
        ok=not bypass and delta in {0,None}
        self.report(Result(self.attack_id('ctype-result'),'content-type-confusion','mcp:exec','no media-type bypass',
                           f'bypass={bypass or "none"}',ok,blocked=ok,upstream_delta=delta,detail=json.dumps(obs)[:500]))

    def approval_concurrent_consumption(self):
        aid=self.attack_id('approval-race')
        req=self.tool(aid,'send_payment',{'amount':75000,'account':'synthetic-race'})
        s,b,_=self.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.agent_headers('approval-race-agent',f'{self.campaign}-approval-race'))
        try: approval=b['error']['data']['heraclitus']['approval_id']
        except Exception: approval=None
        if s!=202 or not approval:
            self.report(Result(aid,'approval-concurrent-consume','mcp:send_payment','approval pending','approval unavailable',False,s,self.reason(b),blocked=True)); return
        sa,_,_=self.request(self.cfg['agent_api'],f'/api/v1/agent/approvals/{approval}/approve','POST',{},self.auth_agent())
        before=self.hits(); n=int(self.cfg.get('approval_race_workers',24))
        def one(i):
            return self.request(self.cfg['mcp_gateway'],'/mcp','POST',req,
                                self.agent_headers('approval-race-agent',f'{self.campaign}-approval-race'),timeout=12)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex: statuses=list(ex.map(one,range(n)))
        after=self.hits(); delta=(after-before) if before is not None and after is not None else None
        wins=sum(x==200 for x in statuses)
        ok=sa==200 and wins==1 and delta in {1,None}
        self.report(Result(aid,'approval-concurrent-consume','mcp:send_payment','exactly one execution from one approval',
                           f'wins={wins}/{n}',ok,200 if wins else None,blocked=not ok,upstream_delta=delta,
                           detail=f'approval={approval[:18]}… statuses={{{s:statuses.count(s) for s in set(statuses)}}}'))

    def replay_storm(self):
        n=int(self.cfg.get('replay_storm',256)); aid=self.attack_id('replay-storm')
        req=self.tool(aid,'exec',{'command':'echo SAFE_MARKER','storm':'same-request'})
        before=self.hits()
        def one(_):return self.request(self.cfg['mcp_gateway'],'/mcp','POST',req,self.agent_headers('storm-agent',f'{self.campaign}-storm'),timeout=12)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(64,n)) as ex: statuses=list(ex.map(one,range(n)))
        after=self.hits(); delta=(after-before) if before is not None and after is not None else None
        denied=sum(x==403 for x in statuses); ok=denied==n and delta in {0,None}
        self.report(Result(aid,'identical-replay-storm','mcp:exec',f'{n} identical requests denied/no upstream',
                           f'{denied}/{n} denied',ok,403 if denied else None,'POLICY_DENY',blocked=ok,upstream_delta=delta))

    def redteam_query_limits(self):
        aid=self.attack_id('redteam-limit')
        s,b,ms=self.request(self.cfg['agent_api'],'/api/v1/agent/red-team/events?limit=999999999',headers=self.auth_agent())
        returned=None
        if isinstance(b,dict) and isinstance(b.get('summary'),dict): returned=b['summary'].get('returned')
        ok=(s in {400,413,422}) or (s==200 and isinstance(returned,int) and returned<=1000)
        self.report(Result(aid,'redteam-query-limit','agent:red-team/events','huge limit rejected or capped',
                           f'HTTP {s} returned={returned}',ok,s,blocked=(s!=200),detail='bounded query protects memory/response amplification',duration_ms=ms))

    def http_method_surface(self):
        obs=[]; ok=True
        for method in ['TRACE','CONNECT','PATCH','DELETE']:
            s,_,_=self.request(self.cfg['agent_api'],'/api/v1/agent/status',method=method,headers=self.auth_agent(),read_body=False)
            obs.append((method,s)); ok &= s not in {200,201,202,204}
        self.report(Result(self.attack_id('method-surface'),'http-method-surface','agent:/status','unexpected methods rejected',
                           json.dumps(obs),bool(ok),blocked=bool(ok),detail='no state-changing verb should succeed on status'))

    def massive_run(self):
        print(f'Agent-Atack-Heraclitus MASSIVE campaign={self.campaign} LOOPBACK-ONLY')
        base=self.run()
        suites=[self.credential_separation,self.multi_agent_same_rpc_id,self.identity_confusion_matrix,
                self.jsonrpc_shape_matrix,self.method_confusion_matrix,self.content_type_confusion,
                self.approval_concurrent_consumption,self.replay_storm,self.redteam_query_limits,self.http_method_surface]
        for fn in suites:
            try:fn()
            except Exception as e:
                self.report(Result(self.attack_id('massive-runner-error'),fn.__name__,'runner','no exception',type(e).__name__,False,detail=str(e)[:300]))
        return self.results


def main():
    ap=argparse.ArgumentParser(description='Massive authorized loopback-only HeraclitusDB red-team')
    ap.add_argument('--config',default='config.example.json'); ap.add_argument('--report',default=None); a=ap.parse_args()
    cfg=load(a.config); lab=MassiveLab(cfg); results=lab.massive_run()
    out={'product':'Agent-Atack-Heraclitus','profile':'massive-multi-agent','campaign':lab.campaign,
         'generated_at':int(time.time()),'results':[asdict(x) for x in results],
         'summary':{'total':len(results),'passed':sum(x.passed for x in results),'failed':sum(not x.passed for x in results)}}
    report=Path(a.report or f'reports/{lab.campaign}-massive.json'); report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    print(f"\nMASSIVE SUMMARY {out['summary']['passed']}/{out['summary']['total']} passed; report={report}")
    return 0 if out['summary']['failed']==0 else 2

if __name__=='__main__': raise SystemExit(main())
