# -*- coding: utf-8 -*-
with open('D:/DEV/HeraclitusDB/console/server.py', 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('default=7480', 'default=7481')
code = code.replace('Heraclitus Console', 'Heraclitus Console V2')

manifold_func = '''
def _manifold_data(db, limit=8000):
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    points = []
    for r in rows:
        emb = r.get("embedding")
        if not isinstance(emb, dict):
            continue
        hyp = emb.get("hyp") or []
        sph = emb.get("sph") or []
        euc = emb.get("euc") or []
        coords = (hyp + sph + euc)[:3]
        if len(coords) < 3:
            coords += [0.0] * (3 - len(coords))
        points.append({
            "id": r.get("id"), "kind": _clean_kind(r.get("kind")),
            "content": (r.get("content") or "")[:100],
            "x": coords[0], "y": coords[1], "z": coords[2],
            "caso": (r.get("attrs") or {}).get("caso", "")
        })
    return {"points": points}

'''
code = code.replace('def _timeline', manifold_func + 'def _timeline')

post_route = '            elif self.path.startswith("/fraudes"):'
new_route = '''            elif self.path.startswith("/manifold_data"):
                self._send(200, json.dumps(_manifold_data(_client()), ensure_ascii=False, default=str))
''' + post_route
code = code.replace(post_route, new_route)

code = code.replace(
    '<script src="vendor/vis-network.min.js"></script>',
    '<script src="vendor/vis-network.min.js"></script>\n<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>'
)

code = code.replace(
    '<button id="fraud" class="btn warn">🕵 Fraudes</button>',
    '<button id="fraud" class="btn warn">🕵 Fraudes</button>\n      <button id="manifold" class="btn" style="background:#f3f6fb">🌌 Manifold 3D</button>'
)

code = code.replace(
    '<svg id="heb"></svg>',
    '<svg id="heb"></svg>\n    <div id="manifold_plot" style="position:absolute;inset:0;display:none;width:100%;height:100%;z-index:2;background:#fff"></div>'
)

js_manifold = '''
/* ---------- MANIFOLD 3D ---------- */
function showManifold(on){ 
    el('manifold_plot').style.display=on?'block':'none'; 
    if(on) {
        el('heb').style.display='none'; 
        el('graph').style.display='none'; 
        el('hebcap').style.display='none'; 
    }
}
async function loadManifold(){
  el('err').textContent='Carregando espaco vetorial (Manifold)...';
  try{ 
      var j=await post('manifold_data',{});
      if(!(j.points||[]).length){ el('err').textContent='Nenhum no com embedding no banco. Rode o agente para injetar dados com vetores.'; return; }
      MODE='manifold'; FRAUD=null; LASTSUGG=null; showManifold(true); 
      
      var trace = {
          x: j.points.map(function(p){return p.x}),
          y: j.points.map(function(p){return p.y}),
          z: j.points.map(function(p){return p.z}),
          text: j.points.map(function(p){return p.kind + ': ' + p.content}),
          mode: 'markers',
          marker: {
              size: 6,
              color: j.points.map(function(p){return p.caso ? 1 : 0}),
              colorscale: 'Viridis',
              opacity: 0.8
          },
          type: 'scatter3d'
      };
      var layout = { margin: { l: 0, r: 0, b: 0, t: 0 }, paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)' };
      Plotly.newPlot('manifold_plot', [trace], layout);
      
      el('count').innerHTML='<b>'+j.points.length+'</b> vetores no espaco 3D';
      el('err').textContent='';
  }catch(e){ el('err').textContent='Falha: '+e.message; }
}
el('manifold').onclick=loadManifold;
'''

code = code.replace("function showHeb(on){", js_manifold + "\nfunction showHeb(on){")
code = code.replace("el('heb').style.display=on?'block':'none';", "el('heb').style.display=on?'block':'none'; if(on) showManifold(false);")
code = code.replace("ensureNetwork(); try{network.fit();}catch(e){}", "ensureNetwork(); showManifold(false); try{network.fit();}catch(e){}")

with open('D:/DEV/HeraclitusDB/console/server_v2.py', 'w', encoding='utf-8') as f:
    f.write(code)
print('server_v2.py gerado com sucesso!')
