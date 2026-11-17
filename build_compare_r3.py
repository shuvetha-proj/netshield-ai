#!/usr/bin/env python3
"""
build_compare_r3.py -- Review-2-style comparison page for Review 3.
Four panels (Flat, Static, Rule, ML 5-factor) on the 8-host topology.
Outcomes, decisions, risk and timing come from the RECORDED run in
results/exp8/ (default run 1). The wave animation is only pacing.

Usage: python3 build_compare_r3.py [run]      -> writes compare_review3.html
"""
import json, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(BASE, "results", "exp8")
OUT = os.path.join(BASE, "compare_review3.html")
RUN = int(sys.argv[1]) if len(sys.argv) > 1 else 1
CFGS = ["flat", "static", "rule", "ml5"]
KEY_IP = {"hr": "10.0.0.1", "fin": "10.0.0.2", "fileserver": "10.0.0.3", "guest": "10.0.0.4",
          "database": "10.0.0.5", "iot1": "10.0.0.6", "iot2": "10.0.0.7", "admin": "10.0.0.8"}
CONTAIN = ("RESTRICT", "QUARANTINE")

def files_for(key):
    """Recorded files for one dropdown entry, or None if any config is missing."""
    if key == "scan":
        cands = [[f"{c}_scan_run{RUN}.json"] for c in CFGS]
    elif key == "benign":
        cands = [[f"{c}_benign_run{RUN}.json"] for c in CFGS]
    else:
        cands = [[f"{c}_lateralall_{key}_run{RUN}.json"] +
                 ([f"{c}_lateral_run{RUN}.json"] if key == "hr" else []) for c in CFGS]
    out = []
    for opts in cands:
        hit = next((os.path.join(IN, o) for o in opts if os.path.exists(os.path.join(IN, o))), None)
        if hit is None:
            return None
        out.append(hit)
    return out


data = {}
for key in list(KEY_IP) + ["scan", "benign"]:
    paths = files_for(key)
    if paths is None:
        continue
    sc = key if key in ("scan", "benign") else "lat:" + key
    for c, p in zip(CFGS, paths):
        d = json.load(open(p))
        att = KEY_IP.get(d.get("attacker") or "")
        rows = sorted(d.get("rows", []), key=lambda r: r["dt"])
        arows = [r for r in rows if r["src"] == att]
        first = next((r for r in arows if r["action"] in CONTAIN), None)
        quarantined = sorted({r["src"] for r in rows if r["action"] == "QUARANTINE"})
        restricted = sorted({(r["src"], r["dst"]) for r in rows if r["action"] == "RESTRICT"})
        if sc == "benign":
            reached = []
        elif sc != "scan":
            reached = [KEY_IP[k] for k, v in d["reach"].items() if v]
        else:
            reached = [KEY_IP[d["target"]]] if d["target_reachable"] else []
        mis = 0
        wrong = 0
        out_rows = []
        for r in rows:
            m = (r["src"] == att) != (r["pred"] != "normal") and r["pred"] != "path-cut"
            mis += m
            wrong += bool(m and r["action"] in CONTAIN)
            out_rows.append([r["src"], r["dst"], r["pred"], round(r["risk"], 3), r["action"], bool(m)])
        data.setdefault(sc, {})[c] = {
            "attacker": att, "target": KEY_IP.get(d.get("target") or "", None),
            "reached": reached, "quarantined": quarantined, "restricted": restricted,
            "rows": out_rows, "misclassified": mis, "wrong": wrong,
            "crit": d.get("critical_reached"), "ncrit": d.get("critical_total", 2),
            "hosts": d.get("hosts_reached"),
            "contained": (d.get("false_containments", 0) == 0) if sc == "benign" else d["contained"] if sc != "scan" else (not d["target_reachable"]),
            "fc": d.get("false_containments"), "pairs": list((d.get("benign_pairs_ok") or {}).items()),
            "pairs_ok": sum((d.get("benign_pairs_ok") or {}).values()), "pairs_n": len(d.get("benign_pairs_ok") or {}),
            "ttc": d.get("time_to_contain_s"),
            "flows": len(arows), "unique": len({r["dst"] for r in arows}),
            "risk_at_detection": first["risk"] if first else d.get("attacker_max_risk"),
            "action": first["action"] if first else "MONITOR (no response)",
        }

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netshield-ai — Four-Configuration Attack Comparison (8-host)</title>
<style>
:root{--bg:#0b0f14;--panel:#141b24;--panel2:#0f151d;--line:#232d3a;--txt:#e6edf3;--mut:#8b949e;
  --green:#3fb950;--red:#f85149;--orange:#e3a008;--grey:#3a434f;--edge:#2b3443}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:20px 18px 48px}
h1{font-size:24px;margin:0 0 3px}.sub{color:var(--mut);margin:0 0 18px;font-size:14px}
.controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
button{font:inherit;font-weight:600;border:none;border-radius:9px;padding:11px 20px;cursor:pointer;color:#fff}
.btn-attack{background:#da3633}.btn-attack:hover{background:#f85149}.btn-attack:disabled{opacity:.5;cursor:not-allowed}
.btn-reset{background:#2d3845}
select{font:inherit;font-weight:600;background:#1b232e;color:var(--txt);border:1px solid var(--line);border-radius:9px;padding:10px 14px}
.scn{color:var(--mut);font-size:13px}.scn b{color:var(--txt)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 16px 14px;position:relative}
.panel.winner{border-color:#2ea04366;box-shadow:0 0 0 1px #2ea04333}
.phead{display:flex;justify-content:space-between;align-items:baseline}
.pname{font-size:16px;font-weight:700}.pdesc{color:var(--mut);font-size:12px;margin-bottom:6px}
.badge{font-size:12px;font-weight:700;padding:3px 10px;border-radius:20px}
.badge.g{background:#17331d;color:var(--green)}.badge.o{background:#3a2c08;color:var(--orange)}.badge.r{background:#3a1715;color:var(--red)}
svg.net{width:100%;height:270px;display:block}
.node text{fill:var(--txt);font-size:9.5px;font-weight:600;text-anchor:middle}
.node .role{fill:var(--mut);font-size:9px;font-weight:500}
.node circle{transition:fill .4s}
.edge{stroke:var(--edge);stroke-width:2.2;fill:none;transition:stroke .4s,opacity .4s}
.ring{fill:none;stroke:var(--red);stroke-width:2.5;opacity:0;transition:opacity .4s}.ring.on{opacity:1}
.statline{display:flex;gap:14px;margin:8px 0 10px;font-size:12.5px;flex-wrap:wrap;color:var(--mut)}.statline b{color:var(--txt)}
.wavetag{position:absolute;top:46px;right:16px;font-size:11px;color:var(--mut)}
.dwrap{max-height:190px;overflow-y:auto}
.dtbl{width:100%;border-collapse:collapse;font-size:11.5px}
.dtbl th{color:var(--mut);text-align:left;font-weight:600;padding:4px 6px;border-bottom:1px solid var(--line);font-size:10px;text-transform:uppercase;position:sticky;top:0;background:var(--panel)}
.dtbl td{padding:4px 6px;border-bottom:1px solid #1a222c}
.dtbl tr.mis{background:#3a2708}.dtbl tr.mis td{color:#f0b429}
.act{font-weight:700}.act.MONITOR{color:var(--green)}.act.RESTRICT{color:var(--orange)}.act.QUARANTINE{color:var(--red)}
.dtitle{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin:10px 0 2px;display:flex;justify-content:space-between}
.quality{font-weight:700}.quality.good{color:var(--green)}.quality.bad{color:var(--orange)}
.summcard{margin-top:10px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.summcard .h{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
.summrow{display:flex;justify-content:space-between;font-size:12.5px;padding:3px 0}.summrow .k{color:var(--mut)}.summrow .v{font-weight:700}
.legend{display:flex;gap:18px;margin:16px 2px 0;font-size:12px;color:var(--mut);flex-wrap:wrap}
.legend span{display:inline-flex;align-items:center;gap:6px}.dot{width:11px;height:11px;border-radius:50%;display:inline-block}
.summary{margin-top:18px;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px;font-size:13.5px;line-height:1.7;color:var(--mut)}.summary b{color:var(--txt)}
</style></head><body>
<h1>Ransomware Containment — Four Configurations, Same Attack (8-host VLAN network)</h1>
<p class="sub">Pick the attack and press start. All four defence configurations respond in parallel. Outcomes, decisions, risk scores and timings are from recorded live run __RUN__; the waves only pace the animation.</p>
<div class="controls">
  <label class="scn">Attack:
    <select id="scen"></select></label>
  <button class="btn-attack" id="go">▶ Start Attack</button>
  <button class="btn-reset" id="reset">↺ Reset</button>
  <span class="scn" id="scninfo"></span>
</div>
<div class="grid" id="grid"></div>
<div class="legend">
  <span><span class="dot" style="background:var(--green)"></span>healthy / not reached</span>
  <span><span class="dot" style="background:var(--red)"></span>attacker / reached</span>
  <span><span class="dot" style="background:var(--orange)"></span>restricted link</span>
  <span><span class="dot" style="background:var(--grey)"></span>isolated (static ACL)</span>
  <span><span style="width:14px;height:14px;border:2.5px solid var(--red);border-radius:50%;display:inline-block"></span>quarantined host</span>
  <span><span class="dot" style="background:#f0b429"></span>critical asset</span>
</div>
<div class="summary" id="summary"></div>
<script>
const DATA=__DATA__;
const NAMES={"10.0.0.1":"HR","10.0.0.2":"Finance","10.0.0.3":"FileServer","10.0.0.4":"Guest","10.0.0.5":"Database","10.0.0.6":"IoT-1","10.0.0.7":"IoT-2","10.0.0.8":"Admin"};
const VLAN={"10.0.0.1":10,"10.0.0.2":20,"10.0.0.3":30,"10.0.0.4":40,"10.0.0.5":30,"10.0.0.6":50,"10.0.0.7":50,"10.0.0.8":60};
const KEYIP={hr:"10.0.0.1",fin:"10.0.0.2",fileserver:"10.0.0.3",guest:"10.0.0.4",database:"10.0.0.5",iot1:"10.0.0.6",iot2:"10.0.0.7",admin:"10.0.0.8"};
const IPS=Object.keys(NAMES), GUEST="10.0.0.4", CRIT=["10.0.0.3","10.0.0.5"];
const CFG=[{key:"flat",name:"A — Flat network",desc:"No segmentation, no response"},
 {key:"static",name:"B — Static segmentation",desc:"Guest VLAN ACL only, no dynamic response"},
 {key:"rule",name:"C — Rule-based adaptive",desc:"Threshold rules, no ML"},
 {key:"ml5",name:"D — ML-driven adaptive",desc:"Random Forest + 5-factor risk model"}];
const W=440,H=270,ns="http://www.w3.org/2000/svg",POS={};
IPS.forEach((ip,i)=>{const a=-Math.PI/2+i*2*Math.PI/8;POS[ip]=[W/2+170*Math.cos(a),H/2+98*Math.sin(a)];});
const sleep=ms=>new Promise(r=>setTimeout(r,ms)), $=id=>document.getElementById(id);
function sc(){return $("scen").value;}
function el(t,a){const e=document.createElementNS(ns,t);for(const k in a)e.setAttribute(k,a[k]);return e;}
function targets(d){return sc()==="scan"?[d.target]:IPS.filter(ip=>ip!==d.attacker);}
Object.keys(DATA).forEach(k=>{const ip=DATA[k].ml5.attacker;$("scen").innerHTML+='<option value="'+k+'">'+(k==="scan"?"IoT-2 (10.0.0.7) — port scan on Database":k==="benign"?"Benign traffic only (no attacker) — false-alarm test":NAMES[ip]+" ("+ip+") — lateral movement to all other hosts")+"</option>";});
function buildPanel(c){
  const p=document.createElement("div");p.className="panel"+(c.key==="ml5"?" winner":"");
  p.innerHTML='<div class="wavetag" id="wave-'+c.key+'"></div><div class="phead"><span class="pname">'+c.name+'</span><span class="badge" id="badge-'+c.key+'" style="visibility:hidden"></span></div>'+
   '<div class="pdesc">'+c.desc+'</div><svg class="net" viewBox="0 0 '+W+' '+H+'" id="svg-'+c.key+'"></svg>'+
   '<div class="statline"><span>Blast radius: <b id="blast-'+c.key+'">—</b></span><span>Contained: <b id="cont-'+c.key+'">—</b></span><span>Quarantined: <b id="quar-'+c.key+'">—</b></span></div>'+
   '<div class="dtitle"><span>Recorded decisions</span><span class="quality" id="qual-'+c.key+'"></span></div>'+
   '<div class="dwrap"><table class="dtbl"><thead><tr><th>Source</th><th>Dest</th><th>Prediction</th><th>Risk</th><th>Action</th></tr></thead><tbody id="dtbl-'+c.key+'"></tbody></table></div>'+
   '<div class="summcard"><div class="h">Attacker activity before containment</div><div id="summ-'+c.key+'"></div></div>';
  $("grid").appendChild(p);
}
function draw(key){
  const d=DATA[sc()][key],svg=$("svg-"+key);svg.innerHTML="";const acl=key!=="flat";
  const B=sc()==="benign";
  const L=B?["Normal flows working","False alarm","Quarantined"]:["Blast radius","Contained","Quarantined"];
  ["blast","cont","quar"].forEach((k,i)=>{$(k+"-"+key).parentNode.firstChild.textContent=L[i]+": ";});
  $("summ-"+key).previousSibling.textContent=B?"Detection quality on normal traffic":"Attacker activity before containment";
  (B?d.pairs.map(p=>p[0].split("->").map(k=>KEYIP[k])):targets(d).map(ip=>[d.attacker,ip])).forEach(([a,t])=>{const [x1,y1]=POS[a],[x2,y2]=POS[t];
    svg.appendChild(el("line",{x1,y1,x2,y2,class:"edge",id:"edge-"+key+"-"+(B?a+"_"+t:t)}));});
  IPS.forEach(ip=>{const [x,y]=POS[ip],g=el("g",{class:"node"});
    g.appendChild(el("circle",{cx:x,cy:y,r:28,class:"ring",id:"ring-"+key+"-"+ip}));
    const c=el("circle",{cx:x,cy:y,r:22,id:"node-"+key+"-"+ip,fill:(ip===GUEST&&acl)?"var(--grey)":"var(--green)"});
    if(CRIT.includes(ip)){c.setAttribute("stroke","#f0b429");c.setAttribute("stroke-width","2.5");}
    g.appendChild(c);
    const t=el("text",{x,y:y+1});t.textContent=NAMES[ip];g.appendChild(t);
    const t2=el("text",{x,y:y+34,class:"role"});t2.textContent=ip+" · VLAN "+VLAN[ip];g.appendChild(t2);
    svg.appendChild(g);});
}
function resetPanel(c){["wave","blast","cont","quar","qual"].forEach(k=>$(k+"-"+c.key).textContent=k==="wave"||k==="qual"?"":"—");
  $("badge-"+c.key).style.visibility="hidden";$("dtbl-"+c.key).innerHTML="";
  $("summ-"+c.key).innerHTML='<div class="summrow"><span class="k">Run the attack to populate.</span></div>';draw(c.key);}
function reset(){CFG.forEach(resetPanel);const d=DATA[sc()].ml5;
  $("scninfo").innerHTML=sc()==="benign"?"No attacker · each host talks only to its usual servers (Admin to two)":"Attacker: <b>"+NAMES[d.attacker]+"</b> · Target(s): <b>"+targets(d).map(i=>NAMES[i]).join(", ")+"</b>";
  $("summary").innerHTML='Pick an attack and click <b>Start Attack</b> to replay it against all four configurations at once.';}
function row(k,v){return '<div class="summrow"><span class="k">'+k+'</span><span class="v">'+v+'</span></div>';}
async function runBenign(c){const key=c.key,d=DATA.benign[key],wave=$("wave-"+key);
  const rs=new Set(d.restricted.map(r=>r[0]+"_"+r[1])),qs=new Set(d.quarantined);
  for(let w=1;w<=3;w++){wave.textContent="round "+w+" / 3";
    for(const [p] of d.pairs){const [a,t]=p.split("->").map(k=>KEYIP[k]),e=$("edge-"+key+"-"+a+"_"+t);
      e.setAttribute("stroke","var(--green)");await sleep(110);
      if(rs.has(a+"_"+t)||qs.has(a)){e.setAttribute("stroke","var(--orange)");e.setAttribute("stroke-dasharray","5 5");}}
    qs.forEach(ip=>{const r=$("ring-"+key+"-"+ip);r.style.stroke="var(--orange)";r.classList.add("on");});
    await sleep(400);}
  wave.textContent="complete";const b=$("badge-"+key);b.style.visibility="visible";
  b.className="badge "+(d.fc?(d.quarantined.length?"r":"o"):"g");
  b.textContent=d.quarantined.length?"false quarantine":(d.fc?d.fc+" link(s) wrongly restricted":"no false alarms");
  $("blast-"+key).textContent=d.pairs_ok+"/"+d.pairs_n;
  $("cont-"+key).innerHTML=d.fc?'<span style="color:var(--orange)">'+d.fc+' wrong action(s)</span>':'<span style="color:var(--green)">none</span>';
  $("quar-"+key).textContent=d.quarantined.length?d.quarantined.map(i=>NAMES[i]).join(", ")+" (innocent)":"none";
  const tb=$("dtbl-"+key);tb.innerHTML="";
  d.rows.forEach(r=>{const tr=document.createElement("tr");tr.innerHTML="<td>"+NAMES[r[0]]+"</td><td>"+NAMES[r[1]]+"</td><td>"+r[2]+"</td><td>"+r[3]+'</td><td class="act '+r[4]+'">'+r[4]+"</td>";tb.appendChild(tr);});
  const pct=Math.round(100*d.misclassified/Math.max(1,d.rows.length));
  const q=$("qual-"+key);q.className="quality "+(pct>20?"bad":"good");q.textContent=d.misclassified+" of "+d.rows.length+" normal flows called attack ("+pct+"%)";
  $("summ-"+key).innerHTML=row("Attacker","none (benign test)")+row("Normal flows logged",d.rows.length)+row("Normal flows called attack",d.misclassified+" ("+pct+"%)")+
    row("False containments",d.fc)+row("False quarantines",d.quarantined.length?d.quarantined.map(i=>NAMES[i]).join(", "):"none")+row("Normal flows still working",d.pairs_ok+"/"+d.pairs_n);
}
async function runPanel(c){
  if(sc()==="benign")return runBenign(c);
  const key=c.key,d=DATA[sc()][key],acl=key!=="flat",wave=$("wave-"+key),att=d.attacker;
  $("node-"+key+"-"+att).setAttribute("fill","var(--red)");
  const reached=new Set(d.reached),restr=new Set(d.restricted.filter(r=>r[0]===att).map(r=>r[1])),quar=d.quarantined.includes(att);
  for(let w=1;w<=3;w++){wave.textContent="wave "+w+" / 3";
    for(const ip of targets(d)){const e=$("edge-"+key+"-"+ip),n=$("node-"+key+"-"+ip);
      if(acl&&ip===GUEST){e.setAttribute("opacity","0.22");continue;}
      if(quar&&w>1)continue;
      e.setAttribute("stroke","var(--red)");await sleep(120);
      if(restr.has(ip)){e.setAttribute("stroke","var(--orange)");e.setAttribute("stroke-dasharray","5 5");}
      else if(reached.has(ip))n.setAttribute("fill","var(--red)");}
    if(quar){$("ring-"+key+"-"+att).classList.add("on");
      targets(d).forEach(ip=>{const e=$("edge-"+key+"-"+ip);if(e.getAttribute("stroke")!=="var(--orange)"){e.setAttribute("stroke","var(--red)");e.setAttribute("stroke-dasharray","2 6");e.setAttribute("opacity","0.5");}});}
    await sleep(450);}
  wave.textContent="complete";
  const b=$("badge-"+key);b.style.visibility="visible";
  if(sc()!=="scan"){
    $("blast-"+key).textContent=(1+d.hosts)+"/8 hosts infected · "+d.crit+"/"+d.ncrit+" critical reached";
    if(d.contained){b.className="badge g";b.textContent="contained · "+(1+d.hosts)+"/8 infected";}else{b.className="badge r";b.textContent=(1+d.hosts)+"/8 hosts infected";}
  }else{
    $("blast-"+key).textContent=d.contained?"Database protected":"Database reached";
    if(d.contained){b.className="badge g";b.textContent="target link restricted";}else{b.className="badge r";b.textContent="target reached";}
  }
  $("cont-"+key).innerHTML=d.contained?'<span style="color:var(--green)">yes</span>':'<span style="color:var(--red)">no</span>';
  $("quar-"+key).textContent=d.quarantined.length?d.quarantined.map(i=>NAMES[i]).join(", "):"none";
  const tb=$("dtbl-"+key);tb.innerHTML="";
  d.rows.forEach(r=>{const tr=document.createElement("tr");
    tr.innerHTML="<td>"+NAMES[r[0]]+"</td><td>"+NAMES[r[1]]+"</td><td>"+r[2]+"</td><td>"+r[3]+'</td><td class="act '+r[4]+'">'+r[4]+"</td>";tb.appendChild(tr);});
  const q=$("qual-"+key);q.className="quality "+(d.wrong?"bad":"good");q.textContent=d.misclassified+" of "+d.rows.length+" flows mislabelled (direction) · "+d.wrong+" led to a wrong action";
    $("summ-"+key).innerHTML=row("Infected host",NAMES[att])+row("Flows logged from attacker",d.flows)+row("Unique hosts contacted",d.unique)+
    row("Risk score at detection",d.risk_at_detection==null?"—":(+d.risk_at_detection).toFixed(3))+row("Containment action",d.action)+
    row("Time to containment",d.ttc==null?"never":d.ttc+" s (measured)");
}
function summaryText(){const D=DATA[sc()];
  if(sc()==="benign"){const p=k=>Math.round(100*D[k].misclassified/Math.max(1,D[k].rows.length));
    const act=k=>D[k].quarantined.length?'<b>wrongly quarantined '+D[k].quarantined.map(i=>NAMES[i]).join(", ")+'</b>':(D[k].fc?'restricted '+D[k].fc+' link(s) but quarantined nobody':'took no wrong action');
    return 'No attack — normal traffic only. <b>Rule (C)</b> called '+p("rule")+'% of normal flows an attack and '+act("rule")+'. <b>ML (D)</b> called '+p("ml5")+'% of normal flows an attack and '+act("ml5")+
      '. Flat (A) and Static (B) never respond, so they raise no false alarms — but they cannot stop an attack either.';}
  if(sc()!=="scan"){const A=NAMES[D.ml5.attacker],n=D.ml5.ncrit;
    const res=k=>(D[k].contained?'contained ('+(1+D[k].hosts)+'/8 infected)':(1+D[k].hosts)+'/8 hosts infected, '+D[k].crit+'/'+n+' critical reached')+(D[k].ttc!=null?' in '+D[k].ttc+' s':'');
    return 'Attacker: <b>'+A+'</b>. <b>Flat (A)</b>: '+res("flat")+'. <b>Static (B)</b>: '+res("static")+'. <b>Rule (C)</b>: '+res("rule")+'. <b>ML (D)</b>: '+res("ml5")+'.'+
      (D.ml5.attacker==="10.0.0.4"?' Guest is isolated by the static VLAN ACL, so segmentation alone stops it in B, C and D.':' Static segmentation only isolates Guest, so it cannot stop a host that is allowed to reach the servers; adaptive response can.');}
  return 'Port scan on <b>Database</b>. <b>Flat (A)</b> and <b>Static (B)</b> never respond, so Database stays reachable. <b>Rule (C)</b> and <b>ML (D)</b> block only the IoT-2 → Database link (orange) and leave IoT-2\'s other access intact — a proportionate RESTRICT, not a quarantine.';}
async function start(){$("go").disabled=$("scen").disabled=true;CFG.forEach(resetPanel);
  $("summary").innerHTML='<b>Attack in progress…</b> watch all four panels.';
  await Promise.all(CFG.map(runPanel));$("summary").innerHTML=summaryText();$("go").disabled=$("scen").disabled=false;}
CFG.forEach(buildPanel);reset();$("go").onclick=start;$("reset").onclick=reset;$("scen").onchange=reset;
</script></body></html>
"""
open(OUT, "w").write(PAGE.replace("__DATA__", json.dumps(data)).replace("__RUN__", str(RUN)))
print(f"page -> {os.path.relpath(OUT, BASE)}  (run {RUN})")
