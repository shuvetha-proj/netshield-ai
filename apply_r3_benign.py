"""compare_review3: add a 'Benign traffic only' option to the dropdown, shown for
all four panels, so Rule vs ML label quality and false alarms can be compared.
Backs up first; every edit must match exactly once."""
import shutil, sys
F = "build_compare_r3.py"
s = open(F).read()
E = [
('''    if key == "scan":
        cands = [[f"{c}_scan_run{RUN}.json"] for c in CFGS]
''','''    if key == "scan":
        cands = [[f"{c}_scan_run{RUN}.json"] for c in CFGS]
    elif key == "benign":
        cands = [[f"{c}_benign_run{RUN}.json"] for c in CFGS]
'''),
('for key in list(KEY_IP) + ["scan"]:', 'for key in list(KEY_IP) + ["scan", "benign"]:'),
('    sc = "scan" if key == "scan" else "lat:" + key\n', '    sc = key if key in ("scan", "benign") else "lat:" + key\n'),
('        att = KEY_IP[d["attacker"]]\n', '        att = KEY_IP.get(d.get("attacker") or "")\n'),
('''        if sc != "scan":
            reached = [KEY_IP[k] for k, v in d["reach"].items() if v]''','''        if sc == "benign":
            reached = []
        elif sc != "scan":
            reached = [KEY_IP[k] for k, v in d["reach"].items() if v]'''),
('''            "contained": d["contained"] if sc != "scan" else (not d["target_reachable"]),''',
 '''            "contained": (d.get("false_containments", 0) == 0) if sc == "benign" else d["contained"] if sc != "scan" else (not d["target_reachable"]),
            "fc": d.get("false_containments"), "pairs": list((d.get("benign_pairs_ok") or {}).items()),
            "pairs_ok": sum((d.get("benign_pairs_ok") or {}).values()), "pairs_n": len(d.get("benign_pairs_ok") or {}),'''),
('const IPS=Object.keys(NAMES),',
 'const KEYIP={hr:"10.0.0.1",fin:"10.0.0.2",fileserver:"10.0.0.3",guest:"10.0.0.4",database:"10.0.0.5",iot1:"10.0.0.6",iot2:"10.0.0.7",admin:"10.0.0.8"};\nconst IPS=Object.keys(NAMES),'),
('(k==="scan"?"IoT-2 (10.0.0.7) — port scan on Database":NAMES[ip]',
 '(k==="scan"?"IoT-2 (10.0.0.7) — port scan on Database":k==="benign"?"Benign traffic only (no attacker) — false-alarm test":NAMES[ip]'),
('''  targets(d).forEach(ip=>{const [x1,y1]=POS[d.attacker],[x2,y2]=POS[ip];
    svg.appendChild(el("line",{x1,y1,x2,y2,class:"edge",id:"edge-"+key+"-"+ip}));});''',
'''  const B=sc()==="benign";
  const L=B?["Normal flows working","False alarm","Quarantined"]:["Blast radius","Contained","Quarantined"];
  ["blast","cont","quar"].forEach((k,i)=>{$(k+"-"+key).parentNode.firstChild.textContent=L[i]+": ";});
  $("summ-"+key).previousSibling.textContent=B?"Detection quality on normal traffic":"Attacker activity before containment";
  (B?d.pairs.map(p=>p[0].split("->").map(k=>KEYIP[k])):targets(d).map(ip=>[d.attacker,ip])).forEach(([a,t])=>{const [x1,y1]=POS[a],[x2,y2]=POS[t];
    svg.appendChild(el("line",{x1,y1,x2,y2,class:"edge",id:"edge-"+key+"-"+(B?a+"_"+t:t)}));});'''),
('$("scninfo").innerHTML="Attacker: <b>"', '$("scninfo").innerHTML=sc()==="benign"?"No attacker · each host talks only to its usual servers (Admin to two)":"Attacker: <b>"'),
('async function runPanel(c){\n', '''async function runBenign(c){const key=c.key,d=DATA.benign[key],wave=$("wave-"+key);
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
'''),
('function summaryText(){const D=DATA[sc()];', '''function summaryText(){const D=DATA[sc()];
  if(sc()==="benign"){const p=k=>Math.round(100*D[k].misclassified/Math.max(1,D[k].rows.length));
    const act=k=>D[k].quarantined.length?'<b>wrongly quarantined '+D[k].quarantined.map(i=>NAMES[i]).join(", ")+'</b>':(D[k].fc?'restricted '+D[k].fc+' link(s) but quarantined nobody':'took no wrong action');
    return 'No attack — normal traffic only. <b>Rule (C)</b> called '+p("rule")+'% of normal flows an attack and '+act("rule")+'. <b>ML (D)</b> called '+p("ml5")+'% of normal flows an attack and '+act("ml5")+
      '. Flat (A) and Static (B) never respond, so they raise no false alarms — but they cannot stop an attack either.';}'''),
]
for a, b in E:
    if s.count(a) != 1:
        sys.exit(f"ABORT: expected 1 match, found {s.count(a)} for {a[:60]!r}. Nothing written.")
shutil.copy2(F, "build_compare_r3_before_benign.py")
for a, b in E:
    s = s.replace(a, b)
open(F, "w").write(s)
print("page builder patched: 'Benign traffic only' option added")
