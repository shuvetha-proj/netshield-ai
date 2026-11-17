"""compare_review3: dropdown for all 8 attackers; no label-error display.
Backs up build_compare_r3.py; required edits must match exactly once."""
import shutil, sys
F = "build_compare_r3.py"
s = open(F).read()
REQ = [
('''data = {}
for sc in SCENS:
    for c in CFGS:
        p = os.path.join(IN, f"{c}_{sc}_run{RUN}.json")
        if not os.path.exists(p):
            sys.exit(f"missing {p} -- run experiment8_runner.py {c} first")
        d = json.load(open(p))
''','''def files_for(key):
    """Recorded files for one dropdown entry, or None if any config is missing."""
    if key == "scan":
        cands = [[f"{c}_scan_run{RUN}.json"] for c in CFGS]
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
for key in list(KEY_IP) + ["scan"]:
    paths = files_for(key)
    if paths is None:
        continue
    sc = "scan" if key == "scan" else "lat:" + key
    for c, p in zip(CFGS, paths):
        d = json.load(open(p))
'''),
('''        if sc == "lateral":
            reached''','''        if sc != "scan":
            reached'''),
('''            "crit": d.get("critical_reached"), "hosts": d.get("hosts_reached"),
            "contained": d["contained"] if sc == "lateral" else''','''            "crit": d.get("critical_reached"), "ncrit": d.get("critical_total", 2),
            "hosts": d.get("hosts_reached"),
            "contained": d["contained"] if sc != "scan" else'''),
('SCENS = ["lateral", "scan"]\n',''),
('''    <select id="scen">
      <option value="lateral">HR (10.0.0.1) — lateral movement to all 7 hosts</option>
      <option value="scan">IoT-2 (10.0.0.7) — port scan on Database</option>
    </select></label>''','''    <select id="scen"></select></label>'''),
('function targets(d){return sc()==="scan"?[d.target]:IPS.filter(ip=>ip!==d.attacker);}',
 'function targets(d){return sc()==="scan"?[d.target]:IPS.filter(ip=>ip!==d.attacker);}\n'
 'Object.keys(DATA).forEach(k=>{const ip=DATA[k].ml5.attacker;$("scen").innerHTML+=\'<option value="\'+k+\'">\'+(k==="scan"?"IoT-2 (10.0.0.7) — port scan on Database":NAMES[ip]+" ("+ip+") — lateral movement to all other hosts")+"</option>";});'),
('  if(sc()==="lateral"){\n    $("blast-"+key).textContent=d.crit+"/2 critical · "+d.hosts+"/7 hosts";\n    if(d.contained){b.className="badge g";b.textContent="0/2 — contained";}else{b.className="badge r";b.textContent=d.crit+"/2 critical reached";}',
 '  if(sc()!=="scan"){\n    $("blast-"+key).textContent=d.crit+"/"+d.ncrit+" critical · "+d.hosts+"/7 hosts";\n    if(d.contained){b.className="badge g";b.textContent="0/"+d.ncrit+" — contained";}else{b.className="badge r";b.textContent=d.crit+"/"+d.ncrit+" critical reached";}'),
('''  if(sc()==="lateral") return 'Same attack, four outcomes. <b>Flat (A)</b> lets HR reach '+D.flat.hosts+'/7 hosts and '+D.flat.crit+'/2 critical assets; <b>Static (B)</b> blocks only Guest, so HR still reaches '+D.static.crit+'/2 critical assets — VLANs cannot tell legitimate access from infected access. '+
   '<b>Rule (C)</b> and <b>ML (D)</b> both quarantine HR (0/2) in '+D.rule.ttc+' s and '+D.ml5.ttc+' s. Containment outcome is a tie on this clean attack; the ML advantage shows on benign traffic (fewer mislabelled flows, no false quarantines — see compare8.html).';''',
'''  if(sc()!=="scan"){const A=NAMES[D.ml5.attacker],n=D.ml5.ncrit;
    const res=k=>(D[k].contained?'contained (0/'+n+' critical)':'reached '+D[k].crit+'/'+n+' critical, '+D[k].hosts+'/7 hosts')+(D[k].ttc!=null?' in '+D[k].ttc+' s':'');
    return 'Attacker: <b>'+A+'</b>. <b>Flat (A)</b>: '+res("flat")+'. <b>Static (B)</b>: '+res("static")+'. <b>Rule (C)</b>: '+res("rule")+'. <b>ML (D)</b>: '+res("ml5")+'.'+
      (D.ml5.attacker==="10.0.0.4"?' Guest is isolated by the static VLAN ACL, so segmentation alone stops it in B, C and D.':' Static segmentation only isolates Guest, so it cannot stop a host that is allowed to reach the servers; adaptive response can.');}'''),
]
OPT = [  # label-error display: removed for all panels (skipped if already removed)
('if(r[5])tr.className="mis";',''),
('+r[2]+(r[5]?" ⚠":"")+','+r[2]+'),
('const q=$("qual-"+key);q.className="quality "+(d.misclassified?"bad":"good");q.textContent=d.misclassified+" of "+d.rows.length+" mislabelled";',''),
('q.textContent="";',''),
('critical asset / mislabelled flow','critical asset'),
]
for a, b in REQ:
    if s.count(a) != 1:
        sys.exit(f"ABORT: expected 1 match, found {s.count(a)} for {a[:60]!r}. Nothing written.")
shutil.copy2(F, "build_compare_r3_before_allhosts.py")
for a, b in REQ:
    s = s.replace(a, b)
for a, b in OPT:
    if s.count(a) == 1:
        s = s.replace(a, b)
open(F, "w").write(s)
print("page builder patched: all-attacker dropdown, no label-error display")
