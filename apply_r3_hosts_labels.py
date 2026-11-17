"""compare_review3: badge shows hosts infected out of 8; label errors shown for
EVERY panel with how many led to a wrong action. Backs up first; exact matches."""
import shutil, sys
F = "build_compare_r3.py"
s = open(F).read()
E = [
('        mis = 0\n', '        mis = 0\n        wrong = 0\n'),
('            mis += m\n', '            mis += m\n            wrong += bool(m and r["action"] in CONTAIN)\n'),
('"rows": out_rows, "misclassified": mis,', '"rows": out_rows, "misclassified": mis, "wrong": wrong,'),
('''    $("blast-"+key).textContent=d.crit+"/"+d.ncrit+" critical · "+d.hosts+"/7 hosts";
    if(d.contained){b.className="badge g";b.textContent="0/"+d.ncrit+" — contained";}else{b.className="badge r";b.textContent=d.crit+"/"+d.ncrit+" critical reached";}''',
'''    $("blast-"+key).textContent=(1+d.hosts)+"/8 hosts infected · "+d.crit+"/"+d.ncrit+" critical reached";
    if(d.contained){b.className="badge g";b.textContent="contained · "+(1+d.hosts)+"/8 infected";}else{b.className="badge r";b.textContent=(1+d.hosts)+"/8 hosts infected";}'''),
('tb.appendChild(tr);});',
 'tb.appendChild(tr);});\n  const q=$("qual-"+key);q.className="quality "+(d.wrong?"bad":"good");'
 'q.textContent=d.misclassified+" of "+d.rows.length+" flows mislabelled (direction) · "+d.wrong+" led to a wrong action";'),
("""(D[k].contained?'contained (0/'+n+' critical)':'reached '+D[k].crit+'/'+n+' critical, '+D[k].hosts+'/7 hosts')""",
 """(D[k].contained?'contained ('+(1+D[k].hosts)+'/8 infected)':(1+D[k].hosts)+'/8 hosts infected, '+D[k].crit+'/'+n+' critical reached')"""),
]
for a, b in E:
    if s.count(a) != 1:
        sys.exit(f"SKIP: already applied or not matching ({a[:40]!r}). Nothing written.")
shutil.copy2(F, "build_compare_r3_before_hosts8.py")
for a, b in E:
    s = s.replace(a, b)
open(F, "w").write(s)
print("page builder patched: X/8 hosts infected + label errors on every panel")
