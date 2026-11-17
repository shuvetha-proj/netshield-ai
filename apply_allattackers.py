"""Runner: new scenario 'lateralall' = lateral movement from EVERY host
(one after another), so the comparison page can offer all 8 attackers.
Backs up the runner first; every edit must match exactly once."""
import shutil, sys
F = "experiment8_runner.py"
s = open(F).read()
edits = [
 ('def run_lateral(h):\n    att = "hr"\n',
  'def run_lateral(h, att="hr"):\n'),
 ('for a, b in [("fin", "database"), ("admin", "fileserver")]}\n    reach',
  'for a, b in [p for p in [("fin", "database"), ("admin", "fileserver"),\n'
  '                                      ("hr", "fileserver"), ("iot1", "admin")] if att not in p][:2]}\n    reach'),
 ('           "critical_reached": sum(reach[c] for c in CRITICAL),\n',
  '           "critical_reached": sum(reach[c] for c in CRITICAL if c != att),\n'
  '           "critical_total": sum(1 for c in CRITICAL if c != att),\n'),
 ('           "contained": all(not reach[c] for c in CRITICAL),\n',
  '           "contained": all(not reach[c] for c in CRITICAL if c != att),\n'),
 ('assert all(s in RUNNERS for s in scenarios)',
  'assert all(s in RUNNERS or s == "lateralall" for s in scenarios)'),
 ('        for sc in scenarios:\n'
  '            for k in range(1, runs + 1):\n'
  '                print(f"[{config}] {sc} run {k}/{runs} ...", flush=True)\n'
  '                res = RUNNERS[sc](h)\n',
  '        jobs = []\n'
  '        for sc in scenarios:\n'
  '            jobs += [(sc, a) for a in HOSTS] if sc == "lateralall" else [(sc, None)]\n'
  '        for sc, att in jobs:\n'
  '            for k in range(1, runs + 1):\n'
  '                tag = f"{sc}_{att}" if att else sc\n'
  '                print(f"[{config}] {tag} run {k}/{runs} ...", flush=True)\n'
  '                res = run_lateral(h, att) if att else RUNNERS[sc](h)\n'),
 ('path = os.path.join(OUT, f"{config}_{sc}_run{k}.json")',
  'path = os.path.join(OUT, f"{config}_{tag}_run{k}.json")'),
]
for a, b in edits:
    if s.count(a) != 1:
        sys.exit(f"ABORT: expected 1 match, found {s.count(a)} for {a[:60]!r}. Nothing written.")
shutil.copy2(F, "experiment8_runner_before_allattackers.py")
for a, b in edits:
    s = s.replace(a, b)
open(F, "w").write(s)
print("runner patched: scenario 'lateralall' added (backup: experiment8_runner_before_allattackers.py)")
