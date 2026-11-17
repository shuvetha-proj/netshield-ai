import json
s = open("decision_data.js").read()
data = json.loads(s[s.index("{"):s.rindex("}")+1])
for att in ["HR", "Finance", "Critical", "Guest"]:
    for m in ["flat", "static", "rule", "ml"]:
        c = data[att][m]
        print(f"{att:8s} {m:7s} blast={c['blast']} contained={c['contained']} quar={c['quarantined']}")
    print()
