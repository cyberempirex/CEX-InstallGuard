import re
def apply(r,patterns):
    for f in r.findings:
        if any(re.search(p,f.rule_id,re.I) or re.search(p,f.code,re.I) for p in patterns): f.suppressed=True
    return r
