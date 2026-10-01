from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass(frozen=True)
class Rule:
    rule_id:str; title:str; severity:str; category:str; pattern:str; description:str; remediation:str; confidence:str='high'; tags:tuple[str,...]=()

@dataclass
class Finding:
    rule_id:str; title:str; severity:str; category:str; confidence:str; line:int; column:int; code:str; description:str; remediation:str; source:str='CEX'; suppressed:bool=False; evidence:dict[str,Any]=field(default_factory=dict)
    def fingerprint(self): return f'{self.rule_id}:{self.source}:{self.line}:{self.code.strip()}'
    def to_dict(self): return asdict(self)

@dataclass
class ScanResult:
    target:str; files:int=0; lines:int=0; bytes_read:int=0; duration_ms:float=0; score:int=0; verdict:str='UNKNOWN'; findings:list[Finding]=field(default_factory=list); errors:list[str]=field(default_factory=list); engine:str='CEX-InstallGuard 13.0.0'; metadata:dict[str,Any]=field(default_factory=dict)
    def active(self): return [f for f in self.findings if not f.suppressed]
    def counts(self):
        d={x:0 for x in ('critical','high','medium','low')}
        for f in self.active(): d[f.severity]=d.get(f.severity,0)+1
        return d
    def density(self):
        """Active findings per 1000 lines (a normalized signal density)."""
        return len(self.active()) / max(1, self.lines) * 1000
    def categories(self):
        out={}
        for f in self.active(): out[f.category]=out.get(f.category,0)+1
        return dict(sorted(out.items(), key=lambda x:(-x[1],x[0])))
    def to_dict(self): return {**asdict(self),'counts':self.counts(),'categories':self.categories(),'findings':[f.to_dict() for f in self.findings]}
