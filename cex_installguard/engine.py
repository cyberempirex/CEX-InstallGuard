from .scanner import scan_text,scan_path,assess
from .models import ScanResult
class AnalysisEngine:
    def __init__(self,max_size=5242880,workers=4,ignore_paths=None): self.max_size=max_size; self.workers=workers; self.ignore_paths=ignore_paths
    def analyze_text(self,text,target='<text>'):
        return assess(ScanResult(target,files=1,lines=len(text.splitlines()),bytes_read=len(text.encode()),findings=scan_text(text,target)))
    def analyze(self,target,recursive=True,progress=None): return assess(scan_path(target,recursive,self.max_size,self.workers,progress_callback=progress,ignore_paths=self.ignore_paths))
