from .scanner import scan_text,scan_path,assess
from .models import ScanResult

def analyze_text(text,target='<text>'): return assess(ScanResult(target,findings=scan_text(text,target)))
def analyze_path(path,recursive=True,max_size=5242880,workers=4): return assess(scan_path(path,recursive,max_size,workers))
