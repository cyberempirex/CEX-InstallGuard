from __future__ import annotations
import os,platform,shutil
from .engine import AnalysisEngine
from .rules import all_rules,search_rules,RULE_BY_ID,rule_count
from .terminal import *
from .reporter import json_report,sarif_report,html_report
from .version import VERSION


def rules_screen():
    clear(); banner(); q=ask('Search rules (Enter = all)').strip(); q='' if q.lower() == 'all' else q; rs=search_rules(q) if q else all_rules()
    section(f'Rule Explorer • {len(rs)} rules')
    for r in rs:
        print(f'  {paint(r.rule_id,YELLOW+BOLD)}  {r.severity.upper():8} {r.category:22} {r.title}')
    rid=ask('Enter rule ID for details (Enter = return)').upper()
    if rid in RULE_BY_ID:
        r=RULE_BY_ID[rid]; clear(); banner(); box(f'{r.rule_id} • {r.title}',[
            f'Severity: {r.severity.upper()}   Confidence: {r.confidence}',f'Category: {r.category}',f'Tags: {", ".join(r.tags) or "none"}',
            f'Detection: {r.pattern}',f'Why it matters: {r.description}',f'Remediation: {r.remediation}'],RED if r.severity=='critical' else YELLOW)
    pause()

def profile_screen():
    clear();banner();section('Security Profile')
    box('Analysis Model',[
        'Static, non-executing shell and installer analysis.',
        'Direct rules + contextual correlation + suspicious indicators.',
        'Target scripts are never executed by the scanner.',
        'Clean results mean no configured detector matched; they are not proof of safety.'
    ])
    box('Capabilities',[
        f'{rule_count()} detection rules (structured AST + content analysis)',
        'Risk model: confidence-weighted, log-damped severity scoring',
        'File, repository and command analysis', 'Recursive discovery and parallel workers',
        'SHA-256 hashing, baselines and suppressions', 'JSON, SARIF 2.1.0 and HTML reports'
    ],TEAL)
    pause()

def about_screen():
    clear();banner();section('About CEX-InstallGuard')
    box('Product',[f'CEX-InstallGuard {VERSION}','Developer / project: CyberEmpireX','Purpose: pre-execution security review of shell and installer scripts','Runtime: Python standard library; optional external tools may be integrated'],CYAN)
    box('Architecture',['Discovery → parser/normalization → rule engine → contextual correlation → scoring/policy → reports','Designed for Termux, Linux and macOS.','The scanner does not execute the analyzed target.'],BLUE)
    box('Security Principle',['Inspect first. Execute later.','Findings are evidence for review, not a declaration of maliciousness.','Use source review, provenance checks and controlled execution for high-risk software.'],GREEN)
    pause()

def report_screen(engine):
    clear();banner(); section('Report Generator')
    target=ask('Script or project path')
    if not target:return
    r=engine.analyze(target,recursive=True)
    render(r)
    kind=ask('Report type (json/sarif/html)') .lower(); out=ask('Output path')
    if kind=='json': json_report(r,out)
    elif kind=='sarif': sarif_report(r,out)
    elif kind=='html': html_report(r,out)
    else: print(paint('  Unknown report type.',YELLOW))
    if kind in {'json','sarif','html'}: print(paint(f'\n  Report written: {out}',GREEN+BOLD)); pause()

def scan_with_live(engine,target,project=False):
    clear(); banner(); section('Live Scan')
    print(f'  Target      {target}')
    print(f'  Mode        {"repository" if project else "single file"}')
    print(f'  Workers     {engine.workers}')
    print()
    from .ui import ScanProgress
    sp=ScanProgress('Analyzing',True)
    r=None
    sp.start()
    try:
        r=engine.analyze(target,recursive=project,progress=sp.update)
    finally:
        if r is None: sp.cancel()
        else: sp.finish(files=r.files)
    render(r)
    return r

def analyze_screen(engine, project=False):
    clear()
    banner()
    label = "Directory path" if project else "Script path"
    target = ask(label)
    if not target:
        box("Input Error", ["No target was provided.", "Returning to the command center."], RED)
        pause()
        return None
    target = target.strip()
    prefixes = ("python installguard.py ", "python3 installguard.py ", "./installguard.py ")
    for prefix in prefixes:
        if target.startswith(prefix):
            target = target[len(prefix):].strip()
            break
    if len(target) >= 2 and target[0] == target[-1] and target[0] in chr(34)+chr(39):
        target = target[1:-1]
    target = os.path.abspath(os.path.expanduser(target))
    if not os.path.exists(target):
        box("Target Not Found", [f"Path: {target}", "", "Check the path and try again.", "The target was NOT executed."], RED)
        pause()
        return None
    if project and not os.path.isdir(target):
        box("Invalid Target", ["Expected a directory:", target, "", "The target was NOT executed."], RED)
        pause()
        return None
    if not project and not os.path.isfile(target):
        box("Invalid Target", ["Expected a file:", target, "", "The target was NOT executed."], RED)
        pause()
        return None
    try:
        return scan_with_live(engine, target, project)
    except KeyboardInterrupt:
        print()
        box("Scan Cancelled", ["The scan was interrupted by the user.", "The target was NOT executed."], YELLOW)
        pause()
        return None
    except Exception as e:
        box("Analysis Error", [f"{type(e).__name__}: {e}", "", "The target was NOT executed."], RED)
        pause()
        return None

def quick_screen(engine):
    clear();banner();section('Quick Command Analysis')
    print('  Paste a shell command. It will be analyzed, never executed.')
    text=ask('Command')
    if text:
        spinner('Analyzing command'); r=engine.analyze_text(text,'<quick-command>'); render(r); return r
    return None

def findings_screen(last):
    clear();banner();
    if not last:
        box('Findings',['No scan has been completed in this session.']); pause(); return
    active=last.active(); section(f'Finding Inspector • {len(active)} active')
    if not active:
        box('Finding Inspector',['No active findings. Static analysis cannot prove safety.'],GREEN); pause(); return
    for i,f in enumerate(active,1):
        print(f'  {i:02d}  {paint(f.rule_id,YELLOW+BOLD)}  {f.severity.upper():8}  {f.title}  ({f.source}:{f.line})')
    sel=ask('Finding number (Enter = return)')
    if sel.isdigit() and 1<=int(sel)<=len(active):
        f=active[int(sel)-1]; clear(); banner(); box(f'{f.rule_id} • {f.title}',[
            f'Severity: {f.severity.upper()}   Confidence: {f.confidence}',f'Category: {f.category}',f'Source: {f.source}:{f.line}',
            f'Evidence: {f.code}',f'Why: {f.description}',f'Fix: {f.remediation}'],RED if f.severity=='critical' else YELLOW)
    pause()

def launch():
    engine=AnalysisEngine(); last=None
    while True:
        clear();banner();
        on=enabled(True); print(f'  {paint("ENGINE",DIM,on)}  {rule_count()} detection rules · AST + dataflow    {paint("PLATFORM",DIM,on)} {platform.system()} / Python {platform.python_version()}')
        print(f'  {paint("SESSION",DIM,on)}  {"Last scan: "+last.verdict+" / "+str(last.score) if last else "No scan yet"}')
        menu(); choice=ask('Command Center')
        if choice=='0': clear();banner();print('\n  Session closed.\n');return 0
        if choice=='1': last=analyze_screen(engine,False) or last
        elif choice=='2': last=analyze_screen(engine,True) or last
        elif choice=='3': last=quick_screen(engine) or last
        elif choice=='4': findings_screen(last)
        elif choice=='5': rules_screen()
        elif choice=='6': profile_screen()
        elif choice=='7': report_screen(engine)
        elif choice=='8': about_screen()
        else: print(paint('\n  Invalid command. Choose 0–8.',YELLOW)); pause()
