from __future__ import annotations
import re, shlex

def strip_comments(line:str)->str:
    out=[]; quote=None; esc=False
    for i,ch in enumerate(line):
        if esc: out.append(ch); esc=False; continue
        if ch=='\\': out.append(ch); esc=True; continue
        if quote:
            out.append(ch)
            if ch==quote: quote=None
            continue
        if ch in "'\"": quote=ch; out.append(ch); continue
        if ch=='#' and (i==0 or line[i-1].isspace()): break
        out.append(ch)
    return ''.join(out)

def mask_strings(line:str)->str:
    out=[]; quote=None; esc=False
    for ch in line:
        if esc: out.append(' '); esc=False; continue
        if ch=='\\': out.append(' '); esc=True; continue
        if quote:
            if ch==quote: quote=None
            out.append(' '); continue
        if ch in "'\"": quote=ch; out.append(ch); continue
        out.append(ch)
    return ''.join(out)

def normalize(lines):
    return [strip_comments(x).rstrip() for x in lines]

def tokens(line:str):
    try: return shlex.split(line, posix=True)
    except ValueError: return re.findall(r'[^\s]+', line)

def command_names(line:str):
    t=tokens(line); return [x for x in t if re.match(r'^[A-Za-z_][\w.-]*$',x)]
