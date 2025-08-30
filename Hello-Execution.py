#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ss.py — Suspicious EXE hunter for Prefetch/Amcache exports (TXT/CSV/TSV/JSONL)

Features
- Inputs: TXT (one path or name per line), CSV/TSV (--field / --path-field), JSON/NDJSON
- Prefetch parsing: extract EXE name from NAME-XXXXXXXX.pf (with --prefetch-mode)
- Short-name detection (length <= --max-len; default 2)
- Allowlist support + optional full override (skip rows entirely) via --allowlist-overrides
- Blacklist on names with 3 modes: token (default), substring, regex
- Bad-path detection on FULL path with 3 modes + compound-fallback in token mode
- Detailed CSV and grouped Summary CSV by name (with reasons/keywords/count/hosts)
- Debug mode to print normalized candidates and paths

Usage examples:
  TXT with full paths:
    python ss.py amcache_paths.txt --force-exe --badpaths-file badpaths.txt --badpaths-mode token \
      --blacklist blacklist.txt --blacklist-mode token --summary --summary-out summary.csv --out detailed.csv

  CSV (Kansa Prefetch):
    python ss.py PrefetchListing.csv --field FullName --prefetch-mode \
      --blacklist blacklist.txt --blacklist-mode token --summary --out detailed.csv
"""

import argparse
import csv
import json
import re
import unicodedata
from collections import defaultdict
from pathlib import Path

# ---------- helpers ----------
def norm(s: str | None) -> str:
    """Normalize strings: keep printable & path separators."""
    if not s:
        return ''
    s = s.replace('\ufeff', '')
    keep = []
    for ch in s:
        cat = unicodedata.category(ch)
        # Keep letters/numbers/punct/symbols + common path chars
        if cat[0] in ('L', 'N', 'P', 'S') or ch in ' \t\\/._-:':
            keep.append(ch)
    return ''.join(keep).strip()

def load_lines(path: Path | None) -> list[str]:
    if not path:
        return []
    out = []
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = norm(line)
        if line and not line.startswith('#'):
            out.append(line)
    return out

def tokens_from_path(p: str) -> set[str]:
    """Split a path into lowercased tokens."""
    return {t for t in re.split(r'[\\/:._\-\s]+', p.lower()) if t}

def is_compound_kw(kw: str) -> bool:
    """Compound keyword includes path separators -> needs substring fallback in token mode."""
    return ('\\' in kw) or ('/' in kw)

def name_tokens(name: str) -> set[str]:
    n = name.lower()
    if n.endswith('.exe'):
        n = n[:-4]
    return {t for t in re.split(r'[^a-z0-9]+', n) if t}

def blacklist_match_name(name: str, keywords: list[str], mode: str) -> str | None:
    low = name.lower()
    if mode == 'substring':
        for kw in keywords:
            if kw.lower() in low:
                return kw
        return None
    if mode == 'regex':
        for kw in keywords:
            try:
                if re.search(kw, low, re.IGNORECASE):
                    return kw
            except re.error:
                if kw.lower() in low:
                    return kw
        return None
    # token (default)
    toks = name_tokens(name)
    for kw in keywords:
        k = kw.lower().rstrip('.exe')
        if k in toks:
            return kw
    return None

def blacklist_match_path(path: str, keywords: list[str], mode: str) -> str | None:
    low = path.lower()
    if mode == 'substring':
        for kw in keywords:
            if kw.lower() in low:
                return kw
        return None
    if mode == 'regex':
        for kw in keywords:
            try:
                if re.search(kw, low, re.IGNORECASE):
                    return kw
            except re.error:
                if kw.lower() in low:
                    return kw
        return None
    # token (default) + compound fallback
    toks = tokens_from_path(path)
    for kw in keywords:
        k = kw.lower()
        if is_compound_kw(k):
            if k in low:  # allow precise multi-segment match e.g. "appdata\local\temp"
                return kw
        else:
            if k in toks:
                return kw
    return None

PREFETCH_NAME_RE = re.compile(r'^(?P<name>.+?)-[0-9A-F]{8}(?:-[0-9A-F]{8})?$', re.IGNORECASE)

def extract_from_prefetch(value: str) -> str:
    """Return EXE name from Prefetch filename (NAME-XXXXXXXX[...].pf)."""
    base = Path(value).name
    if base.lower().endswith('.pf'):
        base = base[:-3]
    m = PREFETCH_NAME_RE.match(base)
    prog = m.group('name') if m else (base.rsplit('-', 1)[0] if '-' in base else base)
    if prog and not prog.lower().endswith('.exe'):
        prog += '.exe'
    return prog

def derive_name(value: str | None, full_path: str | None, prefetch: bool, force_exe: bool) -> str:
    """Choose name from value or path; parse prefetch if requested."""
    v = norm(value) if value else ''
    if prefetch and v and v.lower().endswith('.pf'):
        return extract_from_prefetch(v)
    if not v and full_path:
        v = Path(full_path).name
    if not v:
        return ''
    if force_exe and not v.lower().endswith('.exe'):
        v = f'{v}.exe'
    return v

def short_name_flag(name: str, max_len: int, allowset: set[str]) -> bool:
    nm = name.lower()
    if nm in allowset:
        return False
    base = nm[:-4] if nm.endswith('.exe') else nm
    # keep only letters/digits to measure length
    pure = re.sub(r'[^a-z0-9]', '', base)
    return 1 <= len(pure) <= max_len

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Suspicious by name/blacklist/bad paths (TXT/CSV/TSV/JSONL).")
    ap.add_argument('input', type=Path, help='Input file: TXT/CSV/TSV/JSON/NDJSON.')
    ap.add_argument('--field', help='CSV/JSON field containing the program or Prefetch filename.')
    ap.add_argument('--path-field', help='CSV/JSON field containing the FULL path (e.g., Amcache Path).')
    ap.add_argument('--delim', choices=[',',';','\\t'], help='CSV/TSV delimiter (\\t means TAB).')
    ap.add_argument('--prefetch-mode', action='store_true', help='Treat names as Prefetch filenames.')
    ap.add_argument('--force-exe', action='store_true', help='Append .exe when missing.')
    ap.add_argument('--max-len', type=int, default=2, help='Short-name length threshold (default: 2).')

    ap.add_argument('--allowlist', type=Path, help='Text file of allowed names (one per line).')
    ap.add_argument('--allowlist-overrides', action='store_true',
                    help='If set, skip rows entirely when name is in allowlist (overrides blacklist too).')

    ap.add_argument('--blacklist', type=Path, help='Text file with suspicious name keywords (one per line).')
    ap.add_argument('--blacklist-mode', choices=['token','substring','regex'], default='token',
                    help='How to match blacklist keywords against name (default: token).')

    ap.add_argument('--badpaths-file', type=Path, help='Text file with suspicious path keywords (one per line).')
    ap.add_argument('--badpaths-mode', choices=['token','substring','regex'], default='token',
                    help='How to match bad path keywords against full path (default: token).')
    ap.add_argument('--use-default-badpaths', action='store_true',
                    help='Include built-in suspicious path keywords (Downloads/Temp/Public/etc).')

    ap.add_argument('--out', type=Path, help='Write detailed CSV.')
    ap.add_argument('--summary', action='store_true', help='Print summary by name.')
    ap.add_argument('--summary-out', type=Path, help='Write summary CSV.')
    ap.add_argument('--debug', action='store_true', help='Print debug lines.')

    args = ap.parse_args()

    allowset = {x.lower() for x in load_lines(args.allowlist)}
    blist = load_lines(args.blacklist)
    badpaths = load_lines(args.badpaths_file)
    if args.use_default_badpaths:
        badpaths += [
            'users','public','programdata','downloads','desktop','documents','appdata',
            'local','roaming','temp','startup','recycle.bin','perflogs','inetpub','wwwroot',
            'windows\\temp','appdata\\local\\temp','appdata\\roaming','onedrive'
        ]

    # CSV delimiter
    delimiter = '\t' if args.delim == '\\t' else (args.delim if args.delim else None)

    # Aggregation
    hits = []
    agg_count = defaultdict(int)
    agg_reasons = defaultdict(set)
    agg_keywords = defaultdict(set)
    agg_hosts = defaultdict(set)  # if provided by CSV/JSON

    # Field guesses
    COMMON_FIELD_GUESSES = (
        'ExecutableName','ImageName','ProcessName','Name',
        'PrefetchFilename','Filename','ProgramName','FullName'
    )
    HOST_FIELD_GUESSES = ('PSComputerName','ComputerName','Host','Hostname')
    PATH_FIELD_GUESSES = ('Path','ExecutablePath','FullPath')

    # -------- read & iterate --------
    suffix = args.input.suffix.lower()

    def handle_row(name: str, full_path: str | None, host: str | None, source_line: str):
        if not name:
            return
        candidate = name
        if args.force_exe and not candidate.lower().endswith('.exe'):
            candidate += '.exe'

        if args.debug:
            print(f"[debug] cand={candidate!r} path={full_path!r} host={host!r} from={source_line!r}")

        # allowlist overrides everything (optional)
        if args.allowlist_overrides and candidate.lower() in allowset:
            return

        reasons = []
        kw_name = ''
        kw_path = ''

        # name blacklist
        if blist:
            k = blacklist_match_name(candidate, blist, args.blacklist_mode)
            if k:
                reasons.append('blacklist')
                kw_name = k

        # short name
        if short_name_flag(candidate, args.max_len, allowset):
            reasons.append('short_name')

        # bad path
        if full_path and badpaths:
            kp = blacklist_match_path(full_path, badpaths, args.badpaths_mode)
            if kp:
                reasons.append('bad_path')
                kw_path = kp

        if not reasons:
            return

        hit = {
            'name': candidate,
            'reason': ','.join(sorted(set(reasons))),
            'keyword_name': kw_name,
            'keyword_path': kw_path,
            'path': full_path or '',
            'host': host or '',
            'source_line': source_line
        }
        hits.append(hit)

        key = candidate.lower()
        agg_count[key] += 1
        for r in set(reasons):
            agg_reasons[key].add(r)
        if kw_name:
            agg_keywords[key].add(kw_name)
        if host:
            agg_hosts[key].add(str(host))

    if delimiter or suffix in ('.csv', '.tsv'):
        d = delimiter or (',' if suffix == '.csv' else '\t')
        with args.input.open('r', encoding='utf-8', errors='ignore', newline='') as f:
            reader = csv.DictReader(f, delimiter=d)
            for row in reader:
                source = json.dumps(row, ensure_ascii=False)
                host = None
                for hf in HOST_FIELD_GUESSES:
                    if row.get(hf):
                        host = row[hf]
                        break
                val = row.get(args.field) if args.field else None
                if not val:
                    for guess in COMMON_FIELD_GUESSES:
                        if row.get(guess):
                            val = row[guess]; break
                pval = row.get(args.path_field) if args.path_field else None
                if not pval:
                    for pg in PATH_FIELD_GUESSES:
                        if row.get(pg):
                            pval = row[pg]; break
                name = derive_name(val, pval, args.prefetch_mode, args.force_exe)
                handle_row(name, norm(pval) if pval else None, host, source)

    elif suffix in ('.json', '.ndjson'):
        for line in args.input.read_text(encoding='utf-8', errors='ignore').splitlines():
            ln = norm(line)
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            source = json.dumps(obj, ensure_ascii=False)
            host = None
            for hf in HOST_FIELD_GUESSES:
                if obj.get(hf):
                    host = obj[hf]; break
            val = obj.get(args.field) if args.field else None
            if not val:
                for guess in COMMON_FIELD_GUESSES:
                    if obj.get(guess):
                        val = obj[guess]; break
            pval = obj.get(args.path_field) if args.path_field else None
            if not pval:
                for pg in PATH_FIELD_GUESSES:
                    if obj.get(pg):
                        pval = obj[pg]; break
            name = derive_name(val, pval, args.prefetch_mode, args.force_exe)
            handle_row(name, norm(pval) if pval else None, host, source)

    else:
        # TXT: each line may be a full path OR a plain name
        for line in args.input.read_text(encoding='utf-8', errors='ignore').splitlines():
            ln = norm(line)
            if not ln:
                continue
            if ('\\' in ln) or ('/' in ln):
                p = ln
                n = Path(ln).name
            else:
                p = None
                n = ln
            # Prefetch parsing applies only if n looks like a .pf (rare in TXT)
            name = derive_name(n, p, args.prefetch_mode, args.force_exe)
            handle_row(name, p, None, ln)

    # -------- output --------
    if not hits:
        print("[i] No suspicious items found.")
    else:
        print(f"[+] Suspicious results ({len(hits)}):")
        for h in hits:
            extras = []
            if h['keyword_name']:
                extras.append(f"name_kw={h['keyword_name']}")
            if h['keyword_path']:
                extras.append(f"path_kw={h['keyword_path']}")
            if h['path']:
                extras.append(f"path={h['path']}")
            if h['host']:
                extras.append(f"host={h['host']}")
            print(f"- {h['name']} <-- {h['reason']}  [{', '.join(extras)}]")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['name','reason','keyword_name','keyword_path','path','host','source_line'])
            writer.writeheader()
            for h in hits:
                writer.writerow(h)
        print(f"[+] Saved detailed CSV: {args.out}")

    if args.summary:
        if not agg_count:
            print("[i] Summary: no hits.")
        else:
            print("\n[+] Summary (by name):")
            items = sorted(agg_count.items(), key=lambda kv: (-kv[1], kv[0]))
            for key, cnt in items:
                name = next((h['name'] for h in hits if h['name'].lower() == key), key)
                reasons = ','.join(sorted(agg_reasons[key]))
                keywords = ','.join(sorted(agg_keywords[key])) if agg_keywords[key] else ''
                hosts = ','.join(sorted(agg_hosts[key])) if agg_hosts[key] else ''
                print(f"* {name:25}  count={cnt:4}  reasons={reasons or '-'}"
                      f"{('  name_keywords='+keywords) if keywords else ''}"
                      f"{('  hosts='+hosts) if hosts else ''}")

        if args.summary_out:
            args.summary_out.parent.mkdir(parents=True, exist_ok=True)
            with args.summary_out.open('w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['name','reasons','name_keywords','count','hosts'])
                for key, cnt in sorted(agg_count.items(), key=lambda kv: (-kv[1], kv[0])):
                    name = next((h['name'] for h in hits if h['name'].lower() == key), key)
                    reasons = ','.join(sorted(agg_reasons[key]))
                    keywords = ','.join(sorted(agg_keywords[key])) if agg_keywords[key] else ''
                    hosts = ','.join(sorted(agg_hosts[key])) if agg_hosts[key] else ''
                    w.writerow([name, reasons, keywords, cnt, hosts])
            print(f"[+] Saved summary CSV: {args.summary_out}")

if __name__ == '__main__':
    main()
