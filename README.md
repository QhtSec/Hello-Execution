# Hello Execution – DFIR Script

## Description
This script is designed to quickly flag suspicious executables from **Prefetch, Amcache, or simple lists of paths/names**.
It focuses on:
- **Short names** (like `a.exe`, `go.exe`) often used by malware.
- **Blacklist matches**  known attacker tools (e.g., Anydisk, PsExec ...).
- **Suspicious paths** (e.g., `Downloads`, `Temp`, `Public`).

The script supports multiple input formats (TXT, CSV, TSV, JSONL) and outputs both **detailed results** and a **summary report** to make compromise assessments (CA) easier on large environments.

---

## Features
- Input support: TXT, CSV, TSV, JSON/NDJSON
- Prefetch parsing (`NAME-XXXXXXXX.pf → real EXE name`)
- Short-name detection (configurable length, default ≤ 2)
- Blacklist & allowlist filtering
- Suspicious path detection (Downloads, Temp, Public, etc.)
- Multiple blacklist modes: token, substring, regex
- Detailed CSV output (per hit) + grouped summary CSV
- Debug mode for transparency while parsing

---

## Installation
1. Install Python (if you haven’t already):
    
        choco install python
    
2. Clone the repository:
    
        git clone https://github.com/QhtSec/Hello-Execution.git
        cd Hello-Execution
    
3. Run the script with Python:
    
        python Hello-Execution.py -h

---

## Usage

### Example 1 – TXT file with Prefetch names
    
        python Hello-Execution.py prefetch_list.txt --prefetch-mode --summary --out detailed.csv --summary-out summary.csv

### Example 2 – TXT file with full paths (like Amcache exports)
    
        python Hello-Execution.py amcache_paths.txt --force-exe --use-default-badpaths --blacklist blacklist.txt --summary --out detailed.csv --summary-out summary.csv

### Example 3 – CSV with specific fields
    
        python Hello-Execution.py amcache.csv --field ExecutableName --path-field Path --blacklist blacklist.txt --allowlist allow.txt --use-default-badpaths --summary --out amcache_detailed.csv --summary-out amcache_summary.csv

---

## Output
After execution, the script generates:
- **Detailed CSV** → every suspicious hit with reasons (short_name, blacklist, bad_path)
- **Summary CSV** → grouped by executable name with counts and keywords

Example:
    
        - AnyDesk.exe <-- blacklist  [name_kw=AnyDesk  path=C:\Users\Public\AnyDesk.exe]
        - evil.exe    <-- bad_path   [path_kw=downloads path=C:\Users\USER\Downloads\evil.exe]
        
        [+] Summary (grouped by name):
        * AnyDesk.exe   count=12  reasons=blacklist  keywords=AnyDesk
        * evil.exe      count=5   reasons=bad_path   keywords=downloads

---

## Notes
- Running on large Amcache exports (hundreds of thousands of rows) is supported.
- Make sure your **blacklist.txt** and **allowlist.txt** are prepared to reduce noise.
- `--debug` can help you verify path parsing if results look off.
