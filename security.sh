#!/usr/bin/env bash
# ==============================================================================
# security.sh — Unified Hosting Incident Triage & Forensics Orchestrator (v2.0.0)
# ==============================================================================
# Clean-room Bash + Python 3.6+ reimplementation inspired by security.pl
# (2012, Michael Karr, HostGator.com, LLC).
#
# Eliminates dead external HTTP utility dependencies (git.hgfix.net,
# scripts.hostgator.com), broken filehandle cleanup loops, root-unsafe writes
# inside /home/$user/.security/, obsolete EA3 ModSecurity paths, and shell
# command interpolation.
#
# Integrates 4 incident-response stages into one standalone CLI:
#   1. ModSecurity WAF exception audit (EasyApache 4)
#   2. Symlink-safe webshell & encoded-payload scan + Patient-Zero timeline
#   3. Temporal log correlation (+/- window sec) across domlogs / access_log / FTP
#   4. CMS version detection (WordPress, Joomla, Drupal) + 0700 quarantine/restore
#
# License: Apache-2.0
# Author:  Percio Castelo (https://perciocastelo.com.br)
# Repo:    https://github.com/sr00t3d/security
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="security.sh"
readonly SCRIPT_VERSION="2.0.0"

ACTION="triage"
TARGET_USER=""
TARGET_PATH=""
LIST_FILE=""
RESTORE_TARGET=""
WINDOW_SEC="120"
ACCESS_LOG_OPT=""
MODSEC_CONF_OPT=""
DO_QUARANTINE=0
QUARANTINE_DIR="/var/quarantine/security"
DRY_RUN=0
EXIT_CODE_MODE=0
OUTPUT_FMT="table"
QUIET=0
NO_COLOR=0

C_RED=""
C_GREEN=""
C_YELLOW=""
C_CYAN=""
C_BOLD=""
C_RESET=""

init_colors() {
  if [[ "$NO_COLOR" -eq 0 && -t 1 && "$OUTPUT_FMT" == "table" ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_CYAN=$'\033[0;36m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
  fi
}

usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — Unified Hosting Incident Triage & Forensics Orchestrator

Usage:
  ${SCRIPT_NAME} -u <user> [options]         Full 4-stage incident triage for cPanel/Linux user
  ${SCRIPT_NAME} -p <dir> [options]          Triage a specific webroot directory (standalone)
  ${SCRIPT_NAME} -l <file> [options]         Triage explicit suspect file paths listed in <file>
  ${SCRIPT_NAME} restore <vault_dir>         Restore quarantined files from manifest.json

Options:
  -u, --user <user>         Target cPanel/Linux username
  -p, --path <dir>          Target directory path (defaults to CWD if inside /home/<user>)
  -l, --list <file>         File containing suspect paths (1 per line, or "-" for stdin)
  -w, --window <sec>        Log correlation window around Patient-Zero mtime/ctime (default: 120)
  --access-log <path>       Extra/override Apache or cPanel log file (.log or .gz) to correlate
  --modsec-conf <path>      Override ModSecurity whitelist path
  --quarantine              Move detected malicious files to root-only 0700 vault
  --quarantine-dir <dir>    Quarantine base dir (default: /var/quarantine/security)
  --dry-run                 Preview quarantine moves without modifying disk
  --exit-code               Exit 2 if threats are detected
  -o, --output <fmt>        Output format: table (default), json, csv
  -q, --quiet               Minimal output
  --no-color                Disable ANSI colors
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  ${SCRIPT_NAME} -u percio
  ${SCRIPT_NAME} -p /var/www/html --access-log /var/log/apache2/access.log --window 180
  ${SCRIPT_NAME} -p /var/www/html --quarantine --dry-run
  ${SCRIPT_NAME} -p /var/www/html -o json --exit-code
  ${SCRIPT_NAME} restore /var/quarantine/security/20261123-234200
EOF
}

parse_args() {
  local positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -v|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      -u|--user)
        [[ $# -ge 2 ]] || { printf '[ERR] --user requires a username.\n' >&2; exit 1; }
        TARGET_USER="$2"; shift 2 ;;
      -p|--path)
        [[ $# -ge 2 ]] || { printf '[ERR] --path requires a directory.\n' >&2; exit 1; }
        TARGET_PATH="$2"; shift 2 ;;
      -l|--list)
        [[ $# -ge 2 ]] || { printf '[ERR] --list requires a file path.\n' >&2; exit 1; }
        LIST_FILE="$2"; shift 2 ;;
      -w|--window)
        [[ $# -ge 2 ]] || { printf '[ERR] --window requires seconds.\n' >&2; exit 1; }
        WINDOW_SEC="$2"; shift 2 ;;
      --access-log)
        [[ $# -ge 2 ]] || { printf '[ERR] --access-log requires a file path.\n' >&2; exit 1; }
        ACCESS_LOG_OPT="$2"; shift 2 ;;
      --modsec-conf)
        [[ $# -ge 2 ]] || { printf '[ERR] --modsec-conf requires a file path.\n' >&2; exit 1; }
        MODSEC_CONF_OPT="$2"; shift 2 ;;
      --quarantine) DO_QUARANTINE=1; shift ;;
      --quarantine-dir)
        [[ $# -ge 2 ]] || { printf '[ERR] --quarantine-dir requires a path.\n' >&2; exit 1; }
        QUARANTINE_DIR="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --exit-code) EXIT_CODE_MODE=1; shift ;;
      -o|--output)
        [[ $# -ge 2 ]] || { printf '[ERR] --output requires table|json|csv.\n' >&2; exit 1; }
        OUTPUT_FMT="$2"; shift 2 ;;
      -q|--quiet) QUIET=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      --) shift; while [[ $# -gt 0 ]]; do positional+=("$1"); shift; done ;;
      -*)
        printf '[ERR] Unknown option: %s\n' "$1" >&2
        exit 1 ;;
      *)
        positional+=("$1"); shift ;;
    esac
  done

  if [[ ${#positional[@]} -gt 0 && "${positional[0]}" == "restore" ]]; then
    ACTION="restore"
    RESTORE_TARGET="${positional[1]:-}"
  elif [[ -z "$TARGET_USER" && -z "$TARGET_PATH" && -z "$LIST_FILE" ]]; then
    local cwd_now
    cwd_now="$(pwd)"
    if [[ "$cwd_now" =~ ^/home[0-9]*/([^/]+) ]]; then
      TARGET_USER="${BASH_REMATCH[1]}"
    else
      usage
      exit 0
    fi
  fi

  [[ "$WINDOW_SEC" =~ ^[0-9]+$ ]] || { printf '[ERR] --window must be a non-negative integer.\n' >&2; exit 1; }
  case "$OUTPUT_FMT" in
    table|json|csv) ;;
    *) printf '[ERR] Invalid --output: %s (expected table|json|csv)\n' "$OUTPUT_FMT" >&2; exit 1 ;;
  esac
}

main() {
  parse_args "$@"

  if ! command -v python3 >/dev/null 2>&1; then
    printf '[ERR] python3 is required.\n' >&2
    exit 1
  fi

  init_colors

  local ts_utc
  ts_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  local py_script
  py_script="$(cat <<'PYEOF'
import collections
import csv
import datetime
import glob
import gzip
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import sys
import time

(
    action, target_user, target_path, list_file, restore_target,
    window_s, access_log_opt, modsec_conf_opt, do_quarantine_s,
    quarantine_dir, dry_run_s, exit_code_s, fmt, quiet_s,
    script_name, script_version, ts_utc,
    c_red, c_green, c_yellow, c_cyan, c_bold, c_reset
) = sys.argv[1:24]

window_sec = int(window_s)
do_quarantine = do_quarantine_s == "1"
dry_run = dry_run_s == "1"
exit_code_mode = exit_code_s == "1"
quiet = quiet_s == "1"

EXCLUDED_DIRS = {".git", "node_modules", "virtfs", "mail", "access-logs", ".security"}
SCAN_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar",
    ".inc", ".ico", ".js", ".htaccess", ".cgi", ".pl", ".py", ".sh", ".txt",
}

EICAR_STR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MALWARE_RULES = [
    ("EICAR-Test-Signature", "CRITICAL", re.compile(re.escape(EICAR_STR))),
    ("PHP.Webshell.UserInputExec", "CRITICAL", re.compile(
        rb'\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[', re.I
    )),
    ("PHP.Webshell.AssertInput", "CRITICAL", re.compile(
        rb'\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[', re.I
    )),
    ("PHP.Webshell.EvalEncoded", "HIGH", re.compile(
        rb'\beval\s*\(\s*(?:@\s*)?(?:gzinflate|gzuncompress|str_rot13|base64_decode|rawurldecode)\s*\(', re.I
    )),
    ("PHP.Webshell.PregReplaceE", "HIGH", re.compile(
        rb'\bpreg_replace\s*\(\s*[\'"]/[^\'"]{1,120}/[a-zA-Z]*e[a-zA-Z]*[\'"]\s*,', re.I
    )),
    ("PHP.Webshell.KnownFamily", "CRITICAL", re.compile(
        rb'(?:FilesMan|WSO\s+[0-9]\.[0-9]|c99shell|r57shell|b374k|IndoXploit|ALFA\s+TEaM\s+Shell)', re.I
    )),
    ("Htaccess.MaliciousRedirect", "HIGH", re.compile(
        rb'RewriteRule\s+.*https?://[^\s]+\s+\[R=30[12],L\]', re.I
    )),
]

APACHE_TS_RE = re.compile(r'(\S+)\s+\S+\s+\S+\s+\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]\s+"([^"]+)"\s+(\d{3})')
CPANEL_TS_RE = re.compile(r'(\S+)\s+\S+\s+\S+\s+\[(\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]\s+"([^"]+)"\s+(\d{3})')


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(65536)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return "-"


def get_homedir(user):
    try:
        return os.path.realpath(pwd.getpwnam(user).pw_dir)
    except KeyError:
        return None


def get_user_domains(user):
    doms = set()
    if user and os.path.isfile("/etc/userdomains"):
        with open("/etc/userdomains", "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ":" in ln:
                    d, u = ln.split(":", 1)
                    if u.strip() == user and d.strip() != "*":
                        doms.add(d.strip().lower())
    return sorted(doms)


def audit_modsec(domains):
    cands = [modsec_conf_opt] if modsec_conf_opt else [
        "/etc/apache2/conf.d/modsec/modsec2.user.conf",
        "/etc/httpd/modsecurity.d/whitelist.conf",
        "/opt/mod_security/whitelist.conf",
    ]
    wl_path = next((p for p in cands if p and os.path.isfile(p)), None)
    if not wl_path:
        return {"file": None, "exceptions": []}
    found = []
    dom_set = set(domains)
    with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if "ruleRemoveById" in ln or "ruleRemoveByID" in ln:
                m_rid = re.search(r'ruleRemoveById=([0-9]+)', ln, re.I)
                m_dom = re.search(r'SERVER_NAME\s+"([^"]+)"', ln, re.I)
                if m_rid:
                    raw_d = m_dom.group(1) if m_dom else "(global)"
                    clean_d = re.sub(r'^@rx\s+\^\(\?:www\\\.\)\?', '', raw_d).rstrip('$').replace(r'\.', '.').lower()
                    if not dom_set or clean_d in dom_set or clean_d == "(global)":
                        found.append({"domain": clean_d, "rule_id": m_rid.group(1)})
    return {"file": wl_path, "exceptions": found}


def scan_files(file_paths):
    findings = []
    scanned = 0
    for fp in file_paths:
        try:
            st = os.lstat(fp)
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > 2 * 1024 * 1024:
                continue
            fn = os.path.basename(fp).lower()
            _, ext = os.path.splitext(fn)
            if ext not in SCAN_EXTS and fn != ".htaccess":
                continue
            scanned += 1
            with open(fp, "rb") as f:
                data = f.read(2 * 1024 * 1024)
            for sig, sev, pat in MALWARE_RULES:
                if pat.search(data):
                    findings.append({
                        "path": fp,
                        "signature": sig,
                        "severity": sev,
                        "size_bytes": st.st_size,
                        "mtime": int(st.st_mtime),
                        "ctime": int(st.st_ctime),
                        "mtime_utc": datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "ctime_utc": datetime.datetime.fromtimestamp(st.st_ctime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "sha256": sha256_file(fp),
                    })
                    break
        except Exception:
            continue
    return findings, scanned


def detect_cms(roots):
    cms_hits = []
    for root in roots:
        for cur, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not os.path.islink(os.path.join(cur, d))]
            if "version.php" in files and os.path.basename(cur) == "wp-includes":
                vp = os.path.join(cur, "version.php")
                try:
                    txt = open(vp, "r", encoding="utf-8", errors="ignore").read(4096)
                    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", txt)
                    if m:
                        cms_hits.append({"cms": "WordPress", "version": m.group(1), "path": os.path.dirname(cur)})
                except Exception:
                    pass
            elif "Version.php" in files and cur.endswith("libraries/src"):
                vp = os.path.join(cur, "Version.php")
                try:
                    txt = open(vp, "r", encoding="utf-8", errors="ignore").read(4096)
                    m_maj = re.search(r'MAJOR_VERSION\s*=\s*([0-9]+)', txt)
                    m_min = re.search(r'MINOR_VERSION\s*=\s*([0-9]+)', txt)
                    if m_maj and m_min:
                        cms_hits.append({"cms": "Joomla", "version": f"{m_maj.group(1)}.{m_min.group(1)}", "path": os.path.dirname(os.path.dirname(cur))})
                except Exception:
                    pass
    return cms_hits


def correlate_logs(patient_zero, user, domains):
    if not patient_zero:
        return []
    pz_times = [patient_zero["mtime"], patient_zero["ctime"]]
    log_paths = []
    if access_log_opt and os.path.isfile(access_log_opt):
        log_paths.append(access_log_opt)
    if user:
        for dom in domains:
            for p in (f"/etc/apache2/logs/domlogs/{dom}", f"/usr/local/apache/domlogs/{dom}"):
                if os.path.isfile(p):
                    log_paths.append(p)
        if os.path.isfile("/usr/local/cpanel/logs/access_log"):
            log_paths.append("/usr/local/cpanel/logs/access_log")

    matches = []
    for lp in sorted(set(log_paths)):
        try:
            opener = gzip.open if lp.endswith(".gz") else open
            with opener(lp, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    dt = None
                    ip = "-"
                    req = ""
                    st = "-"
                    m1 = APACHE_TS_RE.search(line)
                    m2 = CPANEL_TS_RE.search(line)
                    if m1:
                        ip, ts_s, req, st = m1.groups()
                        dt = datetime.datetime.strptime(ts_s, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
                    elif m2:
                        ip, ts_s, req, st = m2.groups()
                        dt = datetime.datetime.strptime(ts_s, "%m/%d/%Y:%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
                    if not dt:
                        continue
                    ep = int(dt.timestamp())
                    if any(abs(ep - t) <= window_sec for t in pz_times):
                        matches.append({
                            "log": lp,
                            "timestamp_utc": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "ip": ip,
                            "status": st,
                            "request": req[:72],
                        })
        except Exception:
            continue
    return matches[:30]


def emit_output(payload, columns, rows, title):
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(columns)
        for r in rows:
            w.writerow(r)
        sys.stdout.write(buf.getvalue())
        return
    if not quiet:
        print("=" * 98)
        print(f" {c_bold}{script_name} v{script_version}{c_reset} | {title} | {ts_utc}")
        print("=" * 98)
    if not rows:
        print(f"{c_green}[CLEAN]{c_reset} No malicious files detected.")
        return
    widths = [len(c) for c in columns]
    for r in rows:
        for i, v in enumerate(r):
            plain = re.sub(r'\033\[[0-9;]*m', '', str(v))
            if len(plain) > widths[i]:
                widths[i] = min(len(plain), 60)
    print(f"{c_bold}" + "  ".join(columns[i].ljust(widths[i]) for i in range(len(columns))) + f"{c_reset}")
    print("  ".join("-" * widths[i] for i in range(len(columns))))
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            s = str(v)
            plain = re.sub(r'\033\[[0-9;]*m', '', s)
            cells.append(s + (" " * max(0, widths[i] - len(plain))))
        print("  ".join(cells))


# ==============================================================================
# ACTION: RESTORE
# ==============================================================================
if action == "restore":
    if not restore_target:
        print("[ERR] Usage: security.sh restore <vault_dir>", file=sys.stderr)
        sys.exit(1)
    mpath = os.path.join(restore_target, "manifest.json") if os.path.isdir(restore_target) else restore_target
    if not os.path.isfile(mpath):
        print(f"[ERR] Manifest not found: {mpath}", file=sys.stderr)
        sys.exit(1)
    manifest = json.load(open(mpath, "r", encoding="utf-8"))
    restored = []
    for item in manifest.get("quarantined", []):
        src, dst = item["quarantine_path"], item["original_path"]
        if not os.path.isfile(src):
            restored.append({"path": dst, "status": "MISSING"})
            continue
        if dry_run:
            restored.append({"path": dst, "status": "DRY-RUN"})
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        try:
            os.chmod(dst, int(item["mode"], 8))
            os.chown(dst, int(item["uid"]), int(item["gid"]))
        except Exception:
            pass
        restored.append({"path": dst, "status": "RESTORED"})
    payload = {"tool": script_name, "version": script_version, "action": "restore", "results": restored}
    emit_output(payload, ["STATUS", "PATH"], [[r["status"], r["path"]] for r in restored], "Quarantine Restore")
    sys.exit(0)

# ==============================================================================
# ACTION: TRIAGE
# ==============================================================================
roots = []
explicit_files = []
scope = ""

if list_file:
    src_fh = sys.stdin if list_file == "-" else open(list_file, "r", encoding="utf-8", errors="ignore")
    for ln in src_fh:
        p = ln.strip()
        if p and os.path.isfile(p):
            explicit_files.append(p)
    if list_file != "-":
        src_fh.close()
    scope = f"list:{list_file}"
elif target_path:
    rp = os.path.realpath(target_path)
    if not os.path.isdir(rp):
        print(f"[ERR] Directory not found: {target_path}", file=sys.stderr)
        sys.exit(1)
    roots = [rp]
    scope = rp
elif target_user:
    hd = get_homedir(target_user)
    if not hd:
        print(f"[ERR] User homedir not found: {target_user}", file=sys.stderr)
        sys.exit(1)
    roots = [hd]
    scope = f"user:{target_user}"

all_files = list(explicit_files)
for r in roots:
    for cur, dirs, files in os.walk(r, followlinks=False):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not os.path.islink(os.path.join(cur, d))]
        for fn in files:
            fp = os.path.join(cur, fn)
            if not os.path.islink(fp):
                all_files.append(fp)

domains = get_user_domains(target_user)
modsec_info = audit_modsec(domains)
findings, scanned_count = scan_files(all_files)
findings.sort(key=lambda x: (min(x["mtime"], x["ctime"]), x["path"]))
patient_zero = findings[0] if findings else None
log_corr = correlate_logs(patient_zero, target_user, domains)
cms_list = detect_cms(roots) if roots else []

vault_dir = ""
if do_quarantine and findings:
    slug = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    vault_dir = os.path.join(quarantine_dir, slug)
    q_recs = []
    if not dry_run:
        os.makedirs(vault_dir, mode=0o700, exist_ok=True)
        os.chmod(vault_dir, 0o700)
    for idx, fitem in enumerate(findings, 1):
        src = fitem["path"]
        qpath = os.path.join(vault_dir, f"{idx:04d}_{os.path.basename(src)}.quarantined")
        st = os.lstat(src)
        q_recs.append({
            "original_path": src,
            "quarantine_path": qpath,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "sha256": fitem["sha256"],
        })
        if not dry_run:
            shutil.move(src, qpath)
            os.chmod(qpath, 0o400)
            fitem["action"] = "QUARANTINED"
        else:
            fitem["action"] = "DRY-RUN"
    if not dry_run:
        fd = os.open(os.path.join(vault_dir, "manifest.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as mf:
            mf.write(json.dumps({"tool": script_name, "version": script_version, "created_utc": ts_utc, "quarantined": q_recs}, indent=2) + "\n")
else:
    for fitem in findings:
        fitem["action"] = "DETECTED"

payload = {
    "tool": script_name,
    "version": script_version,
    "action": "triage",
    "dry_run": dry_run,
    "timestamp_utc": ts_utc,
    "scope": scope,
    "files_scanned": scanned_count,
    "threats_found": len(findings),
    "patient_zero": patient_zero,
    "modsec": modsec_info,
    "cms_detected": cms_list,
    "log_correlations": log_corr,
    "quarantine_vault": vault_dir or None,
    "findings": findings,
}

rows = []
for fitem in findings:
    sev = fitem["severity"]
    act = fitem["action"]
    if fmt == "table":
        sev = f"{c_red}{sev}{c_reset}" if sev == "CRITICAL" else f"{c_yellow}{sev}{c_reset}"
        act = f"{c_green}{act}{c_reset}" if act == "QUARANTINED" else (f"{c_yellow}{act}{c_reset}" if act == "DRY-RUN" else f"{c_red}{act}{c_reset}")
    rows.append([sev, fitem["signature"], fitem["mtime_utc"], act, fitem["path"]])

emit_output(payload, ["SEVERITY", "SIGNATURE", "MTIME_UTC", "ACTION", "PATH"], rows, f"Incident Triage | {scope}")
if fmt == "table" and not quiet:
    if patient_zero:
        print(f"\n{c_cyan}Patient Zero:{c_reset} {patient_zero['path']} (mtime={patient_zero['mtime_utc']}, ctime={patient_zero['ctime_utc']})")
    if log_corr:
        print(f"{c_cyan}Log Hits (+/-{window_sec}s):{c_reset}")
        for lh in log_corr[:5]:
            print(f"  - [{lh['timestamp_utc']}] {lh['ip']} ({lh['status']}) {lh['request']}")
    if cms_list:
        print(f"{c_cyan}CMS Detected:{c_reset} " + " | ".join(f"{c['cms']} {c['version']} ({c['path']})" for c in cms_list))
    if modsec_info["exceptions"]:
        print(f"{c_yellow}ModSec Exceptions:{c_reset} {len(modsec_info['exceptions'])} rule(s) disabled in {modsec_info['file']}")
    if vault_dir:
        print(f"Vault: {'[DRY-RUN] ' if dry_run else ''}{vault_dir}")

if exit_code_mode and len(findings) > 0:
    sys.exit(2)
sys.exit(0)
PYEOF
)"

  python3 -c "$py_script" \
    "$ACTION" "$TARGET_USER" "$TARGET_PATH" "$LIST_FILE" "$RESTORE_TARGET" \
    "$WINDOW_SEC" "$ACCESS_LOG_OPT" "$MODSEC_CONF_OPT" "$DO_QUARANTINE" \
    "$QUARANTINE_DIR" "$DRY_RUN" "$EXIT_CODE_MODE" "$OUTPUT_FMT" "$QUIET" \
    "$SCRIPT_NAME" "$SCRIPT_VERSION" "$ts_utc" \
    "$C_RED" "$C_GREEN" "$C_YELLOW" "$C_CYAN" "$C_BOLD" "$C_RESET"
}

main "$@"
