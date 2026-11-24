[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# security

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/security/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requirements)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20Hosting-lightgrey.svg)](#requirements)

**Unified Hosting Incident Triage & Forensics Orchestrator CLI (`security.sh`).**

`security.sh` unifies 4 incident-response stages into one zero-dependency Bash + Python 3.6+ CLI: **(1) ModSecurity EA4 exception auditing**, **(2) symlink-safe webshell & encoded-payload detection with Patient-Zero `mtime`/`ctime` timeline**, **(3) temporal log correlation (`+/- --window` seconds) across Apache/cPanel logs**, and **(4) CMS version detection (WordPress, Joomla)** — with read-only triage by default and optional root-only `0700` quarantine + SHA-256 `restore`.

> **Historical Inspiration:** Clean-room Bash + Python 3.6+ `v2.0.0` reimplementation inspired by `security.pl` (2012, Michael Karr, HostGator.com, LLC). Eliminates dead external HTTP utility downloads (`git.hgfix.net`, `scripts.hostgator.com`), broken filehandle cleanup loops, root-unsafe writes inside `/home/$user/.security/`, obsolete EA3 ModSecurity paths, and shell command interpolation.

---

## Requirements

- Linux with Bash 4.0+ and Python 3.6+ (standard library only)

---

## Direct Execution

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/security/main/security.sh -o security.sh
chmod +x security.sh
sudo ./security.sh -p /var/www/html --exit-code
```

---

## Usage

```bash
# 1. Full read-only 4-stage incident triage for a cPanel/Linux user
sudo ./security.sh -u percio

# 2. Triage a webroot & correlate Patient-Zero timestamps with an Apache access_log
sudo ./security.sh -p /var/www/html --access-log /var/log/apache2/access.log --window 120

# 3. Quarantine detected threats into a 0700 root-only vault (or preview with --dry-run)
sudo ./security.sh -p /var/www/html --quarantine --dry-run
sudo ./security.sh -p /var/www/html --quarantine -o json

# 4. Restore quarantined files cleanly from manifest.json
sudo ./security.sh restore /var/quarantine/security/20261123-234200
```

---

## Real Output Example

```text
==================================================================================================
 security.sh v2.0.0 | Incident Triage | /tmp/security-e2e/webroot | 2026-11-24T03:43:15Z
==================================================================================================
SEVERITY  SIGNATURE                   MTIME_UTC            ACTION    PATH
--------  --------------------------  -------------------  --------  --------------------------------------------------
HIGH      PHP.Webshell.EvalEncoded    2026-11-22 14:10:00  DETECTED  /tmp/security-e2e/webroot/wp-content/shell.php
CRITICAL  PHP.Webshell.UserInputExec  2026-11-22 14:12:00  DETECTED  /tmp/security-e2e/webroot/cmd.php

Patient Zero: /tmp/security-e2e/webroot/wp-content/shell.php (mtime=2026-11-22 14:10:00, ctime=2026-11-22 14:10:00)
Log Hits (+/-120s):
  - [2026-11-22 14:09:50] 198.51.100.44 (200) POST /wp-admin/admin-ajax.php HTTP/1.1
CMS Detected: WordPress 6.6.2 (/tmp/security-e2e/webroot)
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
