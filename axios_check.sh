#!/usr/bin/env bash
# ============================================================================
# Axios Supply-Chain Compromise Scanner
# Author: morph13nd from cyberreplay.com
# Date: 2026-03-31
# Based on: https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7
#
# Scans for:
#   1. Compromised axios versions (1.14.1, 0.30.4) in lockfiles & node_modules
#   2. Malicious packages: plain-crypto-js
#   3. Platform-specific stage-2 payload IOCs (filesystem)
#   4. Active C2 connections to sfrclak.com / 142.11.206.73
#   5. Global npm/yarn/pnpm packages
#   6. npm cache contamination
#   7. Exfiltration to packages.npm.org/product{0,1,2}
#
# Usage:
#   chmod +x scan_axios_compromise.sh
#   ./scan_axios_compromise.sh                    # scan common paths
#   ./scan_axios_compromise.sh /path/to/projects  # scan specific directory
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

FOUND_ISSUES=0

banner() {
  echo ""
  echo -e "${BOLD}========================================${NC}"
  echo -e "${BOLD}  Axios Compromise Scanner (2026-03-31)${NC}"
  echo -e "${BOLD}========================================${NC}"
  echo ""
}

section() {
  echo ""
  echo -e "${CYAN}[*] $1${NC}"
  echo -e "${CYAN}$(printf '%.0s-' {1..50})${NC}"
}

found() {
  echo -e "${RED}[!!!] FOUND: $1${NC}"
  FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

warn() {
  echo -e "${YELLOW}[!] WARNING: $1${NC}"
}

safe() {
  echo -e "${GREEN}[✓] $1${NC}"
}

info() {
  echo -e "    $1"
}

# Determine scan root
SCAN_ROOT="${1:-$HOME}"
OS="$(uname -s)"

banner
echo "Platform detected: $OS"
echo "Scan root:         $SCAN_ROOT"
echo "Date:              $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ============================================================================
# 1. FILESYSTEM IOCs — Stage-2 Payloads
# ============================================================================
section "Checking for stage-2 payload IOCs on disk"

# macOS
if [[ "$OS" == "Darwin" ]]; then
  if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
    found "macOS stage-2 binary at /Library/Caches/com.apple.act.mond"
    ls -la "/Library/Caches/com.apple.act.mond" 2>/dev/null || true
  else
    safe "No macOS stage-2 binary found"
  fi

  # macOS RAT drops ad-hoc signed binaries to /private/tmp/.*
  RAT_TEMPS=$(find /private/tmp -maxdepth 1 -name ".*" -type f -perm +0111 2>/dev/null | head -10 || true)
  if [[ -n "$RAT_TEMPS" ]]; then
    warn "Hidden executable(s) in /private/tmp (consistent with RAT peinject command):"
    echo "$RAT_TEMPS" | sed 's/^/    /'
  fi

  # macOS RAT writes .scpt files to /tmp for osascript execution
  RAT_SCPT=$(find /tmp /private/tmp -maxdepth 1 -name ".*.scpt" 2>/dev/null | head -10 || true)
  if [[ -n "$RAT_SCPT" ]]; then
    found "Hidden .scpt file(s) in /tmp (RAT runscript artifact):"
    echo "$RAT_SCPT" | sed 's/^/    /'
  fi
fi

# Linux
if [[ "$OS" == "Linux" ]]; then
  if [[ -f "/tmp/ld.py" ]]; then
    found "Linux stage-2 payload at /tmp/ld.py"
    ls -la "/tmp/ld.py" 2>/dev/null || true
    echo "    First 5 lines:"
    head -5 "/tmp/ld.py" 2>/dev/null | sed 's/^/    /' || true
  else
    safe "No Linux stage-2 payload (/tmp/ld.py) found"
  fi
fi

# Windows (WSL / Git Bash / MSYS)
if [[ -d "/mnt/c" ]] || [[ "$OS" == "MINGW"* ]] || [[ "$OS" == "MSYS"* ]]; then
  PROGRAMDATA="${PROGRAMDATA:-/mnt/c/ProgramData}"
  TEMP_DIR="${TEMP:-${LOCALAPPDATA:-/mnt/c/Users/$USER/AppData/Local}/Temp}"

  for f in "$PROGRAMDATA/wt.exe" "$TEMP_DIR/6202033.vbs" "$TEMP_DIR/6202033.ps1"; do
    if [[ -f "$f" ]]; then
      found "Windows IOC found: $f"
    fi
  done
  safe "Windows IOC check complete"
fi

# All platforms — $TMPDIR/6202033 temp file
TMPDIR_CHECK="${TMPDIR:-/tmp}"
if [[ -f "${TMPDIR_CHECK}/6202033" ]] || [[ -f "/tmp/6202033" ]]; then
  found "Temp file 6202033 found (dropper artifact):"
  ls -la "${TMPDIR_CHECK}/6202033" "/tmp/6202033" 2>/dev/null | sed 's/^/    /' || true
else
  safe "No 6202033 temp file found"
fi

# ============================================================================
# 2. NETWORK — Active C2 Connections
# ============================================================================
section "Checking for active connections to C2 / exfiltration domains"

# Domains and IPs used by the compromise:
#   sfrclak.com           — stage-2 C2 callback
#   142.11.206.73         — C2 IP address
#   packages.npm.org      — data exfiltration via POST
#     POST /product0      — macOS payload
#     POST /product1      — Windows payload
#     POST /product2      — Linux payload
# Additional domains observed in Socket research: nrwise.com / callnrwise.com (check these too)
C2_DOMAINS=("sfrclak" "packages.npm.org" "142.11.206.73" "nrwise" "callnrwise")
C2_FOUND=0

check_net_tool() {
  local label="$1"; shift
  for domain in "${C2_DOMAINS[@]}"; do
    if "$@" 2>/dev/null | grep -qi "$domain"; then
      found "Active connection to $domain detected! ($label)"
      "$@" 2>/dev/null | grep -i "$domain" | sed 's/^/    /'
      C2_FOUND=1
    fi
  done
}

if command -v ss &>/dev/null; then
  check_net_tool "ss" ss -tunap
elif command -v netstat &>/dev/null; then
  check_net_tool "netstat" netstat -an
elif command -v lsof &>/dev/null; then
  check_net_tool "lsof" lsof -i -n
fi

if [[ $C2_FOUND -eq 0 ]]; then
  safe "No active C2 / exfiltration connections detected"
fi

# ---- Check for evidence of past requests to exfiltration endpoints ----
info ""
info "Checking for evidence of past requests to packages.npm.org/product{0,1,2}..."

EXFIL_URLS=("packages.npm.org/product0" "packages.npm.org/product1" "packages.npm.org/product2")
EXFIL_HIT=0

# Check DNS query logs (macOS unified log)
if [[ "$OS" == "Darwin" ]] && command -v log &>/dev/null; then
  DNS_HITS=$(log show --predicate 'process == "mDNSResponder" && composedMessage CONTAINS "packages.npm.org"' --style compact --last 7d 2>/dev/null | head -5 || true)
  if [[ -n "$DNS_HITS" ]]; then
    warn "macOS DNS log shows queries for packages.npm.org in last 7 days:"
    echo "$DNS_HITS" | sed 's/^/    /'
    EXFIL_HIT=1
  fi

  # Additional macOS unified log check for nrwise / callnrwise (added per Socket IOCs)
  NRWISE_HITS=$(log show --predicate 'composedMessage CONTAINS "nrwise" OR composedMessage CONTAINS "callnrwise"' --style compact --last 7d 2>/dev/null | head -5 || true)
  if [[ -n "$NRWISE_HITS" ]]; then
    warn "macOS DNS/log shows queries for nrwise/callnrwise in last 7 days:"
    echo "$NRWISE_HITS" | sed 's/^/    /'
    EXFIL_HIT=1
  fi
fi

# Check common browser history databases for visits (SQLite)
if command -v sqlite3 &>/dev/null; then
  # Chrome / Chromium-based
  CHROME_HISTORY_PATHS=()
  if [[ "$OS" == "Darwin" ]]; then
    CHROME_HISTORY_PATHS+=("$HOME/Library/Application Support/Google/Chrome/Default/History")
    CHROME_HISTORY_PATHS+=("$HOME/Library/Application Support/Microsoft Edge/Default/History")
    CHROME_HISTORY_PATHS+=("$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/History")
  elif [[ "$OS" == "Linux" ]]; then
    CHROME_HISTORY_PATHS+=("$HOME/.config/google-chrome/Default/History")
    CHROME_HISTORY_PATHS+=("$HOME/.config/microsoft-edge/Default/History")
    CHROME_HISTORY_PATHS+=("$HOME/.config/BraveSoftware/Brave-Browser/Default/History")
  fi

  for hpath in "${CHROME_HISTORY_PATHS[@]}"; do
    if [[ -f "$hpath" ]]; then
      for exfil_url in "${EXFIL_URLS[@]}"; do
        HITS=$(sqlite3 "file:${hpath}?mode=ro&immutable=1" \
          "SELECT url, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls WHERE url LIKE '%${exfil_url}%' LIMIT 5;" 2>/dev/null || true)
        if [[ -n "$HITS" ]]; then
          found "Browser history contains visit to $exfil_url ($(basename "$(dirname "$(dirname "$hpath")")"))"
          echo "$HITS" | sed 's/^/    /'
          EXFIL_HIT=1
        fi
      done
    fi
  done

  # Firefox
  FF_PROFILES=()
  if [[ "$OS" == "Darwin" ]]; then
    FF_PROFILES=("$HOME/Library/Application Support/Firefox/Profiles")
  elif [[ "$OS" == "Linux" ]]; then
    FF_PROFILES=("$HOME/.mozilla/firefox")
  fi

  for ff_dir in "${FF_PROFILES[@]}"; do
    if [[ -d "$ff_dir" ]]; then
      while IFS= read -r -d '' places_db; do
        for exfil_url in "${EXFIL_URLS[@]}"; do
          HITS=$(sqlite3 "file:${places_db}?mode=ro&immutable=1" \
            "SELECT url, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places WHERE url LIKE '%${exfil_url}%' LIMIT 5;" 2>/dev/null || true)
          if [[ -n "$HITS" ]]; then
            found "Firefox history contains visit to $exfil_url"
            echo "$HITS" | sed 's/^/    /'
            EXFIL_HIT=1
          fi
        done
      done < <(find "$ff_dir" -maxdepth 2 -name "places.sqlite" -print0 2>/dev/null || true)
    fi
  done

  # Safari (macOS only)
  if [[ "$OS" == "Darwin" ]]; then
    SAFARI_DB="$HOME/Library/Safari/History.db"
    if [[ -f "$SAFARI_DB" ]]; then
      for exfil_url in "${EXFIL_URLS[@]}"; do
        HITS=$(sqlite3 "file:${SAFARI_DB}?mode=ro&immutable=1" \
          "SELECT hi.url, datetime(hv.visit_time + 978307200,'unixepoch') FROM history_items hi JOIN history_visits hv ON hi.id = hv.history_item WHERE hi.url LIKE '%${exfil_url}%' LIMIT 5;" 2>/dev/null || true)
        if [[ -n "$HITS" ]]; then
          found "Safari history contains visit to $exfil_url"
          echo "$HITS" | sed 's/^/    /'
          EXFIL_HIT=1
        fi
      done
    fi
  fi
else
  info "(sqlite3 not available — skipping browser history check)"
fi

# Check shell history for curl/wget to the exfil endpoints
for histfile in "$HOME/.bash_history" "$HOME/.zsh_history"; do
  if [[ -f "$histfile" ]]; then
    for exfil_url in "${EXFIL_URLS[@]}"; do
      if grep -q "$exfil_url" "$histfile" 2>/dev/null; then
        warn "Shell history ($histfile) contains reference to $exfil_url"
        grep "$exfil_url" "$histfile" | tail -5 | sed 's/^/    /'
        EXFIL_HIT=1
      fi
    done
  fi
done

# Check system proxy / HTTP logs if accessible
for logdir in /var/log/squid /var/log/nginx /var/log/httpd /var/log/apache2; do
  if [[ -d "$logdir" ]]; then
    PROXY_HITS=$(grep -rl "packages.npm.org/product" "$logdir" 2>/dev/null | head -5 || true)
    if [[ -n "$PROXY_HITS" ]]; then
      warn "HTTP proxy/server logs reference packages.npm.org/product*:"
      echo "$PROXY_HITS" | sed 's/^/    /'
      EXFIL_HIT=1
    fi
  fi
done

if [[ $EXFIL_HIT -eq 0 ]]; then
  safe "No evidence of past requests to packages.npm.org/product{0,1,2}"
fi

# ============================================================================
# 3. GLOBAL NPM / YARN / PNPM PACKAGES
# ============================================================================
section "Checking globally installed npm packages"

check_global_package() {
  local pkg="$1"
  local manager="$2"
  local list_output="$3"

  if echo "$list_output" | grep -qF "$pkg"; then
    found "$pkg found in global $manager packages!"
    echo "$list_output" | grep -F "$pkg" | sed 's/^/    /'
  fi
}

# npm global
if command -v npm &>/dev/null; then
  info "Scanning npm global packages..."
  NPM_GLOBAL=$(npm list -g --depth=0 2>/dev/null || true)
  check_global_package "axios@1.14.1" "npm" "$NPM_GLOBAL"
  check_global_package "axios@0.30.4" "npm" "$NPM_GLOBAL"
  check_global_package "plain-crypto-js" "npm" "$NPM_GLOBAL"
  # Also look for related malicious packages observed in research
  check_global_package "@shadanai/openclaw" "npm" "$NPM_GLOBAL"
  check_global_package "@qqbrowser/openclaw-qbot" "npm" "$NPM_GLOBAL"

  # Also check all global with deep dependencies
  NPM_GLOBAL_DEEP=$(npm list -g --all 2>/dev/null || true)
  if echo "$NPM_GLOBAL_DEEP" | grep -q "plain-crypto-js"; then
    found "plain-crypto-js found as a transitive global npm dependency!"
    echo "$NPM_GLOBAL_DEEP" | grep "plain-crypto-js" | sed 's/^/    /'
  fi

  # Check npm global root for the actual files
  NPM_GLOBAL_ROOT=$(npm root -g 2>/dev/null || true)
  if [[ -n "$NPM_GLOBAL_ROOT" ]]; then
    if [[ -d "$NPM_GLOBAL_ROOT/plain-crypto-js" ]]; then
      found "plain-crypto-js directory exists at $NPM_GLOBAL_ROOT/plain-crypto-js"
    fi
    if [[ -d "$NPM_GLOBAL_ROOT/axios" ]]; then
      GLOBAL_AXIOS_VER=$(node -e "console.log(require(process.argv[1]).version)" "$NPM_GLOBAL_ROOT/axios/package.json" 2>/dev/null || echo "unknown")
      if [[ "$GLOBAL_AXIOS_VER" == "1.14.1" || "$GLOBAL_AXIOS_VER" == "0.30.4" ]]; then
        found "Compromised global axios version: $GLOBAL_AXIOS_VER"
      else
        safe "Global axios version $GLOBAL_AXIOS_VER (not compromised)"
      fi
    fi
  fi
else
  warn "npm not found, skipping npm global scan"
fi

# yarn global
if command -v yarn &>/dev/null; then
  info "Scanning yarn global packages..."
  YARN_GLOBAL=$(yarn global list 2>/dev/null || true)
  check_global_package "axios@1.14.1" "yarn" "$YARN_GLOBAL"
  check_global_package "axios@0.30.4" "yarn" "$YARN_GLOBAL"
  check_global_package "plain-crypto-js" "yarn" "$YARN_GLOBAL"
  check_global_package "@shadanai/openclaw" "yarn" "$YARN_GLOBAL"
  check_global_package "@qqbrowser/openclaw-qbot" "yarn" "$YARN_GLOBAL"
fi

# pnpm global
if command -v pnpm &>/dev/null; then
  info "Scanning pnpm global packages..."
  PNPM_GLOBAL=$(pnpm list -g 2>/dev/null || true)
  check_global_package "axios@1.14.1" "pnpm" "$PNPM_GLOBAL"
  check_global_package "axios@0.30.4" "pnpm" "$PNPM_GLOBAL"
  check_global_package "plain-crypto-js" "pnpm" "$PNPM_GLOBAL"
  check_global_package "@shadanai/openclaw" "pnpm" "$PNPM_GLOBAL"
  check_global_package "@qqbrowser/openclaw-qbot" "pnpm" "$PNPM_GLOBAL"
fi

# bun global
if command -v bun &>/dev/null; then
  info "Scanning bun global packages..."
  BUN_GLOBAL_ROOT="$HOME/.bun/install/global/node_modules"
  if [[ -d "$BUN_GLOBAL_ROOT/plain-crypto-js" ]]; then
    found "plain-crypto-js found in bun global packages!"
  fi
  if [[ -d "$BUN_GLOBAL_ROOT/axios" ]]; then
    BUN_AXIOS_VER=$(node -e "console.log(require(process.argv[1]).version)" "$BUN_GLOBAL_ROOT/axios/package.json" 2>/dev/null || echo "unknown")
    if [[ "$BUN_AXIOS_VER" == "1.14.1" || "$BUN_AXIOS_VER" == "0.30.4" ]]; then
      found "Compromised bun global axios version: $BUN_AXIOS_VER"
    fi
  fi
fi

# ============================================================================
# 4. NPM CACHE
# ============================================================================
section "Checking npm cache for compromised packages"

if command -v npm &>/dev/null; then
  NPM_CACHE_DIR=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")

  # Check _cacache for plain-crypto-js entries
  if [[ -d "$NPM_CACHE_DIR/_cacache" ]]; then
    CACHE_HITS=$(find "$NPM_CACHE_DIR/_cacache" -name "*.json" -exec grep -l "plain-crypto-js" {} \; 2>/dev/null | head -20 || true)
    if [[ -n "$CACHE_HITS" ]]; then
      warn "plain-crypto-js found in npm cache (may indicate past install):"
      echo "$CACHE_HITS" | sed 's/^/    /'
      info "Run: npm cache clean --force"
    else
      safe "npm cache clean of plain-crypto-js"
    fi

    CACHE_AXIOS=$(find "$NPM_CACHE_DIR/_cacache" -name "*.json" -exec grep -El '"axios","version":"1\.14\.1"|"axios","version":"0\.30\.4"' {} \; 2>/dev/null | head -20 || true)
    if [[ -n "$CACHE_AXIOS" ]]; then
      warn "Compromised axios version found in npm cache:"
      echo "$CACHE_AXIOS" | sed 's/^/    /'
    fi
  fi
fi

# ============================================================================
# 5. PROJECT LOCKFILES — Comprehensive Scan
# ============================================================================
section "Scanning lockfiles under $SCAN_ROOT (this may take a moment...)"

LOCKFILE_COUNT=0

package_lock_has_axios_version() {
  local lockfile="$1"
  local bad_version="$2"

  command -v node &>/dev/null || return 1

  node - "$lockfile" "$bad_version" >/dev/null 2>&1 <<'NODE'
const fs = require('fs');

const [lockfile, badVersion] = process.argv.slice(2);
let data;

try {
  data = JSON.parse(fs.readFileSync(lockfile, 'utf8'));
} catch (error) {
  process.exit(1);
}

function hasBadDependencyTree(deps) {
  if (!deps || typeof deps !== 'object') {
    return false;
  }

  for (const [name, meta] of Object.entries(deps)) {
    if (name === 'axios' && meta && typeof meta === 'object' && meta.version === badVersion) {
      return true;
    }
    if (meta && hasBadDependencyTree(meta.dependencies)) {
      return true;
    }
  }

  return false;
}

if (data.packages && typeof data.packages === 'object') {
  for (const [pkgPath, meta] of Object.entries(data.packages)) {
    if (/(^|\/)node_modules\/axios$/.test(pkgPath) && meta && meta.version === badVersion) {
      process.exit(0);
    }
  }
}

if (hasBadDependencyTree(data.dependencies)) {
  process.exit(0);
}

process.exit(1);
NODE
}

yarn_lock_has_axios_version() {
  local lockfile="$1"
  local bad_version="$2"

  awk -v bad_version="$bad_version" '
    BEGIN {
      in_axios = 0;
      found = 0;
    }
    /^[^[:space:]].*:[[:space:]]*$/ {
      in_axios = ($0 ~ /(^|, )[\"\047]?axios@/);
      next;
    }
    in_axios && /^[[:space:]]+version([[:space:]]|:)/ {
      line = $0;
      sub(/^[[:space:]]+version[[:space:]]*:?[[:space:]]*"?/, "", line);
      sub(/"?[[:space:]]*$/, "", line);
      if (line == bad_version) {
        found = 1;
        exit;
      }
    }
    END {
      exit(found ? 0 : 1);
    }
  ' "$lockfile" >/dev/null 2>&1
}

pnpm_lock_has_axios_version() {
  local lockfile="$1"
  local bad_version="$2"
  local bad_regex="${bad_version//./\\.}"

  grep -qE "^[[:space:]]*['\"]?(/axios/${bad_regex}|axios@${bad_regex}(\\([^'\"]+\\))?)['\"]?:" "$lockfile" 2>/dev/null
}

lockfile_has_axios_version() {
  local lockfile="$1"
  local bad_version="$2"

  case "$(basename "$lockfile")" in
    package-lock.json)
      package_lock_has_axios_version "$lockfile" "$bad_version"
      ;;
    yarn.lock)
      yarn_lock_has_axios_version "$lockfile" "$bad_version"
      ;;
    pnpm-lock.yaml)
      pnpm_lock_has_axios_version "$lockfile" "$bad_version"
      ;;
    *)
      return 1
      ;;
  esac
}

scan_lockfile() {
  local lockfile="$1"
  local project_dir
  project_dir=$(dirname "$lockfile")
  local hit=0

  # Check for compromised axios versions
  if lockfile_has_axios_version "$lockfile" "1.14.1"; then
    found "axios@1.14.1 in $lockfile"
    hit=1
  fi
  if lockfile_has_axios_version "$lockfile" "0.30.4"; then
    found "axios@0.30.4 in $lockfile"
    hit=1
  fi

  # Check for plain-crypto-js (should NEVER appear in any legit project)
  if grep -q "plain-crypto-js" "$lockfile" 2>/dev/null; then
    found "plain-crypto-js in $lockfile — THIS PACKAGE IS MALICIOUS"
    hit=1
  fi
  # Check specifically for malicious plain-crypto-js versions (4.2.1 and 4.2.0)
  if grep -E "plain-crypto-js[^[:alnum:]\n]*4\\.2\\.1|plain-crypto-js[^[:alnum:]\n]*4\\.2\\.0" "$lockfile" 2>/dev/null; then
    found "plain-crypto-js@4.2.x referenced in $lockfile — MALICIOUS VERSION"
    hit=1
  fi
  
  # Check for vendor/packaged references observed in research
  if grep -q "@shadanai/openclaw" "$lockfile" 2>/dev/null || grep -q "openclaw-qbot" "$lockfile" 2>/dev/null; then
    found "Potentially malicious package reference in $lockfile (@shadanai/openclaw or openclaw-qbot)"
    hit=1
  fi

  if [[ $hit -eq 0 ]]; then
    LOCKFILE_COUNT=$((LOCKFILE_COUNT + 1))
  fi
}

# Find all lockfiles (limit depth to avoid extremely deep traversals)
while IFS= read -r -d '' lockfile; do
  scan_lockfile "$lockfile"
done < <(find "$SCAN_ROOT" \
  -maxdepth 8 \
  -name "node_modules" -prune -o \
  -name ".git" -prune -o \
  \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
  -print0 2>/dev/null || true)

# For bun.lockb (binary format), try bun to inspect
if command -v bun &>/dev/null; then
  while IFS= read -r -d '' bunlock; do
    BUN_TEXT=$(cd "$(dirname "$bunlock")" && bun bun.lockb 2>/dev/null || true)
    if echo "$BUN_TEXT" | grep -q "plain-crypto-js"; then
      found "plain-crypto-js in $bunlock"
    fi
    if echo "$BUN_TEXT" | grep -qE "axios@1\.14\.1|axios@0\.30\.4"; then
      found "Compromised axios version in $bunlock"
    fi
  done < <(find "$SCAN_ROOT" -maxdepth 8 -name "bun.lockb" -print0 2>/dev/null || true)
fi

safe "$LOCKFILE_COUNT lockfiles scanned clean"

# ============================================================================
# 6. NODE_MODULES — Direct Inspection
# ============================================================================
section "Scanning node_modules directories for compromised packages"

NM_SCANNED=0

while IFS= read -r -d '' nm_dir; do
  NM_SCANNED=$((NM_SCANNED + 1))

  # Check for plain-crypto-js (should never exist)
  if [[ -d "$nm_dir/plain-crypto-js" ]]; then
    found "plain-crypto-js installed at $nm_dir/plain-crypto-js"

    # Check if setup.js still exists (it self-deletes, but worth checking)
    if [[ -f "$nm_dir/plain-crypto-js/setup.js" ]]; then
      found "setup.js payload STILL PRESENT at $nm_dir/plain-crypto-js/setup.js"
    fi

    # Check if package.json was swapped (anti-forensics check)
    if [[ -f "$nm_dir/plain-crypto-js/package.json" ]]; then
      if grep -q "postinstall" "$nm_dir/plain-crypto-js/package.json" 2>/dev/null; then
        found "package.json still contains postinstall hook (payload not yet cleaned up)"
      else
        warn "package.json has NO postinstall — likely swapped by anti-forensics (package.md → package.json)"
        warn "This means the payload ALREADY EXECUTED on this system"
      fi
    fi
  fi

  # Check axios version
  if [[ -f "$nm_dir/axios/package.json" ]]; then
    AXIOS_VER=$(node -e "try{console.log(require(process.argv[1]).version)}catch(e){console.log('parse-error')}" "$nm_dir/axios/package.json" 2>/dev/null || true)
    if [[ "$AXIOS_VER" == "1.14.1" || "$AXIOS_VER" == "0.30.4" ]]; then
      found "Compromised axios@$AXIOS_VER at $nm_dir/axios/"

      # Check if it has plain-crypto-js as dependency
      if node -e "const p=require(process.argv[1]);process.exit(p.dependencies&&p.dependencies['plain-crypto-js']?0:1)" "$nm_dir/axios/package.json" 2>/dev/null; then
        found "This axios has plain-crypto-js as a dependency — CONFIRMED COMPROMISED"
      fi
    fi
  fi
done < <(find "$SCAN_ROOT" -maxdepth 7 -type d -name "node_modules" -print0 2>/dev/null || true)

safe "$NM_SCANNED node_modules directories scanned"

# ============================================================================
# 7. RUNNING PROCESSES — Check for suspicious payloads
# ============================================================================
section "Checking running processes for known payload indicators"

PROC_HIT=0

if command -v ps &>/dev/null; then
  PS_OUTPUT=$(ps aux 2>/dev/null || true)

  for pattern in "com.apple.act.mond" "ld.py" "6202033" "sfrclak" "packages.npm.org" "wt.exe.*hidden" "nrwise" "callnrwise" "jasonsaayman"; do
    if echo "$PS_OUTPUT" | grep -v "grep" | grep -qi "$pattern"; then
      found "Suspicious process matching '$pattern':"
      echo "$PS_OUTPUT" | grep -i "$pattern" | grep -v "grep" | sed 's/^/    /'
      PROC_HIT=1
    fi
  done
fi

if [[ $PROC_HIT -eq 0 ]]; then
  safe "No suspicious processes detected"
fi

# ============================================================================
# 8. SHELL HISTORY — Check if npm install ran recently (informational)
# ============================================================================
section "Checking shell history for recent npm installs (informational)"

for histfile in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"; do
  if [[ -f "$histfile" ]]; then
    RECENT_INSTALLS=$(grep -i "npm install\|npm i \|yarn add\|pnpm add\|bun add\|bun install" "$histfile" 2>/dev/null | tail -20 || true)
    if [[ -n "$RECENT_INSTALLS" ]]; then
      info "Recent install commands from $(basename "$histfile"):"
      echo "$RECENT_INSTALLS" | tail -10 | sed 's/^/    /'
    fi
  fi
done

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  SCAN COMPLETE${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

if [[ $FOUND_ISSUES -gt 0 ]]; then
  echo -e "${RED}${BOLD}⚠️  $FOUND_ISSUES ISSUE(S) FOUND — YOUR SYSTEM MAY BE COMPROMISED${NC}"
  echo ""
  echo -e "${YELLOW}Immediate actions:${NC}"
  echo "  1. Disconnect from the network if stage-2 IOCs were found"
  echo "  2. Remove compromised packages: npm uninstall axios && npm install axios@1.14.0"
  echo "  3. Delete plain-crypto-js from all node_modules"
  echo "  4. Remove related malicious packages if present: npm uninstall @shadanai/openclaw @qqbrowser/openclaw-qbot"
  echo "  4. Remove stage-2 payloads:"
  echo "     • macOS: sudo rm -f /Library/Caches/com.apple.act.mond"
  echo "     • Linux: rm -f /tmp/ld.py"
  echo "     • Windows: del %PROGRAMDATA%\\wt.exe, %TEMP%\\6202033.*"
  echo "  5. Clean npm cache: npm cache clean --force"
  echo "  6. ROTATE ALL CREDENTIALS — tokens, API keys, SSH keys, passwords"
  echo "  7. Block sfrclak.com at your DNS/firewall"
  echo "  8. Check CI/CD pipelines for the same compromise"
  echo ""
else
  echo -e "${GREEN}${BOLD}✅ No indicators of compromise found.${NC}"
  echo ""
  echo "Preventive recommendations:"
  echo "  • Pin axios to 1.14.0 in your lockfiles"
  echo "  • Run: npm audit"
  echo "  • Consider enabling npm's --ignore-scripts for untrusted installs"
  echo "  • Block sfrclak.com at your DNS/firewall as a precaution"
fi

echo ""
echo "Scanner finished at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
