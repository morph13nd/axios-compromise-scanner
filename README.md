# Axios compromise scanner

This repository contains a single Bash script that scans a workstation or a directory tree for common indicators associated with a malicious JavaScript supply chain event involving `axios` and the package `plain-crypto-js`.

It is designed to be practical for responders and developers. It checks lockfiles, `node_modules`, npm cache, global installs, a few known filesystem IOCs, and active network connections.

**For full incident context, detection playbook, and containment checklist, see the [CyberReplay axios npm compromise write-up](https://cyberreplay.com/blog/axies-compromised-on-npm-malicious-releases-remote-access-trojan/).**

## What it checks

The script looks for:

- Compromised `axios` versions in common JavaScript lockfiles and in `node_modules`
  - `axios@1.14.1`
  - `axios@0.30.4`
- The malicious package `plain-crypto-js`
- Stage 2 filesystem IOCs
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Linux: `/tmp/ld.py`
  - Windows (WSL, MSYS, Git Bash patterns): `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
- Active network connections to suspicious domains
  - `sfrclak.com`
  - `packages.npm.org` (including evidence of requests to `/product0`, `/product1`, `/product2`)
- Global packages installed via npm, yarn, pnpm, and bun
- npm cache artifacts in `~/.npm` (or the configured npm cache directory)
- Running processes that include known IOC strings
- Optional evidence of past requests to `packages.npm.org/product{0,1,2}`
  - DNS queries on macOS (mDNSResponder unified log)
  - Browser history matches (Chrome, Edge, Brave, Firefox, Safari) when `sqlite3` is available
  - Shell history references
  - Common proxy and web server log locations (best effort)

## Requirements

- Bash
- Standard Unix tools: `find`, `grep`, `awk`, `sed`, `ps`
- Optional but recommended:
  - `node` for accurate `package-lock.json` parsing and for reading installed package versions
  - `npm`, `yarn`, `pnpm`, `bun` if you want the global package checks for those managers
  - `sqlite3` for browser history checks
  - `ss` or `netstat` or `lsof` for active connection checks
  - `dig` for DNS resolution checks

On macOS, `sqlite3` and `dig` may not be present by default depending on system configuration.

## Usage

1. Make the script executable.

   `chmod +x shell.sh`

2. Run it with no arguments to scan your home directory.

   `./shell.sh`

3. Or pass a directory to scan a specific location (for example, a workspace or a drive mount).

   `./shell.sh /path/to/projects`

The script limits recursion depth when scanning for lockfiles and `node_modules` to avoid extremely deep traversals.

## Output and interpretation

- Green lines indicate a check completed without finding the indicator.
- Yellow lines are warnings. They often indicate possible historical artifacts, like npm cache references.
- Red lines indicate a positive match for an IOC or a compromised dependency.

If the script reports findings, treat them as a strong signal to investigate. In most environments you should also:

- Identify where the dependency was introduced and which builds consumed it
- Rotate credentials that may have been present on the machine or in CI at the time
- Review outbound network logs for the listed domains and any resolved IPs

## Notes about the exfil endpoint checks

The `packages.npm.org/product0`, `product1`, and `product2` strings are checked in a few different ways.

- Active connections are checked using `ss`, `netstat`, or `lsof` if available.
- Past activity checks are best effort and depend on what logs are available on the host.
- Browser history checks only detect explicit URL visits. They do not prove that a background library made an HTTP request.

A clean result here does not guarantee the host never contacted the endpoints.

## Limitations

- This is a detection script, not a remediation tool.
- It does not attempt memory forensics.
- It cannot reliably parse `bun.lockb` as text. The script attempts a best effort check if `bun` is available.
- Host log sources vary widely. Some checks may be skipped silently if tools or files are not present.

## Safety

This script is read-only. It does not delete anything. It runs local commands to inspect files and system state.

Still, it should be reviewed and tested in your environment before you run it at scale.

## License

If you need a license statement, add one that matches your intended distribution and usage.
Credit to https://github.com/luiyongsheng for the original script.
