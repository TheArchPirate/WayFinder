<p align="center"><img src="assets/wayfinder-banner.png" alt="Wayfinder — find the path, own the path"></p>

# Wayfinder

**Wayfinder** is a fully offline, zero-dependency analyzer for BloodHound collection data. It reads SharpHound v5/v6 and AzureHound exports and charts a course through an organization's identity attack surface — roasting targets, delegation abuse, DCSync rights, ADCS escalation paths, dangerous ACLs, hybrid/Entra ID seams, and shortest attack paths to high-value targets — without a single packet leaving your machine.

## Why offline?

BloodHound collections are some of the most sensitive artifacts on an engagement: a complete map of an organization's identity attack surface. Wayfinder is built for operators who can't (or won't) let that data touch a third party:

- **No network access** — the script makes zero outbound connections. Run it on an air-gapped box.
- **No dependencies** — Python 3.8+ standard library only. No `pip install`, no supply chain, nothing to break.
- **No BloodHound instance required** — no Neo4j, no Docker, no database. Point it at the collector's zip and read the results.

## Capabilities

**Credential & Kerberos attacks**
- Kerberoastable accounts (with password age and RC4/DES-only encryption flags that make tickets crack fast)
- AS-REP roastable accounts (`DONT_REQ_PREAUTH`)
- Reversible-encryption and DES-only accounts, locked-out accounts, krbtgt password age (golden-ticket validity window)

**Delegation & replication**
- Unconstrained, constrained, and protocol-transition (S4U2Self) delegation, RBCD edges
- DCSync rights (`GetChanges`, `GetChangesAll`, filtered) plus grant paths (`WriteDacl`/`GenericAll` on the domain object) — default holders (Domain Admins, BUILTIN\Administrators, DCs, Enterprise DCs/RODCs, built-in Administrator) are reported as INFO, not CRIT

**ADCS (Certified Pre-Owned)**
- ESC1–ESC11, ESC13, ESC15, ESC16 detection from collected CA/template/registry data
- Golden Cert composite paths (CA control × NTAuthStore control, including via the CA's host)
- NTAuthStore writers, ESC13 group-linked issuance policies, ESC10 weak DC certificate mapping, ESC8/ESC11 relay endpoints
- Honest coverage notes for what isn't collectible offline (ESC12, ESC14 surfaces as `WriteAltSecurityIdentities` ACLs)

**Identity hygiene & stealth**
- Tier-0 and moderately-privileged group membership (incl. DnsAdmins, Key Admins, RODC groups, Protected Users coverage gaps)
- Primary-group memberships invisible in member lists, enabled Guest, SID history, Entra Connect (`MSOL_*`) and Seamless SSO (`AZUREADSSOACC`) seams
- adminCount/AdminSDHolder drift, orphaned SIDs holding control, recently-created privileged objects
- Stale and pre-created computer accounts (default machine passwords), password policy + age histogram, credential hints in description fields, `MachineAccountQuota`

**Attack surface & paths**
- Dangerous non-inherited ACLs (SID-resolved, noise-filtered), cross-domain control edges, GPO control with link-target resolution
- NTLM relay surface: WebClient hosts, SMB signing off, NTLMv1 (`LmCompatibilityLevel`)
- Privileged-user sessions, non-standard local admins, LAPS coverage gaps and LAPS/gMSA password readers
- Trusts with SID-filtering assessment, outdated OS inventory
- **BFS shortest attack paths** from any principal you specify to any high-value target, plus default-population analysis (what *any* domain account can reach), ending in a numbered quick-wins list

**Hybrid / Entra ID (AzureHound)**
- Synced privileged identities cross-referenced on-prem ↔ cloud
- Privileged Entra roles (Global Admin etc.), especially when held by synced accounts
- Deep Azure RBAC (Owner/Contributor/UAA/VM/KeyVault assignments at any ARM scope), dangerous MS Graph app roles, Key Vault access policies with secret/key read

**Precision-first (no false positives by design)**
- Only explicitly collected values are flagged — an absent key never implies a misconfiguration
- Severity ratings calibrated against industry references (PingCastle health-check scoring, SpecterOps Certified Pre-Owned): CRIT = direct path to domain/tenant compromise, HIGH = one condition away, MED = enabler/situational, INFO = expected/hygiene
- Deny ACEs never produce control edges; deny ACEs and inherited noise are excluded at ingest
- Only well-known, vendor-published GUIDs/SIDs/RIDs are matched by identity; unknown custom roles are ignored, never guessed
- Composite attack chains require *all* conditions present; partial matches are reported at lower severity with "verify" notes
- Registry-derived findings require the registry collection to have succeeded
- Hardened against malformed input: corrupt zips, truncated JSON, and structurally invalid documents warn-and-skip rather than crash (fuzz-verified)

## Requirements

Python 3.8 or newer. Nothing else.

## Usage

```bash
# Analyze a SharpHound zip
python3 wayfinder.py --data 20240101120000_BloodHound.zip

# A directory of extracted JSONs, or a single JSON file
python3 wayfinder.py --data ./sharphound_jsons/
python3 wayfinder.py --data 20240101120000_users.json

# Multiple inputs at once (e.g. SharpHound zip + AzureHound zip)
python3 wayfinder.py --data sharphound.zip azurehound.zip

# Attack paths from a principal you own
python3 wayfinder.py --data bh.zip --user JSMITH@CORP.LOCAL

# Several owned principals from a file (one per line)
python3 wayfinder.py --data bh.zip --owned owned.txt

# Machine-readable output
python3 wayfinder.py --data bh.zip --json report.json

# Full HTML report — non-truncated findings + attack paths as SVG node/edge
# diagrams, with clickable severity summary tiles, a live search bar (filter by
# object name, SID, edge kind, or section) and severity filter chips
# (CRIT/HIGH/MED/INFO); self-contained (inline CSS/SVG/JS, no external
# resources), so it renders on an air-gapped machine
python3 wayfinder.py --data bh.zip --user JSMITH@CORP.LOCAL --html report.html
```

### Options

| Flag | Effect |
|---|---|
| `--data <path...>` | **Required.** SharpHound/AzureHound zip(s), a directory of JSONs, or single JSON file(s) |
| `--user <principal>` | Starting/owned principal for path analysis (name, SAM, or SID). Repeatable |
| `--owned <file>` | File with one owned principal per line (`#` comments allowed) |
| `--paths` | Always print the attack-path section |
| `--max-depth N` | Max BFS path length (default 8) |
| `--max-paths N` | Max paths returned (default 5) |
| `--limit N` | Max findings printed per section (default 15) |
| `--full` | No truncation |
| `--json <file>` | Write full findings as JSON |
| `--html <file>` | Write a full (non-truncated) HTML report with attack paths rendered as BloodHound-style SVG chain diagrams, clickable severity summary tiles, a live search bar (object name, SID, edge kind, section), severity filter chips (CRIT/HIGH/MED/INFO), and a domain-inventory sidebar (users/groups/computers/PKI, high-value split from standard) |
| `--no-color` | Disable ANSI colors (for piping/files) |
| `--include-inherited` | Include inherited ACEs (noisy — off by default) |

### Example output

```
[Wayfinder v1.11.0] loaded 7 collection file(s)
  Objects: 6 users, 2 groups, 4 computers, 1 domains | Edges: 17
  Entra ID: 2 object(s) across 2 file(s) — hybrid analysis enabled

== Domains & Trusts (2) ==
   [HIGH] CORP.LOCAL <-> FOREST.LOCAL
        CORP.LOCAL -> FOREST.LOCAL: Bidirectional, transitive=True — SID filtering DISABLED on inbound trust (SIDHistory abuse across forest)

== ADCS Abuse (ESC1-11, 13, 15, 16) (4) ==
   [CRIT] ESC1: CorpUser
        Enrollee supplies subject + client auth + no manager approval/signatures; enrollable by Domain Users.
   [CRIT] Golden Cert path viable
        PKIADMIN@CORP.LOCAL control(s) both a CA and the NTAuthStore — steal the CA private key and forge certificates

== Attack Paths to High-Value Targets ==
   From 1 start(s): 11 objects reachable within 8 traversable edges

   Path #1 — 2 hop(s) to WS01.CORP.LOCAL
        U1@CORP.LOCAL  --[ForceChangePassword]-->  U3@CORP.LOCAL
        U3@CORP.LOCAL  --[AdminTo]-->  WS01.CORP.LOCAL

== Quick Wins (numbered) ==
  [ 1] [CRIT] DCSync Rights: SVC-BACKUP@CORP.LOCAL
  [ 2] [CRIT] ADCS Abuse: ESC1: CorpUser
  ...
```

## Input formats

- **SharpHound v5/v6** (current collectors) — fully supported: users, groups, computers, domains, GPOs, OUs, containers, and the ADCS object types (cert templates, enterprise/root/AIA CAs, NTAuthStore, issuance policies)
- **SharpHound v4** — fully normalized: `ExtendedRight` ACEs resolved via AceType (`GetChanges`/`GetChangesAll`/…), `Owner` → `Owns` edges, `MemberId` membership, domain-prefixed BUILTIN SIDs (`DOMAIN.LOCAL-S-1-5-32-544`) recognized for expected-principal filtering
- **AzureHound v2** — users, groups, service principals, role assignments/definitions, ARM role assignments, app role assignments, key vaults

## Known limitations (by honesty, not by accident)

- **ESC12** (YubiHSM provider key exposure) is not collected by SharpHound — check the CA's CSP/KSP provider manually. The tool says so in its coverage notes rather than staying silent.
- Edges BloodHound CE *composes* at import time (e.g. `CoerceAndRelayNTLMToADCS`, `DCFor`) don't exist in raw collection JSON; Wayfinder analyzes their underlying primitives instead.
- Domain controller LDAP signing policy is not collected by SharpHound and therefore can't be assessed offline.

## License

MIT — see [LICENSE](LICENSE).
