#!/usr/bin/env python3
"""
Wayfinder — fully offline BloodHound/SharpHound collection analyzer.

Parses a SharpHound zip export (or a directory of the JSONs inside it) and
surfaces everything useful for an offensive engagement: roasting targets,
delegation, DCSync rights, dangerous ACLs, sessions of privileged users,
LAPS, trusts, password hygiene, and shortest attack paths to high-value
targets from a given principal.

No network access, no third-party dependencies — Python 3.8+ stdlib only.
Sensitive collection data never leaves the local machine.

Usage:
  python3 wayfinder.py --data 20240101120000_BloodHound.zip
  python3 wayfinder.py --data ./sharphound_jsons/ --user JSMITH@CORP.LOCAL
  python3 wayfinder.py --data bh.zip --owned owned.txt --json report.json
  python3 wayfinder.py --data bh.zip --full --no-color

Input formats: SharpHound v5/v6 JSON (users/groups/computers/domains/gpos/ous/
containers). Best-effort normalization for v4-style TitleCase property names.

FALSE-POSITIVE DISCIPLINE (applies to every check):
  - Only flag explicitly collected values; absent/unset keys never imply a
    misconfiguration (e.g. LmCompatibilityLevel only flags when present).
  - Only well-known, vendor-published GUIDs/SIDs/RIDs are matched by identity;
    unknown custom roles/objects are ignored, never guessed.
  - Composite attack chains (ESC1, Golden Cert, ESC9) require ALL conditions
    present; partial matches are reported at lower severity with "verify"
    notes instead of being claimed.
  - Registry-derived findings require the registry collection to have
    succeeded and the value to be present.
"""
import argparse
import datetime
import json
import re
import sys
import zipfile
from collections import defaultdict, deque
from pathlib import Path

VERSION = "1.5.4"

# --------------------------------------------------------------------------
# Well-known principals / noise reduction
# --------------------------------------------------------------------------
NOISE_SIDS = {
    "S-1-5-18",        # SYSTEM
    "S-1-5-32-544",    # BUILTIN Administrators
    "S-1-5-32-548",    # Account Operators
    "S-1-5-32-549",    # Server Operators
    "S-1-5-32-550",    # Print Operators
    "S-1-5-32-551",    # Backup Operators
}
NOISE_RID_SUFFIXES = ("-512", "-519", "-518")  # DA / EA / Schema Admins

TIER0_RIDS = {
    "-512": "Domain Admins",
    "-519": "Enterprise Admins",
    "-518": "Schema Admins",
}

# ACE rights that confer control over the target object
DANGEROUS_RIGHTS = {
    "GenericAll": "CRIT", "WriteDacl": "HIGH", "WriteOwner": "HIGH",
    "Owns": "HIGH", "ForceChangePassword": "HIGH", "AddMember": "HIGH",
    "AddSelf": "HIGH", "WriteSPN": "MED", "AddKeyCredentialLink": "HIGH",
    "GenericWrite": "MED", "WriteAccountRestrictions": "HIGH",
    "AllExtendedRights": "HIGH", "AddAllowedToAct": "HIGH",
    "WriteGPLink": "HIGH", "WriteAltSecurityIdentities": "HIGH",
    "WritePKINameFlag": "HIGH", "WritePKIEnrollmentFlag": "HIGH",
    "WritePublicInformation": "MED",
    "ManageCA": "CRIT", "ManageCertificates": "HIGH",
}
DCSYNC_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
LAPS_RIGHTS = {"ReadLAPSPassword", "SyncLAPSPassword"}
GMSA_RIGHTS = {"ReadGMSAPassword", "DumpSMSAPassword"}

# Edges the pathfinder is willing to traverse (abuse confers control)
TRAVERSABLE = {
    "MemberOf", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "SQLAdmin",
    "AllowedToDelegate", "AllowedToAct", "HasSIDHistory",
    *DANGEROUS_RIGHTS.keys(), *DCSYNC_RIGHTS, *LAPS_RIGHTS, *GMSA_RIGHTS,
}

# Moderately-privileged built-in/created groups worth enumerating for members
MODERATE_GROUP_RIDS = {
    "-548": ("Account Operators", "can create/modify users & non-admin groups — privesc via account manipulation"),
    "-549": ("Server Operators", "can log on interactively to DCs and stop/start services"),
    "-550": ("Print Operators", "can load printer drivers on DCs (DLL privesc)"),
    "-551": ("Backup Operators", "can backup DC SAM/SYSTEM/NTDS — credential theft"),
    "-554": ("Pre-Windows 2000 Compatible Access", "members get broad anonymous read of users/groups"),
    "-571": ("Allowed RODC Password Replication Group", "members' credentials are cached on RODCs — an RODC compromise yields these creds"),
    "-572": ("Denied RODC Password Replication Group", "protective group — members' creds never cached on RODCs"),
}
MODERATE_GROUP_NAMES = {
    "DNSADMINS": "can load arbitrary DLLs into the DNS service on DCs",
    "KEY ADMINS": "can perform shadow-credential attacks on most objects",
    "ENTERPRISE KEY ADMINS": "can perform shadow-credential attacks forest-wide incl. DCs",
    "HYPER-V ADMINISTRATORS": "local admin on Hyper-V hosts; often path to DCs running as VMs",
    "REMOTE MANAGEMENT USERS": "WinRM access",
    "REMOTE DESKTOP USERS": "RDP access",
}

# Principals considered low-privilege for ADCS enrollment checks
LOW_PRIV_SIDS = {"S-1-1-0", "S-1-5-11"}
LOW_PRIV_SUFFIXES = ("-513", "-515")
LOW_PRIV_NAMES = {"EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "DOMAIN COMPUTERS"}

CLIENT_AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "2.5.29.37.0"}  # client auth / any purpose
CERT_REQUEST_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"

# doc kind -> node kind for ADCS object types
ADCS_KINDS = {
    "certtemplates": "CERTTEMPLATE", "enterprisecas": "ENTERPRISECA",
    "rootcas": "ROOTCA", "ntauthstores": "NTAUTHSTORE",
    "aiacas": "AIACA", "issuancepolicies": "ISSUANCEPOLICY",
}

# Well-known privileged Entra role template IDs
PRIV_ENTRA_ROLES = {
    "62E90394-69F5-4237-9190-012177145E10": ("Global Administrator", "CRIT"),
    "E8611AB8-C189-46E8-94E1-60213AB1F814": ("Privileged Role Administrator", "CRIT"),
    "9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3": ("Application Administrator", "HIGH"),
    "158C047A-C907-4556-B7EF-446551A6B5F7": ("Cloud Application Administrator", "HIGH"),
    "194AE4CB-B126-40B2-BD5B-6091B380977D": ("Security Administrator", "HIGH"),
    "B0F54661-2D74-4C50-AFA3-1EC803F12EFE": ("Authentication Administrator", "HIGH"),
}

# Well-known Azure ARM built-in role definition GUIDs (stable, published by MS)
ARM_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": ("Owner", "CRIT"),
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": ("User Access Administrator", "CRIT"),
    "b24988ac-6180-42a0-ab88-20f7382dd24c": ("Contributor", "HIGH"),
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": ("Virtual Machine Contributor", "HIGH"),
    "1c0163c0-47e6-4577-8991-ea5c82e286e4": ("Virtual Machine Administrator Login", "HIGH"),
    "f25e0fa2-a7c8-44fc-8575-1f39a066f23f": ("Key Vault Contributor", "HIGH"),
    "de139f84-1756-47ae-9be2-907fb6bc28f1": ("Website Contributor", "MED"),
    "87a39d53-fc1b-424a-814c-f7e04687dc9e": ("Logic App Contributor", "MED"),
    "f353d9bd-d4a6-484e-a77a-8050b599b867": ("Automation Account Contributor", "MED"),
    "e40ec5ca-96e0-45a2-b4ff-59039f2c2b59": ("Managed Identity Contributor", "MED"),
}

# Dangerous MS Graph application-role IDs (tenant-wide impact when app-assigned)
GRAPH_APP_ROLES = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": ("RoleManagement.ReadWrite.Directory", "CRIT"),
    "06b708a9-e830-4db3-a914-8e69da51d44f": ("AppRoleAssignment.ReadWrite.All", "CRIT"),
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": ("Directory.ReadWrite.All", "HIGH"),
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": ("Application.ReadWrite.All", "HIGH"),
}
MS_GRAPH_SP_ID = "00000003-0000-0000-c000-000000000000"

# Password/credential hints in description fields
DESC_HINT = re.compile(
    r"(pass(wor)?d|pwd|cred|p@ss|login|logon|secret|apikey|api[_-]?key|token)",
    re.IGNORECASE,
)

SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}


# --------------------------------------------------------------------------
# Console colors
# --------------------------------------------------------------------------
class C:
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
    CYAN = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

def sev_color(sev):
    return {"CRIT": C.RED, "HIGH": C.RED, "MED": C.YELLOW,
            "INFO": C.DIM}.get(sev, "")

USE_COLOR = True
def tag(sev):
    if not USE_COLOR:
        return f"[{sev}]"
    return f"{sev_color(sev)}[{sev}]{C.RESET}"


# --------------------------------------------------------------------------
# Loading & normalization
# --------------------------------------------------------------------------
def _as_dict(v):
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, list) else []


def _as_str(v):
    return v if isinstance(v, str) else ""


def load_documents(paths):
    """Yield (source_name, parsed_json) from zips, dirs or bare json files."""
    docs = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.glob("*.json")):
                try:
                    docs.append((f.name, json.loads(f.read_text(errors="replace"))))
                except json.JSONDecodeError as e:
                    print(f"[!] skipping {f.name}: {e}", file=sys.stderr)
        elif p.suffix.lower() == ".zip":
            try:
                zf = zipfile.ZipFile(p)
            except (zipfile.BadZipFile, OSError) as e:
                print(f"[!] skipping {p.name}: not a readable zip ({e})", file=sys.stderr)
                continue
            with zf as z:
                for name in sorted(z.namelist()):
                    if name.lower().endswith(".json"):
                        try:
                            docs.append((name, json.loads(z.read(name))))
                        except json.JSONDecodeError as e:
                            print(f"[!] skipping {name} in {p.name}: {e}", file=sys.stderr)
        elif p.is_file():
            try:
                docs.append((p.name, json.loads(p.read_text(errors="replace"))))
            except json.JSONDecodeError as e:
                print(f"[!] skipping {p.name}: {e}", file=sys.stderr)
        else:
            print(f"[!] path not found: {p}", file=sys.stderr)
    # collection documents are always JSON objects; anything else is junk
    out = []
    for n, d in docs:
        if isinstance(d, dict):
            out.append((n, d))
        else:
            print(f"[!] skipping {n}: top-level JSON is not an object", file=sys.stderr)
    return out


def doc_kind(doc, fallback=""):
    if not isinstance(doc, dict):
        return fallback.rsplit("_", 1)[-1].replace(".json", "").lower()
    meta = _as_dict(doc.get("meta") or doc.get("Meta"))
    t = meta.get("type") or meta.get("Type") or ""
    if not isinstance(t, str):
        t = ""
    t = t.lower()
    if t:
        return t
    for k in ("users", "groups", "computers", "domains", "gpos", "ous",
              "containers", "certtemplates", "enterprisecas", "rootcas",
              "ntauthstores", "aiacas", "issuancepolicies",
              "azusers", "azgroups"):
        if k in doc or k.capitalize() in doc:
            return k
    return fallback.rsplit("_", 1)[-1].replace(".json", "").lower()


def doc_objects(doc):
    if not isinstance(doc, dict):
        return []
    data = doc.get("data") or doc.get("Data")
    if isinstance(data, list):
        return data
    for k in ("Users", "Groups", "Computers", "Domains", "Gpos", "Ous",
              "Containers", "users", "groups", "computers", "domains"):
        if isinstance(doc.get(k), list):
            return doc[k]
    return []


def props(obj):
    raw = _as_dict(obj.get("Properties") or obj.get("properties"))
    if not raw:
        return {}
    # v5 keys are already lowercase; v4 TitleCase -> normalize to lowercase
    return {k.lower(): v for k, v in raw.items() if isinstance(k, str)}


def obj_sid(obj):
    return _as_str(obj.get("ObjectIdentifier") or obj.get("ObjectSid")).upper()


def obj_kind_guess(obj, doc_kind_name):
    if doc_kind_name in ("users", "groups", "computers", "domains", "gpos",
                         "ous", "containers"):
        return doc_kind_name.rstrip("s").upper()
    if doc_kind_name in ADCS_KINDS:
        return ADCS_KINDS[doc_kind_name]
    if doc_kind_name == "sites":
        return "SITE"
    return "UNKNOWN"


# --------------------------------------------------------------------------
# Graph model
# --------------------------------------------------------------------------
class Graph:
    def __init__(self):
        self.nodes = {}          # sid -> dict(name, kind, domain, props, doc_kinds)
        self.edges = []          # (src_sid, dst_sid, kind, inherited)
        self.name_to_sid = {}    # UPPER name -> sid
        self.sam_to_sid = {}     # UPPER samaccountname -> sid
        self.dns_to_sid = {}     # UPPER dns host -> sid
        self.groups_members = defaultdict(list)   # group sid -> member sids
        self.computer_sessions = defaultdict(list)  # computer sid -> user sids
        self.trusts = []
        self.ca_enabled_templates = set()  # template SIDs published by any Enterprise CA
        self.ca_data = {}                  # CA sid -> {registry, endpoints, hosting}
        self.hidden_primary_groups = []    # (member sid, group sid) non-default primary groups
        self.counts = defaultdict(int)

    def add_node(self, sid, name, kind, domain, pr, doc_kind_name):
        if not sid:
            return
        existing = self.nodes.get(sid)
        node = existing or {"name": name or sid, "kind": kind, "domain": domain,
                            "props": {}, "doc_kinds": set()}
        node["props"].update(pr)
        node["doc_kinds"].add(doc_kind_name)
        if name and (not existing or existing["name"] == sid):
            node["name"] = name
        self.nodes[sid] = node
        if name:
            self.name_to_sid[name.upper()] = sid
        sam = pr.get("samaccountname")
        if not isinstance(sam, str):
            sam = ""
        if sam:
            self.sam_to_sid[sam.upper()] = sid
        if kind == "COMPUTER":
            dns = (name or "").upper()
            self.dns_to_sid[dns] = sid
            if sam:
                self.dns_to_sid.setdefault(sam.upper().rstrip("$") + "." + domain.upper()
                                           if domain else sam.upper(), sid)

    def add_edge(self, src, dst, kind, inherited=False):
        if src and dst:
            self.edges.append((src.upper(), dst.upper(), kind, inherited))

    def edges_to(self, dst):
        """All edges whose destination is dst (lazily built index)."""
        idx = getattr(self, "_edges_by_dst", None)
        if idx is None:
            idx = defaultdict(list)
            for e in self.edges:
                idx[e[1]].append(e)
            self._edges_by_dst = idx
        return idx.get(dst, ())

    def edges_from(self, src):
        """All edges whose source is src (lazily built index)."""
        idx = getattr(self, "_edges_by_src", None)
        if idx is None:
            idx = defaultdict(list)
            for e in self.edges:
                idx[e[0]].append(e)
            self._edges_by_src = idx
        return idx.get(src, ())

    def traversable_adj(self):
        """Adjacency map (src -> [(dst, kind)]) over non-inherited TRAVERSABLE
        edges, built once and cached for the pathfinder."""
        adj = getattr(self, "_trav_adj", None)
        if adj is None:
            adj = defaultdict(list)
            for src, dst, kind, inh in self.edges:
                if kind in TRAVERSABLE and not inh:
                    adj[src].append((dst, kind))
            self._trav_adj = adj
        return adj

    def tier0_member_sids(self):
        """Union of members of DA/EA/Schema Admins + BUILTIN Administrators
        (computed once, cached)."""
        cached = getattr(self, "_tier0_members_cache", None)
        if cached is None:
            cached = set()
            for sid, n in self.nodes.items():
                if n["kind"] == "GROUP" and \
                        (sid.endswith(("-512", "-519", "-518")) or sid == "S-1-5-32-544"):
                    cached.update(self.groups_members.get(sid, []))
            self._tier0_members_cache = cached
        return cached

    def finalize(self):
        """Post-ingest cleanup: dedupe edges/member lists, drop stale caches."""
        self.edges = list(dict.fromkeys(self.edges))
        for members in self.groups_members.values():
            members[:] = list(dict.fromkeys(members))
        for users in self.computer_sessions.values():
            users[:] = list(dict.fromkeys(users))
        for attr in ("_edges_by_dst", "_edges_by_src", "_trav_adj", "_tier0_members_cache"):
            if hasattr(self, attr):
                delattr(self, attr)

    def resolve(self, label):
        """Resolve a principal label (name, SAM, or SID) to a SID."""
        if not label:
            return None
        u = label.strip().upper()
        if u in self.nodes:
            return u
        if u in self.name_to_sid:
            return self.name_to_sid[u]
        if u in self.sam_to_sid:
            return self.sam_to_sid[u]
        # try SAM@DOMAIN / DOMAIN\SAM forms
        if "@" in u:
            sam = u.split("@", 1)[0]
            if sam in self.sam_to_sid:
                return self.sam_to_sid[sam]
        if "\\" in u:
            sam = u.split("\\", 1)[1]
            if sam in self.sam_to_sid:
                return self.sam_to_sid[sam]
        return None

    def name(self, sid):
        n = self.nodes.get(sid.upper()) if sid else None
        return n["name"] if n else (sid or "?")

    def is_noise_principal(self, sid):
        if sid in NOISE_SIDS:
            return True
        if sid.endswith(NOISE_RID_SUFFIXES):
            return True
        n = self.nodes.get(sid)
        if n and n["name"].upper() in (
                "ENTERPRISE DOMAIN CONTROLLERS", "CREATOR OWNER", "SELF"):
            return True
        return False

    # ----- relationship extraction --------------------------------------
    def ingest(self, source_name, doc):
        kind = doc_kind(doc, source_name)
        objects = doc_objects(doc)
        self.counts[kind] += len(objects)
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            pr = props(obj)
            sid = obj_sid(obj)
            name = pr.get("name") or obj.get("Name") or sid
            if not isinstance(name, str):
                name = sid
            nk = obj_kind_guess(obj, kind)
            domain = _as_str(pr.get("domain")).upper()
            self.add_node(sid, name, nk, domain, pr, kind)
            if not sid:
                continue  # unidentifiable object — nothing can key off it

            # ACLs
            for ace in _as_list(obj.get("Aces")):
                if not isinstance(ace, dict):
                    continue
                psid = _as_str(ace.get("PrincipalSID")).upper()
                right = _as_str(ace.get("RightName"))
                if not right:
                    continue
                inh = bool(ace.get("IsInherited"))
                self.add_edge(psid, sid, right, inh)

            # Group membership
            for m in _as_list(obj.get("Members")):
                if not isinstance(m, dict):
                    continue
                msid = _as_str(m.get("ObjectIdentifier")).upper()
                self.add_edge(msid, sid, "MemberOf")
                self.groups_members[sid].append(msid)

            # PrimaryGroupSID: membership that does NOT appear in Members[]
            # (AD quirk — classic stealth-DA hiding spot)
            pgs = _as_str(obj.get("PrimaryGroupSID")).upper()
            if pgs:
                self.add_edge(sid, pgs, "MemberOf")
                self.groups_members[pgs].append(sid)
                default_pg = "-515" if nk == "COMPUTER" else "-513"
                if not pgs.endswith(default_pg) and not (nk == "COMPUTER" and pgs.endswith("-516")) \
                        and not (sid.endswith("-501") and pgs.endswith("-514")):
                    self.hidden_primary_groups.append((sid, pgs))

            # Object-level AdminSDHolder flag (v5+: outside the Properties bag)
            if "IsACLProtected" in obj:
                self.nodes[sid]["props"]["_aclprotected"] = bool(obj.get("IsACLProtected"))

            # Computer relationships
            for sess_key, ekind in (("Sessions", "HasSession"),
                                    ("PrivilegedSessions", "HasSession"),
                                    ("RegistrySessions", "HasSession")):
                block = _as_dict(obj.get(sess_key))
                for r in _as_list(block.get("Results")):
                    if not isinstance(r, dict):
                        continue
                    usid = _as_str(r.get("UserSID") or r.get("ObjectIdentifier")).upper()
                    if usid:
                        self.add_edge(usid, sid, "HasSession")
                        self.computer_sessions[sid].append(usid)

            la = _as_dict(obj.get("LocalAdmins"))
            for r in _as_list(la.get("Results")):
                if not isinstance(r, dict):
                    continue
                psid = _as_str(r.get("ObjectIdentifier")).upper()
                self.add_edge(psid, sid, "AdminTo")
            for ur in _as_list(obj.get("UserRights")):
                if not isinstance(ur, dict):
                    continue
                right = _as_str(ur.get("Privilege"))
                ek = {"SeRemoteInteractiveLogonRight": "CanRDP",
                      "SeNetworkLogonRight": "CanPSRemote"}.get(right)
                if ek:
                    for r in _as_list(ur.get("Results")):
                        if not isinstance(r, dict):
                            continue
                        psid = _as_str(r.get("ObjectIdentifier")).upper()
                        self.add_edge(psid, sid, ek)

            # RBCD list form (some collectors)
            for r in _as_list(obj.get("AllowedToAct")):
                if not isinstance(r, dict):
                    continue
                psid = _as_str(r.get("ObjectIdentifier")).upper()
                self.add_edge(psid, sid, "AllowedToAct")

            # gMSA password readers (collector lists principals directly)
            for r in _as_list(obj.get("DumpSMSAPassword")):
                if not isinstance(r, dict):
                    continue
                psid = _as_str(r.get("ObjectIdentifier")).upper()
                self.add_edge(psid, sid, "DumpSMSAPassword")

            # Constrained delegation via property SPNs
            for spn in _as_list(pr.get("allowedtodelegate")):
                if not isinstance(spn, str):
                    continue
                tgt = self._spn_to_sid(spn, domain)
                if tgt:
                    self.add_edge(sid, tgt, "AllowedToDelegate")

            # SID history: the carrier gains the historical SID's privileges,
            # so the traversable edge runs carrier -> historical principal
            for hs in _as_list(obj.get("HasSIDHistory")):
                if not isinstance(hs, dict):
                    continue
                psid = _as_str(hs.get("ObjectIdentifier")).upper()
                self.add_edge(sid, psid, "HasSIDHistory")

            # Domain trusts
            for t in _as_list(obj.get("Trusts")):
                if not isinstance(t, dict):
                    continue
                self.trusts.append({
                    "domain": name,
                    "target": t.get("TargetName") or t.get("TargetDomainName") or "?",
                    "direction": t.get("TrustDirection"),
                    "type": t.get("TrustType"),
                    "transitive": t.get("IsTransitive"),
                    "sid_filtering": t.get("SidFilteringEnabled"),
                })

            # Enterprise CA extras (ESC6/8/11/16 analysis)
            if nk == "ENTERPRISECA":
                for tpl in _as_list(obj.get("EnabledCertTemplates")):
                    if not isinstance(tpl, dict):
                        continue
                    tsid = _as_str(tpl.get("ObjectIdentifier")).upper()
                    if tsid:
                        self.ca_enabled_templates.add(tsid)
                self.ca_data[sid] = {
                    "hosting": _as_str(obj.get("HostingComputer")),
                    "registry": _as_dict(obj.get("CARegistryData")),
                    "endpoints": _as_list(obj.get("HttpEnrollmentEndpoints")),
                }

            # Computer extras (relay surface / DC cert mapping)
            if nk == "COMPUTER":
                nprops = self.nodes[sid]["props"]
                nprops["_dcregistry"] = _as_dict(obj.get("DCRegistryData"))
                wc = obj.get("IsWebClientRunning")
                nprops["_webclient"] = wc.get("Result") if isinstance(wc, dict) else wc
                smb = _as_dict(obj.get("SmbInfo"))
                if smb:
                    # SharpHound v6 (2025+): APIResult wrapper —
                    # {"Collected": bool, "Result": {"SigningEnabled": bool?}};
                    # absent entirely on v5 and early-v6 collectors. Only trust
                    # the value when collection succeeded.
                    if smb.get("Collected") is False:
                        nprops["_smb_signing"] = None
                    else:
                        inner = smb.get("Result") if isinstance(smb.get("Result"), dict) else smb
                        nprops["_smb_signing"] = inner.get("SigningEnabled")
                else:
                    nprops["_smb_signing"] = None
                ntlm = obj.get("NTLMRegistryData")
                nprops["_ntlmreg"] = ntlm.get("Result") if isinstance(ntlm, dict) else None

            # GPO/OU links
            for l in _as_list(obj.get("Links")):
                if not isinstance(l, dict):
                    continue
                gsid = _as_str(l.get("ObjectIdentifier") or l.get("GUID")).upper()
                if gsid:
                    self.add_edge(gsid, sid, "GPLink")

    def _spn_to_sid(self, spn, domain):
        """Map 'CIFS/host.domain.local' -> computer sid when resolvable."""
        host = spn.split("/", 1)[-1].split(":")[0].upper()
        if host in self.dns_to_sid:
            return self.dns_to_sid[host]
        short = host.split(".", 1)[0]
        for dns, sid in self.dns_to_sid.items():
            if dns.split(".", 1)[0] == short:
                return sid
        return None


# --------------------------------------------------------------------------
# Analysis passes — each returns a list of finding dicts
# --------------------------------------------------------------------------
def find_kerberoastable(g):
    out = []
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    for sid, n in g.nodes.items():
        # USER only: computer accounts also carry hasspn=true (HOST/ SPNs) but
        # have random 120+ char passwords — roasting them is never actionable
        if n["kind"] != "USER":
            continue
        p = n["props"]
        roastable = p.get("hasspn") or bool(p.get("serviceprincipalnames"))
        if roastable and p.get("enabled", True) and not n["name"].upper().startswith("KRBTGT") \
                and not sid.endswith("-502"):
            pwd_date = _epoch_to_date(p.get("pwdlastset"))
            detail = "Kerberoastable (has SPN)"
            if pwd_date:
                detail += f"; password last set {pwd_date}"
                try:
                    age = (now - int(p["pwdlastset"])) / 86400
                    if age > 365:
                        detail += f" ({int(age/365)}y old — good crack odds)"
                except (TypeError, ValueError):
                    pass
            if p.get("admincount") and not p.get("sensitive"):
                detail += "; privileged and delegatable"
            try:
                enc = int(p.get("supportedencryptiontypes") or 0)
            except (TypeError, ValueError):
                enc = 0
            if enc and not (enc & 0x18):  # no AES128/AES256
                algos = []
                if enc & 0x4: algos.append("RC4")
                if enc & 0x3: algos.append("DES")
                sev_note = f"; {'/'.join(algos)}-only Kerberos — tickets crack fast (RC4 keystream is NTLM-derived)"
                detail += sev_note
            out.append({"sev": "HIGH" if (p.get("admincount") or (enc and not enc & 0x18)) else "MED",
                        "name": n["name"], "admincount": bool(p.get("admincount")),
                        "spns": p.get("serviceprincipalnames") or [],
                        "desc": p.get("description") or "",
                        "detail": detail})
    return out


def find_asrep(g):
    out = []
    for sid, n in g.nodes.items():
        p = n["props"]
        if n["kind"] == "USER" and p.get("dontreqpreauth") and p.get("enabled", True):
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": "AS-REP roastable (DONT_REQ_PREAUTH)"})
    return out


def find_delegation(g):
    out = []
    for sid, n in g.nodes.items():
        p = n["props"]
        dn = _as_str(p.get("distinguishedname")).upper()
        is_dc = "OU=DOMAIN CONTROLLERS" in dn
        if p.get("unconstraineddelegation") and n["kind"] != "DOMAIN":
            if n["kind"] == "COMPUTER" and is_dc:
                continue  # DCs are unconstrained by design
            out.append({"sev": "CRIT", "name": n["name"],
                        "detail": "Unconstrained delegation (non-DC) — coerce a DC to this host and capture TGTs"})
        if p.get("trustedtoauth"):
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": "Constrained delegation with protocol transition (TrustedToAuth) — S4U2Self abuse"})
        atd = _as_list(p.get("allowedtodelegate"))
        if atd and not p.get("trustedtoauth"):
            out.append({"sev": "MED", "name": n["name"],
                        "detail": f"Constrained delegation -> {', '.join(str(s) for s in atd[:5])}"})
    # RBCD edges
    for src, dst, kind, inh in g.edges:
        if kind in ("AllowedToAct", "WriteAccountRestrictions") and not inh:
            out.append({"sev": "HIGH",
                        "name": f"{g.name(src)} -> {g.name(dst)}",
                        "detail": f"RBCD ({kind}): {g.name(src)} can impersonate users on {g.name(dst)}"})
    return out


def find_dcsync(g):
    rights_by_principal = defaultdict(set)   # (src, domain) -> {rights}
    grant_paths = defaultdict(set)           # (src, domain) -> {rights}
    for src, dst, kind, inh in g.edges:
        if inh or g.is_noise_principal(src):
            continue
        n = g.nodes.get(dst)
        if not n or n["kind"] != "DOMAIN":
            continue
        if kind in DCSYNC_RIGHTS:
            rights_by_principal[(src, dst)].add(kind)
        elif kind in ("WriteDacl", "GenericAll", "AllExtendedRights", "WriteOwner"):
            grant_paths[(src, dst)].add(kind)
    out = []
    for (src, dst), kinds in rights_by_principal.items():
        out.append({"sev": "CRIT", "name": g.name(src),
                    "detail": f"{' + '.join(sorted(kinds))} on domain {g.name(dst)} — DCSync possible"})
    for (src, dst), kinds in grant_paths.items():
        out.append({"sev": "CRIT", "name": g.name(src),
                    "detail": f"{' + '.join(sorted(kinds))} on domain {g.name(dst)} — can grant self DCSync rights (e.g. Exchange Windows Permissions pattern)"})
    return out


def find_dangerous_acls(g):
    out = []
    for src, dst, kind, inh in g.edges:
        if kind in DANGEROUS_RIGHTS and not inh:
            if g.is_noise_principal(src) or src == dst:
                continue
            out.append({"sev": DANGEROUS_RIGHTS[kind],
                        "name": f"{g.name(src)} --{kind}--> {g.name(dst)}",
                        "detail": f"{g.name(src)} has {kind} over {g.name(dst)}",
                        "src": src, "dst": dst, "right": kind})
    return out


def find_tier0_groups(g):
    """Privileged group membership, including nested resolution."""
    out = []
    tier0 = []  # (sid, display name)
    for sid, n in g.nodes.items():
        if n["kind"] != "GROUP":
            continue
        for suffix, gname in TIER0_RIDS.items():
            if sid.endswith(suffix):
                tier0.append((sid, gname))
                break
    for sid, gname in tier0:
        members = g.groups_members.get(sid, [])
        for m in members:
            mn = g.nodes.get(m, {})
            mname = mn.get("name", m)
            mkind = mn.get("kind", "?")
            sev = "INFO"
            upper = mname.upper()
            if upper in ("EVERYONE", "AUTHENTICATED USERS") or \
               upper.endswith("DOMAIN USERS") or upper.endswith("DOMAIN COMPUTERS"):
                sev = "CRIT"
            elif mkind == "GROUP" and not m.upper().endswith(("-512", "-519", "-518", "-544")):
                sev = "MED"
            if not mn.get("props", {}).get("enabled", True) and mkind == "USER":
                sev = "INFO"
            out.append({"sev": sev,
                        "name": f"{mname} -> {gname}",
                        "detail": f"{mkind} member of {gname}"})
    # Builtin Administrators (S-1-5-32-544)
    for sid, n in g.nodes.items():
        if n["kind"] == "GROUP" and sid == "S-1-5-32-544":
            for m in g.groups_members.get(sid, []):
                mn = g.nodes.get(m, {})
                out.append({"sev": "INFO",
                            "name": f"{mn.get('name', m)} -> Administrators",
                            "detail": "member of BUILTIN Administrators"})
    return out


def find_privileged_sessions(g):
    out = []
    priv_sids = {sid for sid, n in g.nodes.items() if n["props"].get("admincount")}
    priv_sids |= g.tier0_member_sids()
    # replication-capable accounts are credential gold even without adminCount
    for src, dst, kind, inh in g.edges:
        if not inh and kind in DCSYNC_RIGHTS \
                and g.nodes.get(dst, {}).get("kind") == "DOMAIN":
            priv_sids.add(src)
    for comp, users in g.computer_sessions.items():
        cn = g.nodes.get(comp, {})
        if cn.get("kind") != "COMPUTER":
            continue
        for u in set(users):
            if u in priv_sids:
                un = g.name(u)
                if un.upper().startswith("KRBTGT"):
                    continue
                out.append({"sev": "HIGH",
                            "name": f"{un} @ {g.name(comp)}",
                            "detail": f"Privileged user {un} has a session on {g.name(comp)} — dump creds if you admin this host"})
    return out


def find_adminto(g):
    """Direct AdminTo edges from non-noise principals (attack surface)."""
    out = []
    for src, dst, kind, inh in g.edges:
        if kind != "AdminTo":
            continue
        if g.is_noise_principal(src):
            continue
        n = g.nodes.get(src, {})
        if n.get("kind") == "GROUP" and src.endswith(("-512", "-519")):
            continue
        out.append({"sev": "INFO", "name": f"{g.name(src)} -> {g.name(dst)}",
                    "detail": f"{g.name(src)} is local admin on {g.name(dst)}"})
    return out


def find_laps(g):
    out = []
    laps_hosts, no_laps, unknown = [], [], 0
    for sid, n in g.nodes.items():
        if n["kind"] != "COMPUTER":
            continue
        if "haslaps" not in n["props"]:
            unknown += 1  # property not collected — never infer absence of LAPS
            continue
        (laps_hosts if n["props"].get("haslaps") else no_laps).append(n["name"])
    for h in laps_hosts:
        out.append({"sev": "INFO", "name": h, "detail": "LAPS deployed"})
    total = len(laps_hosts) + len(no_laps)
    if total and len(laps_hosts) < total:
        pct = 100 * len(laps_hosts) // total
        out.append({"sev": "MED",
                    "name": f"LAPS coverage {pct}% ({len(laps_hosts)}/{total})",
                    "detail": f"{len(no_laps)} hosts explicitly collected without LAPS — local admin passwords may be shared/static; one local hash could move laterally: {', '.join(no_laps[:12])}"})
    if unknown:
        out.append({"sev": "INFO", "name": f"LAPS state unknown for {unknown} host(s)",
                    "detail": "haslaps was not collected for these computers — excluded from the coverage figure"})
    for src, dst, kind, inh in g.edges:
        if inh or g.is_noise_principal(src):
            continue
        if kind in LAPS_RIGHTS:
            out.append({"sev": "HIGH",
                        "name": f"{g.name(src)} --{kind}--> {g.name(dst)}",
                        "detail": f"{g.name(src)} can read LAPS password for {g.name(dst)}"})
        elif kind in GMSA_RIGHTS:
            out.append({"sev": "HIGH",
                        "name": f"{g.name(src)} --{kind}--> {g.name(dst)}",
                        "detail": f"{g.name(src)} can read the gMSA password of {g.name(dst)}"})
    return out


def find_computers(g):
    out = []
    os_count = defaultdict(int)
    outdated = []
    for sid, n in g.nodes.items():
        if n["kind"] != "COMPUTER":
            continue
        os_name = n["props"].get("operatingsystem")
        if not isinstance(os_name, str):
            os_name = "unknown"
        os_count[os_name] += 1
        if re.search(r"(2003|2008|2012|\bXP\b|Windows 7\b|Vista)", os_name, re.I):
            outdated.append((n["name"], os_name))
    if outdated:
        out.append({"sev": "MED", "name": f"{len(outdated)} outdated OS",
                    "detail": "; ".join(f"{n} ({o})" for n, o in outdated[:20]),
                    "os_histogram": dict(sorted(os_count.items(), key=lambda x: -x[1]))})
    elif os_count:
        out.append({"sev": "INFO", "name": "OS distribution",
                    "detail": "", "os_histogram": dict(sorted(os_count.items(), key=lambda x: -x[1]))})
    return out


def find_password_hygiene(g):
    out = []
    no_req, never_exp = [], []
    buckets = {"never set": 0, "<1y": 0, "1-2y": 0, "2-5y": 0, "5-10y": 0, ">10y": 0}
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    for sid, n in g.nodes.items():
        p = n["props"]
        if n["kind"] != "USER" or not p.get("enabled", True):
            continue
        if p.get("passwordnotreqd"):
            no_req.append(n["name"])
        if p.get("pwdneverexpires"):
            never_exp.append(n["name"])
        if "pwdlastset" not in p:
            continue  # not collected — never infer age from an absent value
        try:
            pls = int(p["pwdlastset"])
        except (TypeError, ValueError):
            continue
        if pls <= 0:
            buckets["never set"] += 1
        else:
            age_y = (now - pls) / (86400 * 365)
            buckets["<1y" if age_y < 1 else "1-2y" if age_y < 2 else
                    "2-5y" if age_y < 5 else "5-10y" if age_y < 10 else ">10y"] += 1
    for name in no_req:
        out.append({"sev": "HIGH", "name": name,
                    "detail": "PASSWORDNOTREQD — may have a blank password; try empty-password auth"})
    if never_exp:
        out.append({"sev": "INFO", "name": f"{len(never_exp)} accounts",
                    "detail": "Password never expires: " + ", ".join(never_exp[:25])})
    total = sum(buckets.values())
    if total:
        out.append({"sev": "INFO", "name": "Password age distribution (enabled users)",
                    "detail": "  ".join(f"{k}: {v}" for k, v in buckets.items()) +
                    " — old passwords crack faster and indicate stale hygiene"})
    return out


def find_descriptions(g):
    out = []
    for sid, n in g.nodes.items():
        desc = n["props"].get("description")
        if isinstance(desc, str) and desc and DESC_HINT.search(desc):
            out.append({"sev": "MED", "name": n["name"],
                        "detail": f"description: {desc.strip()[:160]}"})
        for pwfield in ("userpassword", "unixpassword", "unicodepassword", "sfupassword"):
            val = n["props"].get(pwfield)
            if val:
                out.append({"sev": "CRIT", "name": n["name"],
                            "detail": f"{pwfield} attribute populated: {str(val)[:80]}"})
    return out


def find_admincount_drift(g):
    """admincount=1 principals not in tier-0 groups (stale privileges), plus
    AdminSDHolder protection inconsistencies."""
    tier0_members = g.tier0_member_sids()
    out = []
    for sid, n in g.nodes.items():
        if n["kind"] == "USER" and n["props"].get("admincount") \
                and n["props"].get("enabled", True) and sid not in tier0_members:
            out.append({"sev": "MED", "name": n["name"],
                        "detail": "adminCount=1 but not in a tier-0 group (stale protected-group membership)"})
        # AdminSDHolder mismatch
        p = n["props"]
        if n["kind"] == "USER" and p.get("enabled", True):
            if p.get("admincount") and p.get("_aclprotected") is False:
                out.append({"sev": "INFO", "name": n["name"],
                            "detail": "adminCount=1 but ACL protection not applied (SDProp hasn't run or inheritance broken) — ACLs on this account are NOT guarded by AdminSDHolder"})
            elif not p.get("admincount") and p.get("_aclprotected") is True:
                out.append({"sev": "INFO", "name": n["name"],
                            "detail": "ACL-protected but adminCount=0 — former privileged account still carrying hardened ACLs (changes will keep reverting)"})
    return out


def find_trusts(g):
    out = []
    for t in g.trusts:
        dv = t["direction"] if isinstance(t["direction"], int) else None
        direction = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(dv, str(t["direction"]))
        sev = "INFO"
        detail = f"{t['domain']} -> {t['target']}: {direction}, {t['type']}, transitive={t['transitive']}"
        if dv in (1, 3) and t.get("sid_filtering") is False:
            sev = "HIGH"
            detail += " — SID filtering DISABLED on inbound trust (SIDHistory abuse across forest)"
        elif dv in (1, 3):
            sev = "MED"
            detail += " — inbound trust; cross-domain attacks possible"
            if t.get("sid_filtering") is None:
                detail += " (SID-filtering state not collected — verify manually)"
        out.append({"sev": sev, "name": f"{t['domain']} <-> {t['target']}", "detail": detail})
    return out


def find_gpo_control(g):
    out = []
    for sid, n in g.nodes.items():
        if n["kind"] != "GPO":
            continue
        # where does this GPO link? (GPLink edges: gpo -> domain/OU)
        link_targets = [g.name(dst) for src, dst, kind, inh in g.edges_from(sid)
                        if kind == "GPLink"]
        link_note = f"; applies to: {', '.join(sorted(set(link_targets))[:8])}" if link_targets else ""
        for src, dst, kind, inh in g.edges_to(sid):
            if kind in ("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite") \
                    and not inh and not g.is_noise_principal(src):
                out.append({"sev": "HIGH",
                            "name": f"{g.name(src)} --{kind}--> GPO {n['name']}",
                            "detail": f"{g.name(src)} can edit GPO '{n['name']}'{link_note} — push a malicious setting (immediate task/startup script) for code execution on linked objects"})
        # GPO files outside the domain SYSVOL (unusual share = tampering risk)
        gpcpath = _as_str(n["props"].get("gpcpath")).upper()
        if gpcpath and "\\SYSVOL\\" not in gpcpath:
            out.append({"sev": "MED", "name": f"GPO outside SYSVOL: {n['name']}",
                        "detail": f"gpcFileSysPath is {n['props'].get('gpcpath')} — GPO content lives outside SYSVOL; whoever controls that share controls the GPO"})
    return out


def _epoch_to_date(val):
    try:
        v = int(val)
        if v <= 0:
            return None
        return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError, OverflowError):
        return None


def _is_low_priv(g, sid):
    if sid in LOW_PRIV_SIDS or sid.endswith(LOW_PRIV_SUFFIXES):
        return True
    n = g.nodes.get(sid)
    if n and n["name"].upper() in LOW_PRIV_NAMES:
        return True
    return False


def _low_priv_label(g, sid):
    """Display name for a low-priv principal, resolving well-known SIDs."""
    n = g.nodes.get(sid)
    if n and not n["name"].startswith("S-1-"):
        return n["name"]
    if sid == "S-1-1-0":
        return "Everyone"
    if sid == "S-1-5-11":
        return "Authenticated Users"
    if sid.endswith("-513"):
        return "Domain Users"
    if sid.endswith("-515"):
        return "Domain Computers"
    return sid


def find_domain_policy(g):
    """Domain password/lockout policy + MachineAccountQuota — spray planning."""
    out = []
    for sid, n in g.nodes.items():
        if n["kind"] != "DOMAIN":
            continue
        p = n["props"]
        maq = p.get("machineaccountquota")
        if maq is not None and str(maq).lstrip("-").isdigit():
            if int(maq) > 0:
                out.append({"sev": "HIGH",
                            "name": f"{n['name']}: MachineAccountQuota={maq}",
                            "detail": "Any domain user can create machine accounts — RBCD/noPac-style attacks and relay-to-LDAP computer creation are possible"})
        lock = p.get("lockoutthreshold")
        if lock is not None or p.get("minpwdlength") is not None:
            lock = p.get("lockoutthreshold")
            try:
                lock_i = int(lock)
            except (TypeError, ValueError):
                lock_i = None
            if lock_i == 0:
                sev, note = "HIGH", "NO account lockout — password spraying unrestricted"
            elif lock_i is not None:
                sev, note = "INFO", f"lockout at {lock_i} attempts — throttle sprays (observe window {p.get('lockoutobservationwindow', '?')}, duration {p.get('lockoutduration', '?')})"
            else:
                sev, note = "INFO", "lockout threshold not collected"
            out.append({"sev": sev, "name": f"{n['name']}: password & lockout policy",
                        "detail": f"min length {p.get('minpwdlength', '?')}, history {p.get('pwdhistorylength', '?')}, "
                                  f"max age {p.get('maxpwdage', '?')}, min age {p.get('minpwdage', '?')}, "
                                  f"complexity flags {p.get('pwdproperties', '?')}, functional level {p.get('functionallevel', '?')} — {note}"})
    return out


def find_adcs(g):
    """ADCS abuse: ESC1-4, 6-11, 13, 15, 16 + NTAuthStore + Golden Cert paths."""
    out = []
    published_known = bool(g.ca_enabled_templates)

    # Per-template evaluation
    for sid, n in g.nodes.items():
        if n["kind"] != "CERTTEMPLATE":
            continue
        p = n["props"]
        published = sid in g.ca_enabled_templates
        pub_note = "" if published else (" (not published by any collected CA — verify)" if published_known else "")

        # enrollment rights held by low-priv principals
        low_enrollers = []
        write_holders = []
        for src, dst, kind, inh in g.edges_to(sid):
            if inh:
                continue
            if kind in ("Enroll", "AllExtendedRights", "GenericAll") and _is_low_priv(g, src):
                low_enrollers.append(_low_priv_label(g, src))
            if kind in ("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite", "Owns",
                        "WritePKINameFlag", "WritePKIEnrollmentFlag") and not g.is_noise_principal(src):
                write_holders.append((g.name(src), kind))

        # schema version (1 = legacy, injectable); default to 2 when absent/invalid
        try:
            sv = int(p.get("schemaversion") or 2)
        except (TypeError, ValueError):
            sv = 2

        ekus = {e for e in _as_list(p.get("ekus")) + _as_list(p.get("effectiveekus"))
                if isinstance(e, str)}
        client_auth = bool(p.get("authenticationenabled")) or bool(ekus & CLIENT_AUTH_EKUS) \
            or (not ekus and sv == 1)
        no_approval = not p.get("requiresmanagerapproval")
        no_sigs = not p.get("authorizedsignatures")

        if low_enrollers and p.get("enrolleesuppliessubject") and no_approval and no_sigs and client_auth:
            out.append({"sev": "CRIT", "name": f"ESC1: {n['name']}{pub_note}",
                        "detail": f"Enrollee supplies subject + client auth + no manager approval/signatures; enrollable by {', '.join(sorted(set(low_enrollers)))}. Request a cert as any user (e.g. Domain Admin) with Certify/Certipy"})
        if low_enrollers and CERT_REQUEST_AGENT_EKU in ekus:
            out.append({"sev": "HIGH", "name": f"ESC3: {n['name']}{pub_note}",
                        "detail": f"Certificate Request Agent EKU enrollable by {', '.join(sorted(set(low_enrollers)))} — enrollment-agent attack path"})
        if write_holders:
            out.append({"sev": "CRIT" if any(k in ("GenericAll", "WriteDacl", "WriteOwner", "Owns") for _, k in write_holders) else "HIGH",
                        "name": f"ESC4: {n['name']}",
                        "detail": "Template modifiable by: " + ", ".join(f"{w} ({k})" for w, k in write_holders[:5]) + " — rewrite into ESC1-style template"})
        # ESC2: Any Purpose / no EKU template usable for any purpose incl. SubCA
        if low_enrollers and (not ekus or "2.5.29.37.0" in ekus) and no_approval and no_sigs:
            out.append({"sev": "HIGH", "name": f"ESC2: {n['name']}{pub_note}",
                        "detail": f"Any-purpose/no-EKU template enrollable by {', '.join(sorted(set(low_enrollers)))} — usable for any purpose including as a SubCA cert to forge certificates"})
        # ESC9: no security extension + mappable name flag + weak DC cert mapping
        if p.get("nosecurityextension"):
            mappable = any(p.get(k) for k in ("subjectaltrequireupn", "subjectaltrequirespn",
                                              "subjectaltrequiredns"))
            if low_enrollers and client_auth and no_approval and no_sigs and mappable:
                out.append({"sev": "HIGH", "name": f"ESC9: {n['name']}{pub_note}",
                            "detail": f"NO_SECURITY_EXTENSION + UPN/SPN/DNS-based mapping, enrollable by {', '.join(sorted(set(low_enrollers)))} — with GenericWrite on any account: flip its UPN/dNSHostName to a target, enroll, revert, authenticate as target (needs weak DC certificate mapping — see ESC10)"})
            else:
                out.append({"sev": "MED", "name": f"{n['name']} (NO_SECURITY_EXTENSION)",
                            "detail": "szOID_NTDS_CA_SECURITY_EXT omitted from issued certs — prerequisite for ESC9-style mapping abuse; other conditions not all met"})
        # ESC15 (EKUwu): schema v1 templates are injectable
        if sv == 1 and (low_enrollers or write_holders):
            who = sorted(set(low_enrollers + [w for w, _ in write_holders]))
            out.append({"sev": "MED", "name": f"ESC15/EKUwu: {n['name']}{pub_note}",
                        "detail": f"Schema-version-1 template exposed to {', '.join(who[:5])} — application-policy injection (arbitrary EKU) possible"})

    # ESC13: group-linked issuance policies (Authentication Mechanism Assurance)
    for sid, n in g.nodes.items():
        if n["kind"] != "ISSUANCEPOLICY":
            continue
        p = n["props"]
        link = p.get("oidgrouplink")
        if link:
            out.append({"sev": "HIGH", "name": f"ESC13: {n['name']}",
                        "detail": f"Issuance policy (OID {p.get('oid', '?')}) linked to group {g.name(link)} — any cert issued with this policy grants that group's membership in the ticket (via an enrollable template carrying the policy, or ManageCertificates injection)"})

    # CA-level findings
    for ca_sid, ca in g.ca_data.items():
        caname = g.name(ca_sid)
        reg = ca["registry"]
        san = reg.get("IsUserSpecifiesSanEnabled") or {}
        if isinstance(san, dict) and san.get("Value") is True:
            out.append({"sev": "CRIT", "name": f"ESC6: {caname}",
                        "detail": "EDITF_ATTRIBUTESUBJECTALTNAME2 set — any template allows SAN spoofing; request cert as DA"})
        rpc = reg.get("RPCEncryptionEnforced") or {}
        if isinstance(rpc, dict) and rpc.get("Collected") and rpc.get("Value") is False:
            out.append({"sev": "HIGH", "name": f"ESC11: {caname}",
                        "detail": "ICPR RPC enrollment does not enforce encryption — NTLM relay to the CA's RPC interface (combine with coercion from a relay-capable host)"})
        dis = reg.get("DisabledExtensions") or {}
        if isinstance(dis, dict) and dis.get("Collected") is False:
            dis = {}
        dis_val = dis.get("Value") if isinstance(dis, dict) else None
        if dis_val and any("1.3.6.1.4.1.311.25.2" in str(x) for x in
                           (dis_val if isinstance(dis_val, list) else [dis_val])):
            out.append({"sev": "CRIT", "name": f"ESC16: {caname}",
                        "detail": "CA globally disabled the SID security extension (szOID_NTDS_CA_SECURITY_EXT) — every template behaves like ESC9; with ESC6 use --sid-url to map certs to any target despite strong mapping"})
        for ep in ca["endpoints"] or []:
            if not isinstance(ep, dict):
                continue
            res = ep.get("Result") or {}
            if not isinstance(res, dict):
                continue
            status = res.get("Status")
            vuln = bool(res.get("ADCSWebEnrollmentHTTP"))
            if isinstance(status, str) and status.startswith("Vulnerable"):
                vuln = True
            elif isinstance(status, int) and not isinstance(status, bool) and status < 0x100:
                vuln = True
            if vuln:
                out.append({"sev": "HIGH", "name": f"ESC8: {caname}",
                            "detail": f"HTTP enrollment endpoint {res.get('Url', '?')} ({res.get('Type', '?')}) — NTLM relay to ADCS web enrollment; EPA required: {res.get('ADCSWebEnrollmentEPA')}"})

        # ESC7: CA officers / managers
        for src, dst, kind, inh in g.edges_to(ca_sid):
            if inh or g.is_noise_principal(src):
                continue
            if kind == "ManageCA":
                out.append({"sev": "CRIT", "name": f"ESC7: {g.name(src)}",
                            "detail": f"{g.name(src)} has ManageCA on {caname} — can flip EDITF_ATTRIBUTESUBJECTALTNAME2 / approve requests"})
            elif kind == "ManageCertificates":
                out.append({"sev": "HIGH", "name": f"ESC7: {g.name(src)}",
                            "detail": f"{g.name(src)} has ManageCertificates on {caname} — can approve pending requests (combine with ManageCA)"})

    # ESC10: weak certificate mapping on DCs
    for sid, n in g.nodes.items():
        if n["kind"] != "COMPUTER":
            continue
        dcreg = n["props"].get("_dcregistry") or {}
        if not dcreg:
            continue
        scb = dcreg.get("StrongCertificateBindingEnforcement") or {}
        cmm = dcreg.get("CertificateMappingMethods") or {}
        scb_v = scb.get("Value") if isinstance(scb, dict) else None
        cmm_v = cmm.get("Value") if isinstance(cmm, dict) else None
        issues = []
        if scb_v is not None:
            if scb_v == 0:
                issues.append("StrongCertificateBindingEnforcement=0 (disabled)")
            elif scb_v == 1:
                issues.append("StrongCertificateBindingEnforcement=1 (compatibility mode)")
        if cmm_v is not None:
            try:
                if int(cmm_v) & 0x4:
                    issues.append(f"CertificateMappingMethods={cmm_v} includes UPN mapping")
            except (TypeError, ValueError):
                pass
        if issues:
            sev = "CRIT" if scb_v == 0 else "HIGH"
            out.append({"sev": sev, "name": f"ESC10: {n['name']}",
                        "detail": f"Weak DC certificate mapping ({'; '.join(issues)}) — UPN/DNS-SAN spoofed certs (ESC9/ESC16) will map to impersonated accounts"})
        netlogon = dcreg.get("VulnerableNetlogonSecurityDescriptor") or {}
        if isinstance(netlogon, dict) and netlogon.get("Value"):
            out.append({"sev": "MED", "name": f"{n['name']} netlogon SD",
                        "detail": f"Vulnerable Netlogon security descriptor on this DC: {str(netlogon['Value'])[:120]}"})

    # NTAuthStore control = rogue CA trust
    ntauth_writers = set()
    for sid, n in g.nodes.items():
        if n["kind"] != "NTAUTHSTORE":
            continue
        for src, dst, kind, inh in g.edges_to(sid):
            if not inh and kind in DANGEROUS_RIGHTS and not g.is_noise_principal(src):
                ntauth_writers.add(src)
                out.append({"sev": "CRIT", "name": f"{g.name(src)} --{kind}--> NTAuthStore",
                            "detail": f"{g.name(src)} can modify NTAuthCertificates — publish a rogue CA cert and forge domain authentication certificates"})

    # Golden Cert composite: control of a CA (or its host) + NTAuthStore trust
    ca_controllers = set()
    for ca_sid, ca in g.ca_data.items():
        # HostingComputer is a DNS name — resolve to the computer's SID so it
        # can be matched against edge destinations (which are SIDs)
        host_sid = g.dns_to_sid.get(_as_str(ca.get("hosting")).upper(), "")
        for tgt, rights in ((ca_sid, DANGEROUS_RIGHTS),
                            (host_sid, set(DANGEROUS_RIGHTS) | {"AdminTo"}) if host_sid else (None, ())):
            if not tgt:
                continue
            for src, dst, kind, inh in g.edges_to(tgt):
                if not inh and kind in rights and not g.is_noise_principal(src):
                    ca_controllers.add(src)
    if ntauth_writers and ca_controllers:
        both = ntauth_writers & ca_controllers
        if both:
            detail = (f"{', '.join(g.name(s) for s in list(both)[:5])} control(s) both a CA and the NTAuthStore — "
                      "steal the CA private key (DPAPI on the CA host) and forge certificates for any principal indefinitely")
        else:
            detail = (f"CA control: {', '.join(g.name(s) for s in list(ca_controllers)[:5])}; "
                      f"NTAuthStore control: {', '.join(g.name(s) for s in list(ntauth_writers)[:5])} — "
                      "combined, a Golden Cert path (forge certificates trusted domain-wide)")
        out.append({"sev": "CRIT", "name": "Golden Cert path viable", "detail": detail})
    # ESC5: dangerous control over any PKI object (CAs covered above; also
    # containers/AIACA/RootCA fall under this umbrella via Dangerous ACLs)
    # Coverage note for techniques not derivable from the collection
    has_adcs = bool(g.ca_data) or any(n["kind"] in ADCS_KINDS.values() for n in g.nodes.values())
    if has_adcs:
        out.append({"sev": "INFO", "name": "Coverage notes",
                    "detail": "ESC5 (generic PKI object ACLs) surfaces in the Dangerous ACLs section. "
                              "ESC12 (YubiHSM provider key exposure) is not collected by SharpHound — check the CA's CSP/KSP provider manually. "
                              "ESC14 surfaces as WriteAltSecurityIdentities edges in the Dangerous ACLs section."})
    return out


def find_weak_crypto(g):
    out = []
    locked = 0
    not_sensitive = []
    for sid, n in g.nodes.items():
        p = n["props"]
        if n["kind"] != "USER":
            continue
        if p.get("encryptedtextpwdallowed") and p.get("enabled", True):
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": "Reversible encryption enabled — plaintext recoverable from AD (Mimikatz DCSync / secretsdump after reset)"})
        if p.get("usedeskeyonly") and p.get("enabled", True):
            out.append({"sev": "MED", "name": n["name"],
                        "detail": "USE_DES_KEY_ONLY — Kerberos downgrades to single DES (crackable)"})
        if p.get("admincount") and p.get("enabled", True) and not p.get("sensitive"):
            not_sensitive.append(n["name"])
        if p.get("lockedout"):
            locked += 1
        if sid.endswith("-502") or n["name"].upper().startswith("KRBTGT@"):
            d = _epoch_to_date(p.get("pwdlastset"))
            if d:
                try:
                    age = (datetime.datetime.now(datetime.timezone.utc).timestamp() - int(p["pwdlastset"])) / 86400
                    if age > 365:
                        out.append({"sev": "MED", "name": n["name"],
                                    "detail": f"krbtgt password last changed {d} ({int(age/365)}y ago) — any golden ticket minted since then is still valid; also indicates old DCSync dumps retain value"})
                except (TypeError, ValueError):
                    pass
    # 'not sensitive' only matters when a TGT-capture host actually exists —
    # enumerating every such account otherwise is pure noise
    if not_sensitive:
        unconstrained = [n["name"] for n in g.nodes.values()
                         if n["kind"] == "COMPUTER" and n["props"].get("unconstraineddelegation")
                         and "OU=DOMAIN CONTROLLERS" not in _as_str(n["props"].get("distinguishedname")).upper()]
        if unconstrained:
            for name in not_sensitive:
                out.append({"sev": "MED", "name": name,
                            "detail": f"Privileged but NOT marked 'sensitive and cannot be delegated' — TGT capturable via the unconstrained-delegation host(s) present: {', '.join(unconstrained[:5])}"})
        else:
            out.append({"sev": "INFO", "name": f"{len(not_sensitive)} privileged accounts not marked 'sensitive and cannot be delegated'",
                        "detail": "No unconstrained-delegation hosts in this collection, so no immediate TGT-capture path — hygiene note only"})
    if locked:
        out.append({"sev": "INFO", "name": f"{locked} locked-out accounts",
                    "detail": "Currently locked out (lockout policy is being hit)"})
    return out


def find_stale_and_precreated(g):
    out = []
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    stale_users, stale_comps = [], []
    for sid, n in g.nodes.items():
        p = n["props"]
        ll = p.get("lastlogontimestamp") or p.get("lastlogon")
        try:
            ll = int(ll)
        except (TypeError, ValueError):
            ll = 0
        age_days = (now - ll) / 86400 if ll > 0 else None
        if n["kind"] == "USER" and p.get("enabled", True) and age_days and age_days > 90:
            stale_users.append((n["name"], int(age_days)))
        elif n["kind"] == "COMPUTER" and p.get("enabled", True):
            if age_days and age_days > 90:
                stale_comps.append((n["name"], int(age_days)))
            # pre-created machine account: password never set -> password is
            # lowercase name minus '$'. SharpHound converts FILETIME 0 -> 0 and
            # null -> -1 (Helpers.cs); require the property to be present so
            # collectors that omit it never trigger a false positive.
            if "pwdlastset" not in p:
                continue
            try:
                pls = int(p["pwdlastset"])
            except (TypeError, ValueError):
                continue
            sam = _as_str(p.get("samaccountname"))
            if pls <= 0 and sam.endswith("$") and not p.get("isdc"):
                out.append({"sev": "HIGH", "name": n["name"],
                            "detail": f"Pre-created computer account (password never set) — default password '{sam[:-1].lower()}'; try SMB/LDAP with it"})
    if stale_users:
        out.append({"sev": "INFO", "name": f"{len(stale_users)} stale enabled users (>90d)",
                    "detail": ", ".join(f"{n} ({d}d)" for n, d in sorted(stale_users, key=lambda x: -x[1])[:15]) + " — dormant accounts make quiet spray targets"})
    if stale_comps:
        out.append({"sev": "INFO", "name": f"{len(stale_comps)} stale computers (>90d)",
                    "detail": ", ".join(f"{n} ({d}d)" for n, d in sorted(stale_comps, key=lambda x: -x[1])[:10])})
    return out


def find_moderate_groups(g):
    out = []
    for sid, n in g.nodes.items():
        if n["kind"] != "GROUP":
            continue
        label, note = None, None
        for suffix, (gname, gnote) in MODERATE_GROUP_RIDS.items():
            if sid.endswith(suffix):
                label, note = gname, gnote
                break
        if label is None:
            short = n["name"].upper().split("@", 1)[0].strip()
            if short in MODERATE_GROUP_NAMES:
                label, note = n["name"], MODERATE_GROUP_NAMES[short]
        if label is None:
            continue
        members = [g.name(m) for m in g.groups_members.get(sid, [])]
        # skip default/noise members for the builtin ops groups
        members = [m for m in members if m.upper() not in
                   ("ENTERPRISE ADMINS", "DOMAIN ADMINS") and not m.upper().startswith("EXCHANGE ")]
        if members:
            out.append({"sev": "MED", "name": f"{label} ({len(members)} members)",
                        "detail": f"{note}: {', '.join(sorted(members)[:12])}"})
    # Protected Users coverage: tier-0 members missing from RID 525
    for sid, n in g.nodes.items():
        if n["kind"] == "GROUP" and sid.endswith("-525"):
            protected = set(g.groups_members.get(sid, []))
            tier0 = g.tier0_member_sids()
            missing = [g.name(m) for m in tier0 - protected
                       if g.nodes.get(m, {}).get("kind") == "USER"]
            out.append({"sev": "INFO", "name": f"Protected Users ({len(protected)} members)",
                        "detail": "members are immune to NTLM/DES/RC4 and delegation"})
            if missing := sorted(missing):
                out.append({"sev": "MED", "name": f"{len(missing)} tier-0 users NOT in Protected Users",
                            "detail": f"{', '.join(missing[:12])} — their creds remain usable via NTLM/RC4 and can be delegated; add them to Protected Users"})
            break
    return out


def find_foreign_edges(g):
    """Non-inherited control edges where principal and target live in different domains."""
    interesting = set(DANGEROUS_RIGHTS) | DCSYNC_RIGHTS | {"AdminTo", "MemberOf"}
    out = []
    for src, dst, kind, inh in g.edges:
        if inh or kind not in interesting or src == dst:
            continue
        if "-" not in src or "-" not in dst:
            continue
        # same domain if either SID is a prefix of the other (domain-root SIDs
        # like S-1-5-21-X have one fewer component than object SIDs)
        if src.rsplit("-", 1)[0] == dst.rsplit("-", 1)[0] \
                or dst.startswith(src + "-") or src.startswith(dst + "-"):
            continue
        if src.startswith("S-1-5-32") or src in LOW_PRIV_SIDS or src == "S-1-5-18":
            continue
        if kind == "MemberOf":
            tgt = g.nodes.get(dst, {})
            if not tgt.get("props", {}).get("highvalue"):
                continue
        out.append({"sev": "HIGH" if kind in ("GenericAll", "WriteDacl", "WriteOwner") else "MED",
                    "name": f"{g.name(src)} --{kind}--> {g.name(dst)}",
                    "detail": f"Cross-domain edge: {g.name(src)} (foreign) has {kind} on {g.name(dst)}"})
    return out



def find_relay_surface(g):
    """Coercion/NTLM-relay surface: WebClient (HTTP coercion) and unsigned SMB."""
    out = []
    for sid, n in g.nodes.items():
        if n["kind"] != "COMPUTER":
            continue
        p = n["props"]
        if p.get("_webclient") is True:
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": "WebClient service running — coerce this host to authenticate over HTTP (PetitPotam/DFSCoerce) and relay to LDAP/ADCS web enrollment (ESC8)"})
        if p.get("_smb_signing") is False:
            out.append({"sev": "MED", "name": n["name"],
                        "detail": "SMB signing not required — NTLM relay target"})
        # NTLMv1 / weak NTLM policy (only when the value was explicitly collected)
        ntlm = p.get("_ntlmreg")
        if isinstance(ntlm, dict):
            lmcomp = ntlm.get("LmCompatibilityLevel")
            if lmcomp is not None:
                try:
                    lm = int(lmcomp)
                except (TypeError, ValueError):
                    lm = 99
                if lm <= 2:
                    is_dc = bool(p.get("isdc")) or "OU=DOMAIN CONTROLLERS" in _as_str(p.get("distinguishedname")).upper()
                    out.append({"sev": "HIGH" if is_dc else "MED", "name": n["name"],
                                "detail": f"LmCompatibilityLevel={lm} — accepts NTLMv1 (and possibly LM): crackable via rainbow tables, enables downgrade/relay. "
                                          + ("On a DC this exposes the whole domain." if is_dc else "")})
    return out


def _ci(d, key):
    """Case-insensitive dict lookup (AzureHound uses camelCase)."""
    if not isinstance(d, dict):
        return None
    kl = key.lower()
    for k, v in d.items():
        if isinstance(k, str) and k.lower() == kl:
            return v
    return None


def _build_az_index(az_docs):
    """Index AzureHound objects: id -> {kind, name, onprem, raw}; plus Entra
    directory role assignments, tenant names, and per-kind counts."""
    az_objs = {}
    role_assignments = []
    tenants = []
    kind_counts = defaultdict(int)
    for fname, doc in az_docs:
        kind = doc_kind(doc, fname)
        for o in doc_objects(doc):
            kind_counts[kind] += 1
            oid = _as_str(_ci(o, "id")).upper()
            dname = (_ci(o, "displayName") or _ci(o, "userPrincipalName")
                     or _ci(o, "onPremisesSamAccountName") or _ci(o, "name") or oid or "?")
            if not isinstance(dname, str):
                dname = oid or "?"
            onprem = _as_str(_ci(o, "onPremisesSecurityIdentifier")).upper()
            if oid:
                az_objs[oid] = {"kind": kind, "name": dname, "onprem": onprem, "raw": o}
            if kind == "aztenants":
                tenants.append(dname)
            rd = _ci(o, "roleDefinitionId")
            pr = _ci(o, "principalId")
            sub = _ci(o, "properties") or {}
            rd = rd or _ci(sub, "roleDefinitionId")
            pr = pr or _ci(sub, "principalId")
            if rd and pr:
                role_assignments.append((str(pr).upper(), str(rd).upper()))
    return az_objs, role_assignments, tenants, kind_counts


def find_hybrid(g, az_docs):
    """Entra ID / hybrid analysis: synced identities and privileged cloud roles."""
    out = []
    if not az_docs:
        return out

    az_objs, role_assignments, tenants, kind_counts = _build_az_index(az_docs)

    if tenants:
        out.append({"sev": "INFO", "name": f"{len(tenants)} tenant(s): {', '.join(tenants)}",
                    "detail": "Entra ID objects analyzed: " + ", ".join(f"{k}={v}" for k, v in sorted(kind_counts.items()))})

    # synced identities: Entra object with an on-prem SID present in the AD graph
    synced_priv, synced_total = [], 0
    for oid, o in az_objs.items():
        if not o["onprem"] or o["onprem"] not in g.nodes:
            continue
        synced_total += 1
        onprem_node = g.nodes[o["onprem"]]
        pp = onprem_node["props"]
        priv = pp.get("highvalue") or pp.get("admincount")
        if not priv:
            priv = o["onprem"] in g.tier0_member_sids()
        if priv:
            synced_priv.append((o["name"], onprem_node["name"], o["kind"]))
    for azname, adname, azkind in synced_priv:
        out.append({"sev": "HIGH", "name": f"{azname} (synced)",
                    "detail": f"Entra {azkind} synced from privileged on-prem account {adname} — on-prem credential compromise extends to Entra ID (and vice versa)"})
    if synced_total:
        out.append({"sev": "INFO", "name": f"{synced_total} synced identities matched to on-prem objects",
                    "detail": f"{len(synced_priv)} of them are privileged on-prem"})

    # privileged Entra roles
    role_name_by_id = {}
    for oid, o in az_objs.items():
        if o["kind"] not in ("azroles", "azrole", "azroledefinitions"):
            continue
        tid = _as_str(_ci(o["raw"], "templateId")).upper() if "raw" in o else ""
        disp = _ci(o.get("raw") or {}, "displayName") or o["name"]
        role_name_by_id[oid] = disp
        if tid in PRIV_ENTRA_ROLES:
            role_name_by_id[oid] = PRIV_ENTRA_ROLES[tid][0]
    # also index by templateId (assignments sometimes reference it directly)
    holders = defaultdict(list)  # role display -> [(holder_name, synced_ad)]
    priv_role_names = {v[0] for v in PRIV_ENTRA_ROLES.values()}
    priv_role_sev = {v[0]: v[1] for v in PRIV_ENTRA_ROLES.values()}
    for pr_id, rd_id in role_assignments:
        rname = role_name_by_id.get(rd_id)
        if not rname and rd_id in PRIV_ENTRA_ROLES:
            rname = PRIV_ENTRA_ROLES[rd_id][0]
        if not rname or rname not in priv_role_names:
            continue
        holder = az_objs.get(pr_id, {})
        hname = holder.get("name", pr_id)
        synced = g.nodes.get(holder.get("onprem", ""), {}).get("name")
        holders[rname].append((hname, synced))
    for rname, hs in holders.items():
        sev = priv_role_sev[rname]
        names = ", ".join(f"{h}{' [SYNCED->' + s + ']' if s else ''}" for h, s in hs[:10])
        out.append({"sev": sev, "name": f"Entra role: {rname} ({len(hs)} holder(s))",
                    "detail": f"{names} — full control over the tenant" if rname == "Global Administrator"
                              else f"{names}"})
        for h, s in hs:
            if s:
                out.append({"sev": "CRIT", "name": f"{h} holds {rname} and is synced",
                            "detail": f"On-prem account {s} syncs to an Entra identity holding {rname} — compromising the on-prem password/hash gives tenant-wide cloud control"})
    return out


def find_azure_rbac(g, az_docs):
    """Deep Azure RBAC: ARM role assignments, Key Vault access policies,
    and dangerous MS Graph app roles. Precision-first: only well-known
    role/permission GUIDs are flagged; anything else is ignored."""
    out = []
    if not az_docs:
        return out
    az_objs, _, _, _ = _build_az_index(az_docs)

    def holder_label(pid):
        h = az_objs.get(pid, {})
        name = h.get("name", pid)
        onprem_sid = h.get("onprem", "")
        note = ""
        if onprem_sid and onprem_sid in g.nodes:
            note = f" [SYNCED from on-prem {g.nodes[onprem_sid]['name']}]"
        kind = h.get("kind", "")
        if "serviceprincipal" in kind.lower():
            note += " [service principal — app credential leak grants this]"
        return name + note

    # --- ARM role assignments (AzureRoleAssignments: {objectId: resource, assignees: [...]}) ---
    rbac = defaultdict(list)  # (role_name, sev, resource) -> [holder labels]
    for fname, doc in az_docs:
        for o in doc_objects(doc):
            assignees = _ci(o, "assignees")
            if not isinstance(assignees, list):
                continue
            resource = _as_str(_ci(o, "objectId")).upper()
            rname = az_objs.get(resource, {}).get("name") or resource or "?"
            for a in assignees:
                if not isinstance(a, dict):
                    continue
                roledef = str(_ci(a, "roleDefinitionId") or "").lower()
                guid = roledef.rsplit("/", 1)[-1]
                entry = ARM_ROLES.get(guid)
                if not entry:
                    continue
                pid = _as_str(_ci(a, "objectId")).upper()
                if not pid:
                    sub = _ci(_ci(a, "assignee") or {}, "properties") or {}
                    pid = _as_str(_ci(sub, "principalId")).upper()
                if not pid:
                    continue
                rbac[(entry[0], entry[1], rname)].append(holder_label(pid))
    for (role, sev, resource), holders in sorted(rbac.items(), key=lambda x: SEV_ORDER.get(x[0][1], 9)):
        out.append({"sev": sev,
                    "name": f"{role} on {resource} ({len(holders)} holder(s))",
                    "detail": "; ".join(sorted(set(holders))[:8])})

    # --- Dangerous MS Graph app roles assigned to principals (usually SPs) ---
    for fname, doc in az_docs:
        for o in doc_objects(doc):
            app_role = str(_ci(o, "appRoleId") or "").lower()
            if not app_role or app_role not in GRAPH_APP_ROLES:
                continue
            res = str(_ci(o, "resourceId") or "").lower()
            if res and res != MS_GRAPH_SP_ID:
                continue  # appRoleId GUIDs are Graph-scoped; anything else is a mismatch
            pid = _as_str(_ci(o, "principalId")).upper()
            pname = _ci(o, "principalDisplayName") or holder_label(pid) or pid
            role_name, sev = GRAPH_APP_ROLES[app_role]
            out.append({"sev": sev, "name": f"{pname} holds Graph {role_name}",
                        "detail": f"App role {role_name} on MS Graph — tenant-wide impact (grant roles / add app credentials / write directory)"})

    # --- Key Vault access policies with secret/key read ---
    for fname, doc in az_docs:
        if doc_kind(doc, fname) not in ("azkeyvaults", "azkeyvault"):
            continue
        for o in doc_objects(doc):
            vault = _ci(o, "name") or _ci(o, "displayName") or _ci(o, "id") or "?"
            props = _ci(o, "properties") or {}
            for ap in _ci(props, "accessPolicies") or []:
                perms = _ci(ap, "permissions") or {}
                readable = [p for p in ((_ci(perms, "secrets") or []) + (_ci(perms, "keys") or []))
                            if str(p).lower() in ("get", "list", "all")]
                if not readable:
                    continue
                pid = _as_str(_ci(ap, "objectId")).upper()
                out.append({"sev": "HIGH",
                            "name": f"{holder_label(pid)} can read Key Vault {vault}",
                            "detail": f"Access policy grants {sorted(set(str(p) for p in readable))} on secrets/keys of {vault} — pull stored credentials/connection strings"})
    return out



def find_stealth(g):
    """Hidden memberships, SID history, built-in account abuse, sync seams."""
    out = []
    # Hidden primary-group memberships (invisible in Members[])
    for member, grp in g.hidden_primary_groups:
        mn, gn = g.name(member), g.name(grp)
        gnode = g.nodes.get(grp, {})
        sev = "CRIT" if grp.endswith(("-512", "-519", "-518")) or gnode.get("props", {}).get("highvalue") else "MED"
        out.append({"sev": sev, "name": f"{mn} => {gn} (primary group)",
                    "detail": f"{mn} has primaryGroupID set to {gn} — this membership does NOT appear in the group's member list (stealth membership; survives most audits)"})
    # Enabled Guest
    for sid, n in g.nodes.items():
        if n["kind"] == "USER" and sid.endswith("-501") and n["props"].get("enabled"):
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": "Built-in Guest account is ENABLED — anonymous/null-session access likely possible"})
    # SID history
    for sid, n in g.nodes.items():
        hist = _as_list(n["props"].get("sidhistory"))
        if hist and n["props"].get("enabled", True):
            out.append({"sev": "HIGH", "name": n["name"],
                        "detail": f"Carries SID history: {', '.join(str(h) for h in hist[:5])} — inherits old domain privileges; check for foreign/tier-0 SIDs"})
    # Entra Connect / SSO seams
    for sid, n in g.nodes.items():
        p = n["props"]
        nm = n["name"].upper()
        if n["kind"] == "USER" and (nm.startswith("MSOL_") or nm.startswith("AAD_") and "CONNECT" in _as_str(p.get("description")).upper()):
            if p.get("enabled", True):
                out.append({"sev": "HIGH", "name": n["name"],
                            "detail": "Entra Connect sync account — typically holds DCSync rights and is often overprivileged; prime credential target"})
        if n["kind"] == "COMPUTER" and nm.startswith("AZUREADSSOACC"):
            # only assess rotation age when the timestamp was actually collected
            if "pwdlastset" not in p:
                continue
            d = _epoch_to_date(p.get("pwdlastset"))
            try:
                age = (datetime.datetime.now(datetime.timezone.utc).timestamp() - int(p["pwdlastset"])) / 86400
            except (TypeError, ValueError):
                age = 9999
            if age > 30:
                out.append({"sev": "HIGH", "name": n["name"],
                            "detail": f"Entra Seamless SSO computer account password last rotated {d or 'never'} — the AZUREADSSOACC Kerberos key decrypts cloud SSO tickets; if dumped, mint silver tickets for cloud access (rotate every 30d)"})
    return out


def find_anomalies(g):
    """Orphan SIDs with control, recently-created tier-0 objects."""
    out = []
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    unresolved = defaultdict(list)
    for src, dst, kind, inh in g.edges:
        if inh or kind not in DANGEROUS_RIGHTS or g.is_noise_principal(src):
            continue
        n = g.nodes.get(src)
        if not n or n["name"] == src:  # never resolved to an object
            unresolved[src].append((kind, g.name(dst)))
    for sid, edges in list(unresolved.items())[:10]:
        out.append({"sev": "MED", "name": f"Unresolved SID {sid}",
                    "detail": f"Holds {len(edges)} dangerous right(s) but no matching object in the collection (deleted/foreign account): {edges[0][0]} -> {edges[0][1]} — orphaned SIDs can be reclaimed via SID history"})
    for sid, n in g.nodes.items():
        p = n["props"]
        if not (p.get("highvalue") or p.get("admincount")):
            continue
        try:
            wc = int(p.get("whencreated") or 0)
        except (TypeError, ValueError):
            continue
        if wc > 0 and (now - wc) < 30 * 86400:
            out.append({"sev": "INFO", "name": n["name"],
                        "detail": f"Privileged object created {_epoch_to_date(wc)} (last 30 days) — verify this was an authorized change"})
    return out



# --------------------------------------------------------------------------
# Pathfinding (BFS shortest paths to high-value targets)
# --------------------------------------------------------------------------
def bfs_paths(g, start_sids, max_depth=8, max_paths=5):
    """Return list of paths (each a list of (name, edge_kind, name)) from any
    start sid to any high-value node."""
    adj = g.traversable_adj()

    targets = {sid for sid, n in g.nodes.items()
               if n["props"].get("highvalue") or
               (n["kind"] == "GROUP" and sid.endswith(("-512", "-519", "-518")))}
    targets -= set(start_sids)
    if not targets:
        return []

    # BFS from all starts simultaneously; record parent for shortest tree
    parent = {}   # sid -> (prev_sid, edge_kind)
    depth = {}
    dq = deque()
    for s in start_sids:
        parent[s] = None
        depth[s] = 0
        dq.append(s)

    hit_targets = []
    while dq:
        cur = dq.popleft()
        if depth[cur] >= max_depth:
            continue
        for nxt, kind in adj.get(cur, []):
            if nxt in parent:
                continue
            parent[nxt] = (cur, kind)
            depth[nxt] = depth[cur] + 1
            if nxt in targets:
                hit_targets.append(nxt)
                if len(hit_targets) >= max_paths:
                    dq.clear()
                    break
            dq.append(nxt)

    paths = []
    for t in sorted(hit_targets, key=lambda x: depth[x]):
        chain = []
        node = t
        while parent.get(node):
            prev, kind = parent[node]
            chain.append((g.name(prev), kind, g.name(node)))
            node = prev
        chain.reverse()
        paths.append({"depth": depth[t], "target": g.name(t), "chain": chain})
    return paths


def reachable_count(g, start_sids, max_depth=8):
    adj = g.traversable_adj()
    seen = set(start_sids)
    dq = deque((s, 0) for s in start_sids)
    while dq:
        cur, d = dq.popleft()
        if d >= max_depth:
            continue
        for nxt, _ in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                dq.append((nxt, d + 1))
    return len(seen)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_section(title, findings, limit):
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["sev"], 9))
    print(f"\n{C.BOLD}{C.CYAN}== {title} ({len(findings)}) =={C.RESET}")
    if not findings:
        print("   (none found)")
        return findings
    for f in findings[:limit]:
        line = f"   {tag(f['sev'])} {f['name']}"
        if f.get("detail") and f["detail"] != f["name"]:
            line += f"\n        {C.DIM}{f['detail']}{C.RESET}"
        print(line)
    if len(findings) > limit:
        print(f"   ... {len(findings) - limit} more (use --full or --limit to expand)")
    return findings


def main():
    ap = argparse.ArgumentParser(
        description="Fully offline BloodHound collection analyzer (stdlib only).")
    ap.add_argument("--data", required=True, nargs="+",
                    help="SharpHound zip(s), directory of JSONs, or single JSON file")
    ap.add_argument("--user", action="append", default=[],
                    help="Starting/owned principal (name, SAM, or SID). Repeatable.")
    ap.add_argument("--owned", type=Path,
                    help="File with one owned principal per line")
    ap.add_argument("--paths", action="store_true",
                    help="Always print the attack-path section (still needs --user/--owned to resolve a start)")
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--max-paths", type=int, default=5)
    ap.add_argument("--limit", type=int, default=15,
                    help="Max findings printed per section (default 15)")
    ap.add_argument("--full", action="store_true", help="No truncation of findings")
    ap.add_argument("--json", type=Path, help="Write full findings as JSON to this file")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--include-inherited", action="store_true",
                    help="Include inherited ACEs in analysis (noisy)")
    args = ap.parse_args()

    global USE_COLOR
    USE_COLOR = not args.no_color and sys.stdout.isatty()
    if not USE_COLOR:
        for attr in ("RED", "YELLOW", "GREEN", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(C, attr, "")
    limit = 10**9 if args.full else args.limit

    docs = load_documents(args.data)
    if not docs:
        print("[!] No JSON documents loaded — check --data path.", file=sys.stderr)
        sys.exit(1)

    g = Graph()
    az_docs = []
    skipped = 0
    for name, doc in docs:
        if not doc_objects(doc):
            skipped += 1  # not a collection file (e.g. a prior --json report)
            continue
        k = doc_kind(doc, name)
        if k.startswith("az"):
            az_docs.append((name, doc))
            continue
        g.ingest(name, doc)

    if not args.include_inherited:
        g.edges = [e for e in g.edges if not e[3] or e[2] == "MemberOf"]
    g.finalize()

    n_users = sum(1 for n in g.nodes.values() if n["kind"] == "USER")
    n_groups = sum(1 for n in g.nodes.values() if n["kind"] == "GROUP")
    n_comps = sum(1 for n in g.nodes.values() if n["kind"] == "COMPUTER")
    n_domains = sum(1 for n in g.nodes.values() if n["kind"] == "DOMAIN")

    n_ad = len(docs) - skipped - len(az_docs)
    print(f"{C.BOLD}[Wayfinder v{VERSION}]{C.RESET} loaded {n_ad} collection file(s)")
    print(f"  Objects: {n_users} users, {n_groups} groups, {n_comps} computers, "
          f"{n_domains} domains | Edges: {len(g.edges)}")
    if az_docs:
        n_az = sum(len(doc_objects(d)) for _, d in az_docs)
        print(f"  Entra ID: {n_az} object(s) across {len(az_docs)} file(s) — hybrid analysis enabled")

    sections = {}
    sections["Domains & Trusts"] = find_trusts(g)
    sections["Domain Password & Lockout Policy"] = find_domain_policy(g)
    sections["Kerberoastable Accounts"] = find_kerberoastable(g)
    sections["AS-REP Roastable Accounts"] = find_asrep(g)
    sections["Delegation Abuse"] = find_delegation(g)
    sections["DCSync Rights"] = find_dcsync(g)
    sections["ADCS Abuse (ESC1-11, 13, 15, 16)"] = find_adcs(g)
    sections["Tier-0 Group Membership"] = find_tier0_groups(g)
    sections["Moderately-Privileged Groups"] = find_moderate_groups(g)
    sections["Stealth & Hidden Memberships"] = find_stealth(g)
    sections["Anomalies (orphan SIDs, new tier-0 objects)"] = find_anomalies(g)
    sections["Dangerous ACLs (non-inherited, noise-filtered)"] = find_dangerous_acls(g)
    sections["Cross-Domain Control Edges"] = find_foreign_edges(g)
    sections["GPO Control"] = find_gpo_control(g)
    sections["Privileged User Sessions"] = find_privileged_sessions(g)
    sections["NTLM Relay Surface"] = find_relay_surface(g)
    sections["Non-standard Local Admins"] = find_adminto(g)
    sections["LAPS & gMSA Readers"] = find_laps(g)
    sections["Computers / OS"] = find_computers(g)
    sections["Password Hygiene"] = find_password_hygiene(g)
    sections["Weak Crypto & UAC Flags"] = find_weak_crypto(g)
    sections["Stale & Pre-created Accounts"] = find_stale_and_precreated(g)
    sections["Descriptions & Password Attributes"] = find_descriptions(g)
    sections["AdminCount Drift"] = find_admincount_drift(g)
    if az_docs:
        sections["Hybrid / Entra ID"] = find_hybrid(g, az_docs)
        sections["Azure RBAC & Graph Permissions"] = find_azure_rbac(g, az_docs)

    for title, findings in sections.items():
        sorted_f = print_section(title, findings, limit)
        sections[title] = sorted_f
        # print OS histograms inline
        for f in sorted_f:
            if f.get("os_histogram"):
                for osname, cnt in list(f["os_histogram"].items())[:10]:
                    print(f"        {cnt:>4}  {osname}")

    # ---- path analysis ----
    start_labels = list(args.user)
    if args.owned and args.owned.is_file():
        start_labels += [l.strip() for l in args.owned.read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
    start_sids = []
    for lbl in start_labels:
        sid = g.resolve(lbl)
        if sid:
            start_sids.append(sid)
        else:
            print(f"[!] could not resolve principal: {lbl}", file=sys.stderr)

    paths = []
    if start_sids or args.paths:
        print(f"\n{C.BOLD}{C.CYAN}== Attack Paths to High-Value Targets =={C.RESET}")
        if not start_sids:
            print("   (no starting principals resolved — pass --user or --owned)")
        else:
            reach = reachable_count(g, start_sids, args.max_depth)
            print(f"   From {len(start_sids)} start(s): {reach} objects reachable "
                  f"within {args.max_depth} traversable edges")
            paths = bfs_paths(g, start_sids, args.max_depth, args.max_paths)
            if not paths:
                print("   No traversable path to a high-value target found.")
            for i, p in enumerate(paths, 1):
                print(f"\n   {C.BOLD}Path #{i}{C.RESET} — {p['depth']} hop(s) to {C.RED}{p['target']}{C.RESET}")
                for src, kind, dst in p["chain"]:
                    print(f"        {src}  {C.YELLOW}--[{kind}]-->{C.RESET}  {dst}")

    # Default-population paths: what can EVERY domain user reach?
    default_pop = [sid for sid, n in g.nodes.items()
                   if n["kind"] == "GROUP" and
                   (sid.endswith("-513") or sid in ("S-1-1-0", "S-1-5-11"))]
    if default_pop:
        pop_paths = bfs_paths(g, default_pop, args.max_depth, 3)
        print(f"\n{C.BOLD}{C.CYAN}== Paths from Default Populations (Domain Users / Everyone) =={C.RESET}")
        if not pop_paths:
            print("   No traversable path from a default population to a high-value target. Good.")
        else:
            for i, p in enumerate(pop_paths, 1):
                print(f"\n   {C.BOLD}Path #{i}{C.RESET} — {p['depth']} hop(s) to {C.RED}{p['target']}{C.RESET} "
                      f"(usable by ANY domain account)")
                for src, kind, dst in p["chain"]:
                    print(f"        {src}  {C.YELLOW}--[{kind}]-->{C.RESET}  {dst}")
            for p in pop_paths:
                paths.append({**p, "from": "default-population"})

    # ---- quick wins summary ----
    print(f"\n{C.BOLD}{C.GREEN}== Quick Wins (numbered) =={C.RESET}")
    wins = []
    for title in ("DCSync Rights", "ADCS Abuse (ESC1-11, 13, 15, 16)",
                  "Delegation Abuse", "Domain Password & Lockout Policy",
                  "AS-REP Roastable Accounts", "Kerberoastable Accounts",
                  "Dangerous ACLs (non-inherited, noise-filtered)",
                  "Cross-Domain Control Edges", "GPO Control",
                  "Privileged User Sessions", "NTLM Relay Surface",
                  "Weak Crypto & UAC Flags", "Hybrid / Entra ID",
                  "Azure RBAC & Graph Permissions",
                  "Stealth & Hidden Memberships", "Anomalies (orphan SIDs, new tier-0 objects)",
                  "Stale & Pre-created Accounts", "LAPS & gMSA Readers",
                  "Descriptions & Password Attributes"):
        for f in sections.get(title, []):
            if f["sev"] in ("CRIT", "HIGH"):
                wins.append((title, f))
    wins.sort(key=lambda x: SEV_ORDER.get(x[1]["sev"], 9))
    if not wins:
        print("   No CRIT/HIGH quick wins identified — review MED/INFO sections manually.")
    for i, (title, f) in enumerate(wins[:20], 1):
        print(f"  [{i:>2}] {tag(f['sev'])} {title}: {f['name']}")
    if len(wins) > 20:
        print(f"   ... {len(wins) - 20} more")

    # ---- optional JSON dump ----
    if args.json:
        def clean(findings):
            return [{k: v for k, v in f.items() if not isinstance(v, set)} for f in findings]
        payload = {
            "version": VERSION,
            "stats": {"users": n_users, "groups": n_groups, "computers": n_comps,
                      "domains": n_domains, "edges": len(g.edges)},
            "trusts": g.trusts,
            "sections": {t: clean(f) for t, f in sections.items()},
            "paths": [{"depth": p["depth"], "target": p["target"],
                       "chain": [{"from": a, "edge": k, "to": b}
                                 for a, k, b in p["chain"]]} for p in paths],
            "quick_wins": [{"section": t, **{k: v for k, v in f.items() if k != "os_histogram"}}
                           for t, f in wins],
        }
        try:
            args.json.write_text(json.dumps(payload, indent=2, default=str))
        except OSError as e:
            print(f"[!] could not write JSON report: {e}", file=sys.stderr)
        else:
            print(f"\n[+] JSON findings written to {args.json}")


if __name__ == "__main__":
    main()
