"""Build an AttackGraph from any AuditData.

Generic — does NOT hard-code any client-specific principal name. Edges are
derived from data already loaded by ``report.data.load_audit_data``:

  - inventory/users.csv          → User nodes + AdminCount + SPN attrs
  - inventory/groups.csv         → Group nodes
  - inventory/dcs.csv            → DC computer nodes (Tier 0)
  - inventory/privileged_accounts.csv → MemberOf edges (Group -> User)
  - txt_files["domain_admins"]   → membership fallback
  - txt_files["enterprise_admins"]
  - txt_files["schema_admins"]
  - txt_files["accounts_userPrivileged"]
  - txt_files["DCSyncRights"]    → DCSync edges to Domain root / AdminSDHolder
  - txt_files["UnconstrainedDelegation"], ConstrainedDelegation, RBCD
  - txt_files["ShadowCredentials"]
  - txt_files["SPNs"]            → kerberoastable users
  - txt_files["ASREP"]
  - txt_files["vulnerable_templates"] → ESC4 enrollment edges
  - evidence/domain.json         → domain FQDN to label root node

Tiering heuristic (data-driven, no client-specific names):
  T0 = Domain root, DA/EA/SA groups + members, krbtgt, AdminSDHolder, DCs,
       Cert Publishers (since they own ADCS issuance)
  T1 = Account/Backup/Server/Print Operators, DnsAdmins, AdminCount=1 not in T0
  T2 = Privileged users (accounts_userPrivileged) not in T0/T1, GPO managers
  T3 = Authenticated Users (synthetic) — universal source
"""
from __future__ import annotations

import re

from .model import (
    AttackGraph, Edge, EdgeKind, Node, NodeKind, Tier,
)

# Built-in group-to-tier classification. Generic, applies to any English/Spanish
# AD installation. Schema names always English regardless of UI locale.
_T0_GROUPS = {
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Domain Controllers", "Enterprise Read-only Domain Controllers",
    "Read-only Domain Controllers", "Cert Publishers",
    "Group Policy Creator Owners", "Replicator",
    "Pre-Windows 2000 Compatible Access",
}
_T1_GROUPS = {
    "Account Operators", "Backup Operators", "Server Operators",
    "Print Operators", "DnsAdmins", "DnsUpdateProxy",
    "Remote Desktop Users",  # if granted on DCs/admin servers
}

# Pseudo-source — any authenticated principal in the domain
_PSEUDO_AUTH_USERS = "pseudo:AuthenticatedUsers"
_PSEUDO_DOMAIN_USERS = "pseudo:DomainUsers"


def _norm(s: str) -> str:
    """Canonicalise a principal name to lower-case, no domain prefix."""
    s = (s or "").strip()
    if "\\" in s:
        s = s.split("\\", 1)[1]
    return s.lower()


def _tier_for_group(name: str) -> Tier:
    if name in _T0_GROUPS:
        return Tier.T0
    if name in _T1_GROUPS:
        return Tier.T1
    return Tier.T2


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_attack_graph(data) -> AttackGraph:
    """Construct an AttackGraph from a fully-loaded AuditData."""
    g = AttackGraph()

    _add_pseudo_sources(g)
    domain_node_id = _add_domain_node(g, data)
    _add_priv_groups(g)                     # known T0/T1 groups
    _add_users_from_inventory(g, data)      # User nodes + attrs
    _add_dc_nodes(g, data)                  # T0 DC computer nodes

    # Edges
    _edges_memberof_from_priv_csv(g, data)
    _edges_memberof_from_txt(g, data)
    _edges_dcsync(g, data, domain_node_id)
    _edges_kerberoastable(g, data)
    _edges_asrep(g, data)
    _edges_shadow_credentials(g, data)
    _edges_unconstrained_delegation(g, data)
    _edges_rbcd(g, data)
    _edges_esc4_templates(g, data)

    # Promote T0 transitively: any user member of a T0 group is T0
    _promote_t0_transitively(g)

    # Drop orphan nodes (no in/out edges) — they clutter the SVG and
    # add nothing to path-finding.
    _prune_orphans(g)

    return g


def _prune_orphans(g: AttackGraph) -> None:
    """Remove nodes that have neither incoming nor outgoing edges, EXCEPT for
    pseudo-sources and Tier-0 anchor nodes (so the graph still shows the
    target ring even if no path reaches it)."""
    KEEP_KINDS = {NodeKind.PSEUDO, NodeKind.DOMAIN, NodeKind.DC}
    referenced: set[str] = set()
    for e in g.edges:
        referenced.add(e.src_id)
        referenced.add(e.dst_id)
    drop = [
        nid for nid, n in g.nodes.items()
        if nid not in referenced
        and n.kind not in KEEP_KINDS
        and not n.is_tier0       # always keep T0 anchors so user sees targets
    ]
    for nid in drop:
        g.nodes.pop(nid, None)


# ---------------------------------------------------------------------------
# Node builders
# ---------------------------------------------------------------------------

def _add_pseudo_sources(g: AttackGraph) -> None:
    g.add_node(Node(
        id=_PSEUDO_AUTH_USERS, label="Authenticated Users",
        kind=NodeKind.PSEUDO, tier=Tier.T3,
        attrs={"description": "Cualquier usuario autenticado del dominio"}))
    g.add_node(Node(
        id=_PSEUDO_DOMAIN_USERS, label="Domain Users",
        kind=NodeKind.PSEUDO, tier=Tier.T3,
        attrs={"description": "Grupo por defecto que contiene a todos los usuarios"}))


def _add_domain_node(g: AttackGraph, data) -> str:
    dom = data.evidence.get("domain", {}) or {}
    fqdn = dom.get("domain_name") or data.execution.get("domain_name") or "DOMAIN"
    node_id = f"domain:{fqdn.lower()}"
    g.add_node(Node(
        id=node_id, label=fqdn, kind=NodeKind.DOMAIN, tier=Tier.T0,
        attrs={"description": "Raiz del dominio (DC=...)"}))
    # AdminSDHolder also a T0 sink
    g.add_node(Node(
        id="object:AdminSDHolder", label="AdminSDHolder",
        kind=NodeKind.DOMAIN, tier=Tier.T0,
        attrs={"description": "ACL plantilla de objetos protegidos (DA/EA/...)"}))
    # krbtgt
    g.add_node(Node(
        id="user:krbtgt", label="krbtgt", kind=NodeKind.USER, tier=Tier.T0,
        attrs={"description": "Cuenta del KDC; su hash forja Golden Tickets"}))
    return node_id


def _add_priv_groups(g: AttackGraph) -> None:
    for grp in _T0_GROUPS:
        g.add_node(Node(id=f"group:{grp}", label=grp, kind=NodeKind.GROUP, tier=Tier.T0))
    for grp in _T1_GROUPS:
        g.add_node(Node(id=f"group:{grp}", label=grp, kind=NodeKind.GROUP, tier=Tier.T1))


def _add_users_from_inventory(g: AttackGraph, data) -> None:
    """Only add users that matter for the graph: AdminCount=1, with SPN, with
    ASREP-roastable flag, or with non-default attributes. Regular users join
    via the synthetic `Authenticated Users` source rather than as discrete
    nodes — keeps the SVG legible."""
    for row in data.inventory.get("users", []):
        sam = (row.get("SamAccountName") or "").strip()
        if not sam:
            continue
        is_admin = row.get("AdminCount", "0") == "1"
        has_spn  = bool((row.get("SPNs") or "").strip())
        no_pre   = row.get("DoesNotRequirePreAuth", "False") == "True"
        if not (is_admin or has_spn or no_pre):
            continue
        attrs = {
            "WhenCreated": row.get("WhenCreated", ""),
            "PasswordLastSet": row.get("PasswordLastSet", ""),
            "LastLogonDate": row.get("LastLogonDate", ""),
            "AdminCount": row.get("AdminCount", "0") == "1",
            "Enabled": row.get("Enabled", "True") != "False",
            "SPNs": row.get("SPNs", ""),
            "DoesNotRequirePreAuth":
                row.get("DoesNotRequirePreAuth", "False") == "True",
            "PasswordNeverExpires":
                row.get("PasswordNeverExpires", "False") == "True",
            "DistinguishedName": row.get("DistinguishedName", ""),
        }
        # Tier guess: AdminCount=1 → at least T1; promotion to T0 happens later
        tier = Tier.T1 if attrs["AdminCount"] else Tier.T3
        display = (row.get("DisplayName") or sam).strip() or sam
        g.add_node(Node(
            id=f"user:{_norm(sam)}", label=sam, kind=NodeKind.USER,
            tier=tier, attrs=attrs))


def _add_dc_nodes(g: AttackGraph, data) -> None:
    for row in data.inventory.get("dcs", []):
        name = (row.get("Name") or row.get("HostName") or "").strip()
        if not name:
            continue
        g.add_node(Node(
            id=f"dc:{_norm(name)}", label=name,
            kind=NodeKind.DC, tier=Tier.T0,
            attrs={"OperatingSystem": row.get("OperatingSystem", "")}))


# ---------------------------------------------------------------------------
# Edge builders
# ---------------------------------------------------------------------------

def _edges_memberof_from_priv_csv(g: AttackGraph, data) -> None:
    for row in data.inventory.get("privileged_accounts", []):
        grp = (row.get("Group") or "").strip()
        sam = (row.get("SamAccountName") or "").strip()
        if not grp or not sam:
            continue
        grp_id = f"group:{grp}"
        usr_id = f"user:{_norm(sam)}"
        if grp_id not in g.nodes:
            g.add_node(Node(id=grp_id, label=grp, kind=NodeKind.GROUP,
                            tier=_tier_for_group(grp)))
        if usr_id not in g.nodes:
            g.add_node(Node(id=usr_id, label=sam, kind=NodeKind.USER, tier=Tier.T1))
        g.add_edge(Edge(src_id=usr_id, dst_id=grp_id,
                        kind=EdgeKind.MEMBER_OF,
                        evidence=f"{sam} ∈ {grp}"))


def _edges_memberof_from_txt(g: AttackGraph, data) -> None:
    """Fallback when privileged_accounts.csv is absent — parse the .txt files."""
    pairs = [
        ("domain_admins",     "Domain Admins"),
        ("enterprise_admins", "Enterprise Admins"),
        ("schema_admins",     "Schema Admins"),
    ]
    for stem, group in pairs:
        for ln in data.txt_files.get(stem, []):
            # format: "user <sam> <displayname>"
            parts = ln.split(" ", 2)
            if len(parts) < 2:
                continue
            sam = parts[1].strip()
            usr_id = f"user:{_norm(sam)}"
            grp_id = f"group:{group}"
            if usr_id not in g.nodes:
                g.add_node(Node(id=usr_id, label=sam, kind=NodeKind.USER,
                                tier=Tier.T1))
            g.add_edge(Edge(src_id=usr_id, dst_id=grp_id,
                            kind=EdgeKind.MEMBER_OF, evidence=ln))

    # accounts_userPrivileged.txt: "<sam> (<displayname>) ..."
    for ln in data.txt_files.get("accounts_userPrivileged", []):
        m = re.match(r"^(\S+)", ln)
        if not m:
            continue
        sam = m.group(1)
        usr_id = f"user:{_norm(sam)}"
        if usr_id not in g.nodes:
            g.add_node(Node(id=usr_id, label=sam, kind=NodeKind.USER,
                            tier=Tier.T2,
                            attrs={"PrivilegedNote": "accounts_userPrivileged"}))


def _edges_dcsync(g: AttackGraph, data, domain_node_id: str) -> None:
    """[location] IDENTITY: <user> | SID: <sid> | Right: DS-Replication-... | DN: <dn>"""
    rx = re.compile(r"\[([^\]]+)\]\s*IDENTITY:\s*([^|]+)\s*\|\s*SID:")
    legit = ("Domain Admins", "Enterprise Admins", "Domain Controllers",
            "SYSTEM", "Enterprise Read-only Domain Controllers", "Administrators")
    for ln in data.txt_files.get("DCSyncRights", []):
        m = rx.search(ln)
        if not m:
            continue
        location = m.group(1).strip()
        ident = m.group(2).strip()
        if any(g_legit in ident for g_legit in legit):
            continue
        # Non-default principal with DCSync — surface as edge to Domain or AdminSDHolder
        sam = _norm(ident)
        usr_id = f"user:{sam}"
        if usr_id not in g.nodes:
            # principal might be a group ("JGBSA\\GroupName") or unknown user
            g.add_node(Node(id=usr_id, label=ident, kind=NodeKind.USER,
                            tier=Tier.T2,
                            attrs={"DCSyncSource": location}))
        target_id = (domain_node_id if "DomainRoot" in location.replace(" ", "")
                    or "DC=" in location else "object:AdminSDHolder")
        # If location says AdminSDHolder explicitly, route there; else Domain
        if "AdminSDHolder" in location:
            target_id = "object:AdminSDHolder"
        elif "DomainRoot" in location.replace(" ", "") or "Domain" in location:
            target_id = domain_node_id
        g.add_edge(Edge(src_id=usr_id, dst_id=target_id,
                        kind=EdgeKind.DCSYNC, evidence=ln.strip()))


def _edges_kerberoastable(g: AttackGraph, data) -> None:
    """Any user with SPN: from Authenticated Users → user (because anyone can
    request the TGS and crack offline)."""
    seen: set[str] = set()
    # From SPNs.txt
    for ln in data.txt_files.get("SPNs", []):
        m = re.match(r"^(\S+)", ln)
        if m:
            seen.add(_norm(m.group(1)))
    # From users.csv (more authoritative)
    for row in data.inventory.get("users", []):
        if (row.get("SPNs") or "").strip():
            seen.add(_norm(row.get("SamAccountName", "")))
    for sam in seen:
        if not sam:
            continue
        usr_id = f"user:{sam}"
        if usr_id not in g.nodes:
            g.add_node(Node(id=usr_id, label=sam, kind=NodeKind.USER,
                            tier=Tier.T2,
                            attrs={"Roastable": True}))
        else:
            g.nodes[usr_id].attrs["Roastable"] = True
        g.add_edge(Edge(src_id=_PSEUDO_AUTH_USERS, dst_id=usr_id,
                        kind=EdgeKind.HAS_SPN_ROASTABLE,
                        evidence=f"SPN registered on {sam}"))


def _edges_asrep(g: AttackGraph, data) -> None:
    seen: set[str] = set()
    for ln in data.txt_files.get("ASREP", []):
        m = re.match(r"^(\S+)", ln)
        if m:
            seen.add(_norm(m.group(1)))
    for row in data.inventory.get("users", []):
        if row.get("DoesNotRequirePreAuth", "") == "True":
            seen.add(_norm(row.get("SamAccountName", "")))
    for sam in seen:
        if not sam:
            continue
        usr_id = f"user:{sam}"
        if usr_id not in g.nodes:
            g.add_node(Node(id=usr_id, label=sam, kind=NodeKind.USER,
                            tier=Tier.T2, attrs={"AsRepRoastable": True}))
        g.add_edge(Edge(src_id=_PSEUDO_AUTH_USERS, dst_id=usr_id,
                        kind=EdgeKind.ASREP_ROASTABLE,
                        evidence=f"DoesNotRequirePreAuth on {sam}"))


def _edges_shadow_credentials(g: AttackGraph, data) -> None:
    for ln in data.txt_files.get("ShadowCredentials", []):
        m = re.match(r"^(\S+)", ln)
        if not m:
            continue
        sam = _norm(m.group(1))
        usr_id = f"user:{sam}"
        if usr_id not in g.nodes:
            g.add_node(Node(id=usr_id, label=m.group(1), kind=NodeKind.USER,
                            tier=Tier.T2))
        g.add_edge(Edge(src_id=_PSEUDO_AUTH_USERS, dst_id=usr_id,
                        kind=EdgeKind.SHADOW_CREDENTIAL, evidence=ln))


def _edges_unconstrained_delegation(g: AttackGraph, data) -> None:
    for ln in data.txt_files.get("UnconstrainedDelegation", []):
        # Skip DCs (legitimate)
        if re.search(r"\bDC\b|Domain Controllers", ln, re.IGNORECASE):
            continue
        m = re.match(r"^(\S+)", ln)
        if not m:
            continue
        host = _norm(m.group(1))
        host_id = f"computer:{host}"
        if host_id not in g.nodes:
            g.add_node(Node(id=host_id, label=m.group(1), kind=NodeKind.COMPUTER,
                            tier=Tier.T1, attrs={"UnconstrainedDelegation": True}))
        # Any DA who logs onto this host leaks TGT — synthetic edge
        g.add_edge(Edge(src_id=host_id, dst_id="group:Domain Admins",
                        kind=EdgeKind.UNCONSTRAINED_DELEGATION, evidence=ln))


def _edges_rbcd(g: AttackGraph, data) -> None:
    for ln in data.txt_files.get("RBCD", []):
        m = re.match(r"^(\S+)", ln)
        if not m:
            continue
        principal = _norm(m.group(1))
        nid = f"computer:{principal}"
        if nid not in g.nodes:
            g.add_node(Node(id=nid, label=m.group(1), kind=NodeKind.COMPUTER,
                            tier=Tier.T2, attrs={"RBCD": True}))


def _edges_esc4_templates(g: AttackGraph, data) -> None:
    """ESC4: Authenticated Users can write to template ACL → enroll as anyone.
    Edge: Authenticated Users → Template (ESC4) → Domain Admins (transitive)."""
    rx = re.compile(r"^(ESC\d+)[: ]+(.+?)\s+\(([^)]+)\)\s*$")
    for ln in data.txt_files.get("vulnerable_templates", []):
        m = rx.match(ln)
        if not m or m.group(1) != "ESC4":
            continue
        tpl = m.group(2).strip()
        tpl_id = f"template:{_norm(tpl)}"
        if tpl_id not in g.nodes:
            g.add_node(Node(id=tpl_id, label=f"ADCS template: {tpl}",
                            kind=NodeKind.TEMPLATE, tier=Tier.T1,
                            attrs={"esc": "ESC4", "raw": ln.strip()}))
        # Authenticated Users can modify → can enroll → can be anyone
        g.add_edge(Edge(src_id=_PSEUDO_AUTH_USERS, dst_id=tpl_id,
                        kind=EdgeKind.ESC4_ENROLL, evidence=ln.strip()))
        # Template hops to Domain Admins (since ESC4 lets attacker emit certs as DA)
        g.add_edge(Edge(src_id=tpl_id, dst_id="group:Domain Admins",
                        kind=EdgeKind.GENERIC_ALL,
                        evidence=f"ESC4 template {tpl} → DA via cert spoof"))


# ---------------------------------------------------------------------------
# Tier promotion
# ---------------------------------------------------------------------------

def _promote_t0_transitively(g: AttackGraph) -> None:
    """Any user that is MemberOf a T0 group is itself T0 for path-finding
    purposes. Iterate until fixed-point."""
    changed = True
    while changed:
        changed = False
        for e in g.edges:
            if e.kind != EdgeKind.MEMBER_OF:
                continue
            grp = g.nodes.get(e.dst_id)
            usr = g.nodes.get(e.src_id)
            if grp is None or usr is None:
                continue
            if grp.tier == Tier.T0 and usr.tier != Tier.T0:
                usr.tier = Tier.T0
                changed = True
            elif grp.tier == Tier.T1 and usr.tier == Tier.T3:
                usr.tier = Tier.T1
                changed = True
