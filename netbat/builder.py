"""Build a NetworkConfig from raw JunOS hierarchical config text."""

from __future__ import annotations

from ipaddress import IPv4Network, ip_network
from typing import List, Optional

from netbat.models import (
    Address,
    AddressBook,
    AddressSet,
    Application,
    ApplicationSet,
    FirewallFilter,
    FirewallFilterTerm,
    Interface,
    InterfaceUnit,
    NetworkConfig,
    PolicyMatch,
    PolicyRule,
    SecurityPolicy,
    SecurityZone,
)
from netbat.parser.juniper import Statement, parse_config


# ---------------------------------------------------------------------------
# Helpers for navigating the statement list
# ---------------------------------------------------------------------------

def _find(stmts: List[Statement], keyword: str) -> List[Statement]:
    return [s for s in stmts if s[0] == keyword]


def _find_one(stmts: List[Statement], keyword: str) -> Optional[Statement]:
    found = _find(stmts, keyword)
    return found[0] if found else None


def _child_stmts(stmt: Optional[Statement]) -> List[Statement]:
    """Return the children list of a Statement, or [] if stmt is None/leaf."""
    if stmt is None:
        return []
    children = stmt[2]
    return children if children is not None else []


def _leaf_value(stmts: List[Statement], keyword: str) -> Optional[str]:
    """Return the first arg of the first matching leaf statement, or None."""
    stmt = _find_one(stmts, keyword)
    if stmt is None:
        return None
    args = stmt[1]
    return args[0] if args else None


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------

def _parse_interfaces(stmts: List[Statement]) -> dict[str, Interface]:
    interfaces: dict[str, Interface] = {}

    iface_block = _find_one(stmts, "interfaces")
    for iface_name, _, iface_children in _child_stmts(iface_block):
        if iface_children is None:
            continue
        iface = Interface(name=iface_name)

        desc_stmt = _find_one(iface_children, "description")
        if desc_stmt and desc_stmt[1]:
            iface.description = " ".join(desc_stmt[1])

        for _, unit_args, unit_children in _find(iface_children, "unit"):
            if not unit_args or unit_children is None:
                continue
            unit_id = unit_args[0]
            unit = InterfaceUnit(unit_id=unit_id)

            family_stmt = _find_one(unit_children, "family")
            if family_stmt is None:
                continue
            family_children = _child_stmts(family_stmt)
            # "family inet { ... }" → 'inet' is an arg, addresses are direct children
            # "family { inet { ... } }" → 'inet' is a nested block
            if "inet" in family_stmt[1]:
                addr_container = family_children
            else:
                inet_stmt = _find_one(family_children, "inet")
                addr_container = _child_stmts(inet_stmt)
            for _, addr_args, _ in _find(addr_container, "address"):
                if addr_args:
                    try:
                        unit.ipv4_addresses.append(
                            ip_network(addr_args[0], strict=False)
                        )
                    except ValueError:
                        pass

            iface.units[unit_id] = unit

        interfaces[iface_name] = iface

    return interfaces


def _parse_address_book(book_stmts: List[Statement]) -> AddressBook:
    book = AddressBook()

    for _, addr_args, _ in _find(book_stmts, "address"):
        if len(addr_args) >= 2:
            name, prefix_str = addr_args[0], addr_args[1]
            try:
                book.addresses[name] = Address(name, ip_network(prefix_str, strict=False))
            except ValueError:
                pass

    for _, set_args, set_children in _find(book_stmts, "address-set"):
        if not set_args:
            continue
        set_name = set_args[0]
        members = [a[1][0] for a in _find(_child_stmts((None, [], set_children)), "address")
                   if a[1]]
        # Rebuild helper: set_children is the raw children list
        member_stmts = set_children if set_children else []
        members = [s[1][0] for s in member_stmts if s[0] == "address" and s[1]]
        book.address_sets[set_name] = AddressSet(set_name, members)

    return book


def _parse_security_zones(security_children: List[Statement]) -> dict[str, SecurityZone]:
    zones: dict[str, SecurityZone] = {}

    zones_stmt = _find_one(security_children, "zones")
    for kw, zone_args, zone_children in _child_stmts(zones_stmt):
        if kw != "security-zone" or not zone_args or zone_children is None:
            continue
        zone_name = zone_args[0]
        zone = SecurityZone(name=zone_name)

        ifaces_stmt = _find_one(zone_children, "interfaces")
        for iface_kw, iface_args, _ in _child_stmts(ifaces_stmt):
            # Interfaces inside a zone are listed as bare statements: ge-0/0/0.0;
            zone.interfaces.append(iface_kw)

        book_stmt = _find_one(zone_children, "address-book")
        if book_stmt:
            zone.address_book = _parse_address_book(_child_stmts(book_stmt))

        zones[zone_name] = zone

    return zones


def _parse_policy_match(match_children: List[Statement]) -> PolicyMatch:
    pm = PolicyMatch()
    for kw, args, _ in match_children:
        if kw == "source-address":
            pm.source_addresses.extend(args)
        elif kw == "destination-address":
            pm.destination_addresses.extend(args)
        elif kw == "application":
            pm.applications.extend(args)
    return pm


def _parse_security_policies(security_children: List[Statement]) -> List[SecurityPolicy]:
    policies: List[SecurityPolicy] = []

    policies_stmt = _find_one(security_children, "policies")
    for kw, direction_args, direction_children in _child_stmts(policies_stmt):
        if kw != "from-zone" or direction_children is None:
            continue
        # direction_args: ['trust', 'to-zone', 'untrust']
        from_zone = direction_args[0] if len(direction_args) > 0 else ""
        to_zone = direction_args[2] if len(direction_args) > 2 else ""

        sp = SecurityPolicy(from_zone=from_zone, to_zone=to_zone)

        for rule_kw, rule_args, rule_children in direction_children:
            if rule_kw != "policy" or not rule_args or rule_children is None:
                continue
            rule_name = rule_args[0]
            rule = PolicyRule(name=rule_name)

            match_stmt = _find_one(rule_children, "match")
            if match_stmt:
                rule.match = _parse_policy_match(_child_stmts(match_stmt))

            then_stmt = _find_one(rule_children, "then")
            for action_kw, _, _ in _child_stmts(then_stmt):
                if action_kw in ("permit", "deny", "reject"):
                    rule.action = action_kw
                    break

            sp.rules.append(rule)

        policies.append(sp)

    return policies


def _parse_applications(
    app_stmts: List[Statement],
) -> tuple[dict[str, Application], dict[str, ApplicationSet]]:
    applications: dict[str, Application] = {}
    application_sets: dict[str, ApplicationSet] = {}

    apps_block = _find_one(app_stmts, "applications")
    for kw, args, children in _child_stmts(apps_block):
        if kw == "application" and args and children is not None:
            name = args[0]
            app = Application(name=name)
            proto = _leaf_value(children, "protocol")
            if proto:
                app.protocol = proto
            port = _leaf_value(children, "destination-port")
            if port:
                app.dst_port = port
            applications[name] = app

        elif kw == "application-set" and args and children is not None:
            name = args[0]
            members = [s[1][0] for s in children if s[0] == "application" and s[1]]
            application_sets[name] = ApplicationSet(name=name, members=members)

    return applications, application_sets


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_network_config(text: str) -> NetworkConfig:
    """Parse JunOS config text and return a fully populated NetworkConfig."""
    stmts = parse_config(text)
    nc = NetworkConfig()

    nc.interfaces = _parse_interfaces(stmts)

    security_stmt = _find_one(stmts, "security")
    if security_stmt:
        sec = _child_stmts(security_stmt)
        nc.security_zones = _parse_security_zones(sec)
        nc.security_policies = _parse_security_policies(sec)

        # Global address book: security { address-book { global { ... } } }
        global_ab_stmt = _find_one(sec, "address-book")
        if global_ab_stmt:
            global_children = _child_stmts(global_ab_stmt)
            global_block = _find_one(global_children, "global")
            if global_block:
                nc.global_address_book = _parse_address_book(_child_stmts(global_block))
            else:
                nc.global_address_book = _parse_address_book(global_children)

    nc.applications, nc.application_sets = _parse_applications(stmts)

    return nc
