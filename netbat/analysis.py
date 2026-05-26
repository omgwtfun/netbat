"""Analysis queries over a parsed NetworkConfig."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import List, Optional, Tuple

from netbat.applications import JUNOS_APPLICATIONS
from netbat.models import (
    Application,
    NetworkConfig,
    PolicyRule,
    SecurityPolicy,
    SecurityZone,
)


@dataclass
class ReachabilityResult:
    action: str                          # 'permit' | 'deny' | 'unknown'
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    matching_rule: Optional[PolicyRule] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_in_network(ip: IPv4Address, net: IPv4Network) -> bool:
    return ip in net


def _zone_for_interface(nc: NetworkConfig, iface_unit: str) -> Optional[str]:
    """Return zone name that claims interface ge-X/Y/Z.U, or None."""
    for zone_name, zone in nc.security_zones.items():
        if iface_unit in zone.interfaces:
            return zone_name
    return None


def _lookup_app(nc: NetworkConfig, name: str) -> Optional[Application]:
    """Resolve an application name to an Application, checking custom then built-in."""
    if name in nc.applications:
        return nc.applications[name]
    return JUNOS_APPLICATIONS.get(name)


def _resolve_app_names(nc: NetworkConfig, names: List[str]) -> List[Application]:
    """Expand a list of application/application-set names to Application objects."""
    result: List[Application] = []
    for name in names:
        if name in nc.application_sets:
            for member in nc.application_sets[name].members:
                app = _lookup_app(nc, member)
                if app:
                    result.append(app)
        else:
            app = _lookup_app(nc, name)
            if app:
                result.append(app)
    return result


def _port_matches(rule_port: Optional[str], pkt_port: Optional[int]) -> bool:
    """Check if a packet's destination port matches the application's port spec."""
    if rule_port is None:
        return True
    if pkt_port is None:
        return True
    if "-" in rule_port:
        lo, hi = rule_port.split("-", 1)
        return int(lo) <= pkt_port <= int(hi)
    return pkt_port == int(rule_port)


def _app_matches(app: Application, protocol: Optional[str], dst_port: Optional[int]) -> bool:
    """Return True if the given traffic matches the application definition."""
    if app.name == "any" or app.protocol is None:
        return True
    if protocol is not None and app.protocol != protocol:
        return False
    return _port_matches(app.dst_port, dst_port)


def _resolve_addresses_for_zone(
    nc: NetworkConfig, zone_name: Optional[str], addr_names: List[str]
) -> List[IPv4Network]:
    """Expand address names using the zone address book, falling back to global."""
    networks: List[IPv4Network] = []
    zone = nc.security_zones.get(zone_name or "")
    for name in addr_names:
        if name == "any":
            return [IPv4Network("0.0.0.0/0")]
        resolved = []
        if zone:
            resolved = zone.address_book.resolve(name)
        if not resolved:
            resolved = nc.global_address_book.resolve(name)
        networks.extend(resolved)
    return networks


def _ip_matches_addresses(
    ip: IPv4Address,
    nc: NetworkConfig,
    zone_name: Optional[str],
    addr_names: List[str],
) -> bool:
    if "any" in addr_names:
        return True
    networks = _resolve_addresses_for_zone(nc, zone_name, addr_names)
    return any(_ip_in_network(ip, net) for net in networks)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def zone_of_ip(nc: NetworkConfig, src_ip: str) -> Optional[str]:
    """Return the security zone name that contains *src_ip*, or None.

    Membership is determined by checking whether the IP falls within any
    subnet of an interface that belongs to the zone.
    """
    addr = ip_address(src_ip)
    for iface in nc.interfaces.values():
        for unit_id, net in iface.all_addresses():
            if addr in net:
                iface_unit = f"{iface.name}.{unit_id}"
                zone = _zone_for_interface(nc, iface_unit)
                if zone is not None:
                    return zone
    return None


def reachability(
    nc: NetworkConfig,
    src_ip: str,
    dst_ip: str,
    protocol: str = "tcp",
    dst_port: Optional[int] = None,
) -> ReachabilityResult:
    """Evaluate whether traffic from *src_ip* to *dst_ip* is permitted.

    Returns a ReachabilityResult with:
      action        – 'permit', 'deny', or 'unknown' (zone not found)
      from_zone     – source security zone
      to_zone       – destination security zone
      matching_rule – the first PolicyRule that matched, if any
    """
    from_zone = zone_of_ip(nc, src_ip)
    to_zone = zone_of_ip(nc, dst_ip)

    if from_zone is None or to_zone is None:
        return ReachabilityResult(action="unknown", from_zone=from_zone, to_zone=to_zone)

    if from_zone == to_zone:
        return ReachabilityResult(action="permit", from_zone=from_zone, to_zone=to_zone)

    src_addr = ip_address(src_ip)
    dst_addr = ip_address(dst_ip)

    for sp in nc.security_policies:
        if sp.from_zone != from_zone or sp.to_zone != to_zone:
            continue
        for rule in sp.rules:
            if not _ip_matches_addresses(src_addr, nc, from_zone, rule.match.source_addresses):
                continue
            if not _ip_matches_addresses(dst_addr, nc, to_zone, rule.match.destination_addresses):
                continue
            apps = _resolve_app_names(nc, rule.match.applications)
            if not apps or any(_app_matches(a, protocol, dst_port) for a in apps):
                return ReachabilityResult(
                    action=rule.action,
                    from_zone=from_zone,
                    to_zone=to_zone,
                    matching_rule=rule,
                )

    # No policy matched → implicit deny
    return ReachabilityResult(action="deny", from_zone=from_zone, to_zone=to_zone)


def shadowed_rules(nc: NetworkConfig) -> List[Tuple[SecurityPolicy, PolicyRule]]:
    """Find policy rules that can never be reached because an earlier rule catches all their traffic.

    A rule R is considered shadowed when every earlier sibling rule that has
    ``any`` for all three match fields (source, destination, application)
    precedes R — meaning R will never be evaluated.

    Returns a list of (SecurityPolicy, PolicyRule) pairs.
    """
    result: List[Tuple[SecurityPolicy, PolicyRule]] = []
    for sp in nc.security_policies:
        catchall_seen = False
        for rule in sp.rules:
            if catchall_seen:
                result.append((sp, rule))
            # A rule is a catch-all when every match field contains only 'any'
            m = rule.match
            if (
                m.source_addresses == ["any"]
                and m.destination_addresses == ["any"]
                and m.applications == ["any"]
            ):
                catchall_seen = True
    return result


def interface_ips(nc: NetworkConfig) -> List[Tuple[str, str, IPv4Network]]:
    """Return all configured IPv4 addresses as (interface_name, unit_id, network) triples."""
    result: List[Tuple[str, str, IPv4Network]] = []
    for iface in nc.interfaces.values():
        for unit_id, net in iface.all_addresses():
            result.append((iface.name, unit_id, net))
    return result
