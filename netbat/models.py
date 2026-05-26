"""Domain model dataclasses for Juniper firewall configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class InterfaceUnit:
    unit_id: str
    ipv4_addresses: List[IPv4Network] = field(default_factory=list)


@dataclass
class Interface:
    name: str
    description: Optional[str] = None
    units: Dict[str, InterfaceUnit] = field(default_factory=dict)

    def all_addresses(self) -> List[Tuple[str, IPv4Network]]:
        """Return (unit_id, network) for every configured address across all units."""
        result: List[Tuple[str, IPv4Network]] = []
        for uid, unit in self.units.items():
            for addr in unit.ipv4_addresses:
                result.append((uid, addr))
        return result


@dataclass
class Address:
    name: str
    prefix: IPv4Network


@dataclass
class AddressSet:
    name: str
    members: List[str]  # names of Address or AddressSet entries


@dataclass
class AddressBook:
    addresses: Dict[str, Address] = field(default_factory=dict)
    address_sets: Dict[str, AddressSet] = field(default_factory=dict)

    def resolve(self, name: str, _seen: Optional[Set[str]] = None) -> List[IPv4Network]:
        """Expand a name to its constituent prefixes, following address-set nesting."""
        if _seen is None:
            _seen = set()
        if name in _seen:
            return []
        _seen.add(name)

        if name == "any":
            return [IPv4Network("0.0.0.0/0")]

        if name in self.addresses:
            return [self.addresses[name].prefix]

        if name in self.address_sets:
            result: List[IPv4Network] = []
            for member in self.address_sets[name].members:
                result.extend(self.resolve(member, _seen))
            return result

        return []


@dataclass
class SecurityZone:
    name: str
    interfaces: List[str] = field(default_factory=list)
    address_book: AddressBook = field(default_factory=AddressBook)


@dataclass
class Application:
    name: str
    protocol: Optional[str] = None   # 'tcp', 'udp', 'icmp', etc.
    dst_port: Optional[str] = None   # single port or range 'lo-hi'


@dataclass
class ApplicationSet:
    name: str
    members: List[str] = field(default_factory=list)  # Application or ApplicationSet names


@dataclass
class PolicyMatch:
    source_addresses: List[str] = field(default_factory=list)
    destination_addresses: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)


@dataclass
class PolicyRule:
    name: str
    match: PolicyMatch = field(default_factory=PolicyMatch)
    action: str = "deny"  # 'permit' | 'deny' | 'reject'


@dataclass
class SecurityPolicy:
    from_zone: str
    to_zone: str
    rules: List[PolicyRule] = field(default_factory=list)


@dataclass
class FirewallFilterTerm:
    name: str
    from_source_address: List[IPv4Network] = field(default_factory=list)
    from_destination_address: List[IPv4Network] = field(default_factory=list)
    from_protocol: List[str] = field(default_factory=list)
    from_destination_port: List[str] = field(default_factory=list)
    action: str = "discard"


@dataclass
class FirewallFilter:
    name: str
    family: str = "inet"
    terms: List[FirewallFilterTerm] = field(default_factory=list)


@dataclass
class NetworkConfig:
    """Complete parsed representation of a Juniper firewall configuration."""
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    security_zones: Dict[str, SecurityZone] = field(default_factory=dict)
    security_policies: List[SecurityPolicy] = field(default_factory=list)
    firewall_filters: Dict[str, FirewallFilter] = field(default_factory=dict)
    applications: Dict[str, Application] = field(default_factory=dict)
    application_sets: Dict[str, ApplicationSet] = field(default_factory=dict)
    global_address_book: AddressBook = field(default_factory=AddressBook)
