"""Tests for the domain model classes."""

import pytest
from ipaddress import IPv4Network
from netbat.models import Address, AddressBook, AddressSet, Interface, InterfaceUnit


class TestAddressBook:
    def setup_method(self):
        self.book = AddressBook()
        self.book.addresses["web"] = Address("web", IPv4Network("10.0.0.1/32"))
        self.book.addresses["db"] = Address("db", IPv4Network("10.0.0.2/32"))
        self.book.addresses["net"] = Address("net", IPv4Network("10.0.0.0/24"))
        self.book.address_sets["servers"] = AddressSet("servers", ["web", "db"])
        self.book.address_sets["all"] = AddressSet("all", ["servers"])  # nested

    def test_resolve_single_address(self):
        assert self.book.resolve("web") == [IPv4Network("10.0.0.1/32")]

    def test_resolve_address_set_expands_members(self):
        result = self.book.resolve("servers")
        assert IPv4Network("10.0.0.1/32") in result
        assert IPv4Network("10.0.0.2/32") in result
        assert len(result) == 2

    def test_resolve_nested_address_set(self):
        result = self.book.resolve("all")
        assert IPv4Network("10.0.0.1/32") in result
        assert IPv4Network("10.0.0.2/32") in result

    def test_resolve_any_returns_quad_zero(self):
        result = self.book.resolve("any")
        assert result == [IPv4Network("0.0.0.0/0")]

    def test_resolve_unknown_name_returns_empty(self):
        assert self.book.resolve("nonexistent") == []

    def test_resolve_does_not_infinite_loop_on_cycle(self):
        self.book.address_sets["cyclic"] = AddressSet("cyclic", ["cyclic"])
        result = self.book.resolve("cyclic")
        assert result == []

    def test_resolve_prefix_network(self):
        result = self.book.resolve("net")
        assert result == [IPv4Network("10.0.0.0/24")]


class TestInterface:
    def test_all_addresses_returns_unit_and_network(self):
        iface = Interface(name="ge-0/0/0")
        unit = InterfaceUnit(unit_id="0")
        unit.ipv4_addresses.append(IPv4Network("192.168.1.0/24"))
        iface.units["0"] = unit
        pairs = iface.all_addresses()
        assert len(pairs) == 1
        uid, net = pairs[0]
        assert uid == "0"
        assert net == IPv4Network("192.168.1.0/24")

    def test_all_addresses_aggregates_multiple_units(self):
        iface = Interface(name="lo0")
        for i, prefix in enumerate(["10.0.0.1/32", "10.0.0.2/32"]):
            unit = InterfaceUnit(unit_id=str(i))
            unit.ipv4_addresses.append(IPv4Network(prefix))
            iface.units[str(i)] = unit
        assert len(iface.all_addresses()) == 2

    def test_all_addresses_empty_when_no_units(self):
        iface = Interface(name="ge-0/0/0")
        assert iface.all_addresses() == []
