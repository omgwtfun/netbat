"""Tests for the config builder (AST -> domain model)."""

import pytest
from ipaddress import IPv4Network
from netbat.builder import build_network_config


class TestBuildInterfaces:
    def test_single_interface_single_ip(self):
        config = """
        interfaces {
            ge-0/0/0 {
                unit 0 {
                    family inet {
                        address 192.168.1.1/24;
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        assert "ge-0/0/0" in nc.interfaces
        unit = nc.interfaces["ge-0/0/0"].units["0"]
        assert IPv4Network("192.168.1.0/24") in unit.ipv4_addresses

    def test_interface_description_quoted(self):
        config = """
        interfaces {
            ge-0/0/0 {
                description "LAN interface";
                unit 0 { family inet { address 10.0.0.1/30; } }
            }
        }
        """
        nc = build_network_config(config)
        assert nc.interfaces["ge-0/0/0"].description == "LAN interface"

    def test_multiple_interfaces_parsed(self):
        config = """
        interfaces {
            ge-0/0/0 { unit 0 { family inet { address 192.168.1.1/24; } } }
            ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/30; } } }
        }
        """
        nc = build_network_config(config)
        assert "ge-0/0/0" in nc.interfaces
        assert "ge-0/0/1" in nc.interfaces

    def test_multiple_addresses_on_same_unit(self):
        config = """
        interfaces {
            ge-0/0/0 {
                unit 0 {
                    family inet {
                        address 192.168.1.1/24;
                        address 10.0.0.1/30;
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        unit = nc.interfaces["ge-0/0/0"].units["0"]
        assert len(unit.ipv4_addresses) == 2

    def test_no_interfaces_section(self):
        nc = build_network_config("security { }")
        assert nc.interfaces == {}


class TestBuildSecurityZones:
    def test_zone_has_correct_name(self):
        config = """
        security {
            zones {
                security-zone trust { interfaces { ge-0/0/0.0; } }
            }
        }
        """
        nc = build_network_config(config)
        assert "trust" in nc.security_zones

    def test_zone_interface_membership(self):
        config = """
        security {
            zones {
                security-zone trust { interfaces { ge-0/0/0.0; } }
            }
        }
        """
        nc = build_network_config(config)
        assert "ge-0/0/0.0" in nc.security_zones["trust"].interfaces

    def test_multiple_zones(self):
        config = """
        security {
            zones {
                security-zone trust   { interfaces { ge-0/0/0.0; } }
                security-zone untrust { interfaces { ge-0/0/1.0; } }
            }
        }
        """
        nc = build_network_config(config)
        assert "trust" in nc.security_zones
        assert "untrust" in nc.security_zones

    def test_zone_address_book_addresses(self):
        config = """
        security {
            zones {
                security-zone trust {
                    address-book {
                        address web-server 192.168.1.100/32;
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        book = nc.security_zones["trust"].address_book
        assert "web-server" in book.addresses
        assert book.addresses["web-server"].prefix == IPv4Network("192.168.1.100/32")

    def test_zone_address_book_address_sets(self):
        config = """
        security {
            zones {
                security-zone trust {
                    address-book {
                        address web 192.168.1.100/32;
                        address db  192.168.1.200/32;
                        address-set servers {
                            address web;
                            address db;
                        }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        book = nc.security_zones["trust"].address_book
        assert "servers" in book.address_sets
        assert "web" in book.address_sets["servers"].members
        assert "db" in book.address_sets["servers"].members


class TestBuildSecurityPolicies:
    def test_permit_rule_parsed(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy allow-web {
                        match {
                            source-address any;
                            destination-address any;
                            application junos-http;
                        }
                        then { permit; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        assert len(nc.security_policies) == 1
        sp = nc.security_policies[0]
        assert sp.from_zone == "trust"
        assert sp.to_zone == "untrust"
        assert len(sp.rules) == 1
        rule = sp.rules[0]
        assert rule.name == "allow-web"
        assert rule.action == "permit"

    def test_deny_rule_parsed(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy deny-all {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then { deny; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        assert nc.security_policies[0].rules[0].action == "deny"

    def test_match_source_and_destination_addresses(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy test {
                        match {
                            source-address src-addr;
                            destination-address dst-addr;
                            application any;
                        }
                        then { permit; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        rule = nc.security_policies[0].rules[0]
        assert "src-addr" in rule.match.source_addresses
        assert "dst-addr" in rule.match.destination_addresses

    def test_bracketed_application_list(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy allow-web {
                        match {
                            source-address any;
                            destination-address any;
                            application [junos-http junos-https];
                        }
                        then { permit; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        apps = nc.security_policies[0].rules[0].match.applications
        assert "junos-http" in apps
        assert "junos-https" in apps

    def test_multiple_rules_preserve_order(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy first  { match { source-address any; destination-address any; application junos-http;  } then { permit; } }
                    policy second { match { source-address any; destination-address any; application junos-https; } then { permit; } }
                    policy last   { match { source-address any; destination-address any; application any;         } then { deny;   } }
                }
            }
        }
        """
        nc = build_network_config(config)
        names = [r.name for r in nc.security_policies[0].rules]
        assert names == ["first", "second", "last"]

    def test_multiple_policy_directions(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy outbound { match { source-address any; destination-address any; application any; } then { permit; } }
                }
                from-zone untrust to-zone trust {
                    policy inbound  { match { source-address any; destination-address any; application any; } then { deny;   } }
                }
            }
        }
        """
        nc = build_network_config(config)
        assert len(nc.security_policies) == 2
        directions = {(sp.from_zone, sp.to_zone) for sp in nc.security_policies}
        assert ("trust", "untrust") in directions
        assert ("untrust", "trust") in directions


class TestBuildApplications:
    def test_custom_application_parsed(self):
        config = """
        applications {
            application custom-app {
                protocol tcp;
                destination-port 8080;
            }
        }
        """
        nc = build_network_config(config)
        assert "custom-app" in nc.applications
        app = nc.applications["custom-app"]
        assert app.protocol == "tcp"
        assert app.dst_port == "8080"

    def test_application_set_parsed(self):
        config = """
        applications {
            application-set web-apps {
                application junos-http;
                application junos-https;
            }
        }
        """
        nc = build_network_config(config)
        assert "web-apps" in nc.application_sets
        members = nc.application_sets["web-apps"].members
        assert "junos-http" in members
        assert "junos-https" in members
