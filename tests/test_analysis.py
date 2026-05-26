"""Tests for the analysis / query layer."""

import pytest
from netbat.builder import build_network_config
from netbat.analysis import (
    ReachabilityResult,
    interface_ips,
    reachability,
    shadowed_rules,
    zone_of_ip,
)

# ---------------------------------------------------------------------------
# Shared fixture config
# ---------------------------------------------------------------------------

FULL_CONFIG = """
interfaces {
    ge-0/0/0 {
        description "LAN";
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
    ge-0/0/1 {
        description "WAN";
        unit 0 {
            family inet {
                address 203.0.113.1/30;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                address 127.0.0.1/32;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
            address-book {
                address web-server 192.168.1.100/32;
                address db-server  192.168.1.200/32;
                address-set internal-servers {
                    address web-server;
                    address db-server;
                }
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-http {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then { permit; }
            }
            policy allow-https {
                match {
                    source-address any;
                    destination-address any;
                    application junos-https;
                }
                then { permit; }
            }
            policy allow-dns {
                match {
                    source-address any;
                    destination-address any;
                    application junos-dns-udp;
                }
                then { permit; }
            }
            policy deny-rest {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
        }
        from-zone untrust to-zone trust {
            policy allow-to-web {
                match {
                    source-address any;
                    destination-address web-server;
                    application junos-http;
                }
                then { permit; }
            }
            policy deny-inbound {
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


@pytest.fixture
def nc():
    return build_network_config(FULL_CONFIG)


# ---------------------------------------------------------------------------
# zone_of_ip
# ---------------------------------------------------------------------------

class TestZoneOfIp:
    def test_ip_in_trust_zone(self, nc):
        assert zone_of_ip(nc, "192.168.1.50") == "trust"

    def test_ip_in_untrust_zone(self, nc):
        assert zone_of_ip(nc, "203.0.113.2") == "untrust"

    def test_interface_ip_itself_in_trust(self, nc):
        assert zone_of_ip(nc, "192.168.1.1") == "trust"

    def test_unknown_ip_returns_none(self, nc):
        assert zone_of_ip(nc, "10.99.99.99") is None

    def test_loopback_not_in_any_named_zone(self, nc):
        # lo0 is not assigned to any zone in the config
        assert zone_of_ip(nc, "127.0.0.1") is None


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------

class TestReachability:
    def test_http_trust_to_untrust_permitted(self, nc):
        r = reachability(nc, "192.168.1.50", "203.0.113.2", "tcp", 80)
        assert r.action == "permit"
        assert r.from_zone == "trust"
        assert r.to_zone == "untrust"

    def test_https_trust_to_untrust_permitted(self, nc):
        r = reachability(nc, "192.168.1.50", "203.0.113.2", "tcp", 443)
        assert r.action == "permit"

    def test_dns_udp_trust_to_untrust_permitted(self, nc):
        r = reachability(nc, "192.168.1.50", "203.0.113.2", "udp", 53)
        assert r.action == "permit"

    def test_ssh_trust_to_untrust_denied(self, nc):
        r = reachability(nc, "192.168.1.50", "203.0.113.2", "tcp", 22)
        assert r.action == "deny"

    def test_matching_rule_name_returned(self, nc):
        r = reachability(nc, "192.168.1.50", "203.0.113.2", "tcp", 80)
        assert r.matching_rule is not None
        assert r.matching_rule.name == "allow-http"

    def test_http_untrust_to_web_server_permitted(self, nc):
        r = reachability(nc, "203.0.113.2", "192.168.1.100", "tcp", 80)
        assert r.action == "permit"

    def test_http_untrust_to_db_server_denied(self, nc):
        r = reachability(nc, "203.0.113.2", "192.168.1.200", "tcp", 80)
        assert r.action == "deny"

    def test_no_policy_returns_deny(self, nc):
        # No policy from untrust → trust for arbitrary traffic (db server, non-http)
        r = reachability(nc, "203.0.113.2", "192.168.1.200", "tcp", 443)
        assert r.action == "deny"

    def test_unknown_src_zone_returns_unknown(self, nc):
        r = reachability(nc, "10.99.99.1", "203.0.113.2", "tcp", 80)
        assert r.action == "unknown"

    def test_unknown_dst_zone_returns_unknown(self, nc):
        r = reachability(nc, "192.168.1.50", "10.99.99.1", "tcp", 80)
        assert r.action == "unknown"

    def test_same_zone_traffic_returns_permit(self, nc):
        # intra-zone traffic — default permit in JunOS
        r = reachability(nc, "192.168.1.10", "192.168.1.20", "tcp", 80)
        assert r.action == "permit"


# ---------------------------------------------------------------------------
# shadowed_rules
# ---------------------------------------------------------------------------

class TestShadowedRules:
    def test_rule_after_catchall_deny_is_shadowed(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy catch-all {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then { deny; }
                    }
                    policy never-matches {
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
        shadowed = shadowed_rules(nc)
        names = [r.name for _, r in shadowed]
        assert "never-matches" in names
        assert "catch-all" not in names

    def test_rule_after_catchall_permit_is_shadowed(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy permit-all {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then { permit; }
                    }
                    policy unreachable {
                        match {
                            source-address any;
                            destination-address any;
                            application junos-ssh;
                        }
                        then { deny; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        shadowed = shadowed_rules(nc)
        names = [r.name for _, r in shadowed]
        assert "unreachable" in names

    def test_no_shadowed_rules_in_normal_policy(self, nc):
        shadowed = shadowed_rules(nc)
        # The fixture has specific rules before the catch-all, none are shadowed
        assert shadowed == []

    def test_returns_policy_alongside_rule(self):
        config = """
        security {
            policies {
                from-zone trust to-zone untrust {
                    policy any-permit {
                        match { source-address any; destination-address any; application any; }
                        then { permit; }
                    }
                    policy shadowed {
                        match { source-address any; destination-address any; application junos-http; }
                        then { deny; }
                    }
                }
            }
        }
        """
        nc = build_network_config(config)
        shadowed = shadowed_rules(nc)
        assert len(shadowed) == 1
        policy, rule = shadowed[0]
        assert policy.from_zone == "trust"
        assert rule.name == "shadowed"


# ---------------------------------------------------------------------------
# interface_ips
# ---------------------------------------------------------------------------

class TestInterfaceIps:
    def test_returns_all_configured_addresses(self, nc):
        ips = interface_ips(nc)
        prefixes = {str(net) for _, _, net in ips}
        assert "192.168.1.0/24" in prefixes
        assert "203.0.113.0/30" in prefixes
        assert "127.0.0.1/32" in prefixes

    def test_returns_interface_and_unit_names(self, nc):
        ips = interface_ips(nc)
        iface_names = {iface for iface, _, _ in ips}
        assert "ge-0/0/0" in iface_names
        assert "ge-0/0/1" in iface_names

    def test_empty_when_no_interfaces(self):
        nc = build_network_config("")
        assert interface_ips(nc) == []
