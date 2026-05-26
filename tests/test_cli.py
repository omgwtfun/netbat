"""Tests for the CLI entry point."""

import json
import pytest
from netbat.cli import main

# ---------------------------------------------------------------------------
# Shared fixture config
# ---------------------------------------------------------------------------

_CONFIG = """
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 192.168.1.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 203.0.113.1/30; } } }
}
security {
    zones {
        security-zone trust   { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/1.0; } }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-http {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
            policy deny-all {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
    }
}
"""

_SHADOWED_CONFIG = """
security {
    policies {
        from-zone trust to-zone untrust {
            policy catch-all {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
            policy unreachable {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
        }
    }
}
"""


@pytest.fixture
def conf(tmp_path):
    p = tmp_path / "fw.conf"
    p.write_text(_CONFIG)
    return str(p)


@pytest.fixture
def shadowed_conf(tmp_path):
    p = tmp_path / "shadowed.conf"
    p.write_text(_SHADOWED_CONFIG)
    return str(p)


# ---------------------------------------------------------------------------
# reachability subcommand
# ---------------------------------------------------------------------------

class TestReachabilityCommand:
    def test_permit_shown_in_output(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80"])
        assert "permit" in capsys.readouterr().out.lower()

    def test_deny_shown_in_output(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "22"])
        assert "deny" in capsys.readouterr().out.lower()

    def test_zones_shown_in_output(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80"])
        out = capsys.readouterr().out
        assert "trust" in out
        assert "untrust" in out

    def test_matching_rule_shown_in_output(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80"])
        assert "allow-http" in capsys.readouterr().out

    def test_default_protocol_is_tcp(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80"])
        assert "permit" in capsys.readouterr().out.lower()

    def test_unknown_zone_shown(self, conf, capsys):
        main(["reachability", conf, "10.99.99.1", "203.0.113.2", "--port", "80"])
        assert "unknown" in capsys.readouterr().out.lower()

    def test_json_permit(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["action"] == "permit"
        assert data["from_zone"] == "trust"
        assert data["to_zone"] == "untrust"
        assert data["matching_rule"] == "allow-http"

    def test_json_deny_includes_rule(self, conf, capsys):
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "22", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["action"] == "deny"
        assert data["matching_rule"] == "deny-all"

    def test_json_unknown_zone(self, conf, capsys):
        main(["reachability", conf, "10.99.99.1", "203.0.113.2", "--port", "80", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["action"] == "unknown"
        assert data["matching_rule"] is None

    def test_json_implicit_deny_has_no_rule(self, conf, capsys):
        # Inbound with no matching policy → implicit deny, no rule object
        main(["reachability", conf, "203.0.113.2", "192.168.1.50", "--port", "80", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["action"] == "deny"
        assert data["matching_rule"] is None

    def test_exit_code_zero_on_success(self, conf):
        # Should not raise SystemExit
        main(["reachability", conf, "192.168.1.50", "203.0.113.2", "--port", "80"])

    def test_missing_config_file_exits_nonzero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["reachability", "/no/such/file.conf", "1.2.3.4", "5.6.7.8"])
        assert exc.value.code != 0


# ---------------------------------------------------------------------------
# zone-of subcommand
# ---------------------------------------------------------------------------

class TestZoneOfCommand:
    def test_known_ip_prints_zone(self, conf, capsys):
        main(["zone-of", conf, "192.168.1.50"])
        assert "trust" in capsys.readouterr().out

    def test_untrust_ip_prints_untrust(self, conf, capsys):
        main(["zone-of", conf, "203.0.113.2"])
        assert "untrust" in capsys.readouterr().out

    def test_unknown_ip_says_not_found(self, conf, capsys):
        main(["zone-of", conf, "10.99.99.1"])
        assert "not in any zone" in capsys.readouterr().out

    def test_json_known_ip(self, conf, capsys):
        main(["zone-of", conf, "192.168.1.50", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["zone"] == "trust"
        assert data["ip"] == "192.168.1.50"

    def test_json_unknown_ip(self, conf, capsys):
        main(["zone-of", conf, "10.99.99.1", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["zone"] is None

    def test_missing_config_file_exits_nonzero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["zone-of", "/no/such/file.conf", "1.2.3.4"])
        assert exc.value.code != 0


# ---------------------------------------------------------------------------
# shadowed subcommand
# ---------------------------------------------------------------------------

class TestShadowedCommand:
    def test_no_shadowed_rules_message(self, conf, capsys):
        main(["shadowed", conf])
        assert "no shadowed" in capsys.readouterr().out.lower()

    def test_shadowed_rule_name_shown(self, shadowed_conf, capsys):
        main(["shadowed", shadowed_conf])
        assert "unreachable" in capsys.readouterr().out

    def test_shadowed_output_shows_zones(self, shadowed_conf, capsys):
        main(["shadowed", shadowed_conf])
        out = capsys.readouterr().out
        assert "trust" in out
        assert "untrust" in out

    def test_json_empty_list_when_none(self, conf, capsys):
        main(["shadowed", conf, "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data == []

    def test_json_lists_shadowed_rule(self, shadowed_conf, capsys):
        main(["shadowed", shadowed_conf, "--json"])
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1
        assert data[0]["rule"] == "unreachable"
        assert data[0]["from_zone"] == "trust"
        assert data[0]["to_zone"] == "untrust"

    def test_missing_config_file_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc:
            main(["shadowed", "/no/such/file.conf"])
        assert exc.value.code != 0


# ---------------------------------------------------------------------------
# interfaces subcommand
# ---------------------------------------------------------------------------

class TestInterfacesCommand:
    def test_interface_names_shown(self, conf, capsys):
        main(["interfaces", conf])
        out = capsys.readouterr().out
        assert "ge-0/0/0" in out
        assert "ge-0/0/1" in out

    def test_subnets_shown(self, conf, capsys):
        main(["interfaces", conf])
        out = capsys.readouterr().out
        assert "192.168.1.0/24" in out
        assert "203.0.113.0/30" in out

    def test_empty_config_says_no_interfaces(self, tmp_path, capsys):
        empty = tmp_path / "empty.conf"
        empty.write_text("")
        main(["interfaces", str(empty)])
        assert "no interfaces" in capsys.readouterr().out.lower()

    def test_json_returns_list(self, conf, capsys):
        main(["interfaces", conf, "--json"])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_json_fields_present(self, conf, capsys):
        main(["interfaces", conf, "--json"])
        data = json.loads(capsys.readouterr().out)
        entry = data[0]
        assert "interface" in entry
        assert "unit" in entry
        assert "network" in entry

    def test_json_interface_names(self, conf, capsys):
        main(["interfaces", conf, "--json"])
        data = json.loads(capsys.readouterr().out)
        names = {d["interface"] for d in data}
        assert "ge-0/0/0" in names
        assert "ge-0/0/1" in names

    def test_missing_config_file_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc:
            main(["interfaces", "/no/such/file.conf"])
        assert exc.value.code != 0
