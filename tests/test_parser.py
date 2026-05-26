"""Tests for the JunOS hierarchical config parser."""

import pytest
from netbat.parser.juniper import tokenize, parse, parse_config


class TestTokenizer:
    def test_empty_string(self):
        assert tokenize("") == []

    def test_single_leaf_with_quoted_value(self):
        assert tokenize('description "WAN interface";') == [
            "description", "WAN interface", ";"
        ]

    def test_structural_chars(self):
        assert tokenize("{}[];") == ["{", "}", "[", "]", ";"]

    def test_strips_single_line_comment(self):
        text = "# comment\ndescription foo;"
        assert tokenize(text) == ["description", "foo", ";"]

    def test_strips_block_comment(self):
        text = "/* block comment */ description foo;"
        assert tokenize(text) == ["description", "foo", ";"]

    def test_ip_with_prefix(self):
        assert tokenize("address 10.0.0.1/24;") == ["address", "10.0.0.1/24", ";"]

    def test_interface_name_with_unit(self):
        assert tokenize("ge-0/0/0.0;") == ["ge-0/0/0.0", ";"]

    def test_quoted_string_preserves_spaces(self):
        assert tokenize('"hello world"') == ["hello world"]

    def test_multiple_tokens_on_line(self):
        tokens = tokenize("from-zone trust to-zone untrust {}")
        assert tokens == ["from-zone", "trust", "to-zone", "untrust", "{", "}"]


class TestParser:
    def test_empty_token_list(self):
        assert parse([]) == []

    def test_leaf_statement(self):
        tokens = ["description", "foo", ";"]
        stmts = parse(tokens)
        assert len(stmts) == 1
        keyword, args, children = stmts[0]
        assert keyword == "description"
        assert args == ["foo"]
        assert children is None

    def test_leaf_with_no_args(self):
        tokens = ["permit", ";"]
        stmts = parse(tokens)
        keyword, args, children = stmts[0]
        assert keyword == "permit"
        assert args == []
        assert children is None

    def test_block_statement(self):
        tokens = ["interfaces", "{", "ge-0/0/0", "{", "}", "}"]
        stmts = parse(tokens)
        assert len(stmts) == 1
        keyword, args, children = stmts[0]
        assert keyword == "interfaces"
        assert args == []
        assert isinstance(children, list)
        assert children[0][0] == "ge-0/0/0"

    def test_multiple_sibling_statements(self):
        tokens = ["a", ";", "b", ";"]
        stmts = parse(tokens)
        assert [s[0] for s in stmts] == ["a", "b"]

    def test_nested_blocks(self):
        config = "security { zones { security-zone trust { } } }"
        stmts = parse_config(config)
        assert stmts[0][0] == "security"
        zones = stmts[0][2][0]
        assert zones[0] == "zones"
        zone = zones[2][0]
        assert zone[0] == "security-zone"
        assert zone[1] == ["trust"]

    def test_bracketed_list_values(self):
        tokens = ["application", "[", "junos-http", "junos-https", "]", ";"]
        stmts = parse(tokens)
        keyword, args, children = stmts[0]
        assert keyword == "application"
        assert args == ["junos-http", "junos-https"]
        assert children is None

    def test_from_zone_to_zone_syntax(self):
        config = "policies { from-zone trust to-zone untrust { } }"
        stmts = parse_config(config)
        children = stmts[0][2]
        kw, args, _ = children[0]
        assert kw == "from-zone"
        assert args == ["trust", "to-zone", "untrust"]

    def test_repeated_leaf_same_key(self):
        config = "family inet { address 10.0.0.1/24; address 10.0.0.2/24; }"
        stmts = parse_config(config)
        inet_children = stmts[0][2]
        addr_stmts = [s for s in inet_children if s[0] == "address"]
        assert len(addr_stmts) == 2
        assert addr_stmts[0][1] == ["10.0.0.1/24"]
        assert addr_stmts[1][1] == ["10.0.0.2/24"]

    def test_multiword_statement_args(self):
        config = "address-set servers { address web; address db; }"
        stmts = parse_config(config)
        kw, args, children = stmts[0]
        assert kw == "address-set"
        assert args == ["servers"]
        member_names = [s[1][0] for s in children if s[0] == "address"]
        assert "web" in member_names
        assert "db" in member_names

    def test_real_interface_snippet(self):
        config = """
        interfaces {
            ge-0/0/0 {
                description "LAN";
                unit 0 {
                    family inet {
                        address 192.168.1.1/24;
                    }
                }
            }
        }
        """
        stmts = parse_config(config)
        iface_block = stmts[0]
        assert iface_block[0] == "interfaces"
        ge = iface_block[2][0]
        assert ge[0] == "ge-0/0/0"
