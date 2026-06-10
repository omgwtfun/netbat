//! Tests for the JunOS hierarchical config parser.

use netbat::parser::{parse, parse_config, tokenize, Statement};

fn tok(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// --- tokenizer -------------------------------------------------------------

#[test]
fn empty_string() {
    assert_eq!(tokenize(""), Vec::<String>::new());
}

#[test]
fn single_leaf_with_quoted_value() {
    assert_eq!(
        tokenize("description \"WAN interface\";"),
        tok(&["description", "WAN interface", ";"])
    );
}

#[test]
fn structural_chars() {
    assert_eq!(tokenize("{}[];"), tok(&["{", "}", "[", "]", ";"]));
}

#[test]
fn strips_single_line_comment() {
    assert_eq!(
        tokenize("# comment\ndescription foo;"),
        tok(&["description", "foo", ";"])
    );
}

#[test]
fn strips_block_comment() {
    assert_eq!(
        tokenize("/* block comment */ description foo;"),
        tok(&["description", "foo", ";"])
    );
}

#[test]
fn ip_with_prefix() {
    assert_eq!(
        tokenize("address 10.0.0.1/24;"),
        tok(&["address", "10.0.0.1/24", ";"])
    );
}

#[test]
fn interface_name_with_unit() {
    assert_eq!(tokenize("ge-0/0/0.0;"), tok(&["ge-0/0/0.0", ";"]));
}

#[test]
fn quoted_string_preserves_spaces() {
    assert_eq!(tokenize("\"hello world\""), tok(&["hello world"]));
}

#[test]
fn multiple_tokens_on_line() {
    assert_eq!(
        tokenize("from-zone trust to-zone untrust {}"),
        tok(&["from-zone", "trust", "to-zone", "untrust", "{", "}"])
    );
}

// --- parser ----------------------------------------------------------------

#[test]
fn empty_token_list() {
    assert_eq!(parse(&[]), Vec::<Statement>::new());
}

#[test]
fn leaf_statement() {
    let stmts = parse(&tok(&["description", "foo", ";"]));
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0].keyword, "description");
    assert_eq!(stmts[0].args, tok(&["foo"]));
    assert!(stmts[0].children.is_none());
}

#[test]
fn leaf_with_no_args() {
    let stmts = parse(&tok(&["permit", ";"]));
    assert_eq!(stmts[0].keyword, "permit");
    assert!(stmts[0].args.is_empty());
    assert!(stmts[0].children.is_none());
}

#[test]
fn block_statement() {
    let stmts = parse(&tok(&["interfaces", "{", "ge-0/0/0", "{", "}", "}"]));
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0].keyword, "interfaces");
    assert!(stmts[0].args.is_empty());
    let children = stmts[0].children.as_ref().unwrap();
    assert_eq!(children[0].keyword, "ge-0/0/0");
}

#[test]
fn multiple_sibling_statements() {
    let stmts = parse(&tok(&["a", ";", "b", ";"]));
    let kws: Vec<_> = stmts.iter().map(|s| s.keyword.clone()).collect();
    assert_eq!(kws, tok(&["a", "b"]));
}

#[test]
fn nested_blocks() {
    let stmts = parse_config("security { zones { security-zone trust { } } }");
    assert_eq!(stmts[0].keyword, "security");
    let zones = &stmts[0].children.as_ref().unwrap()[0];
    assert_eq!(zones.keyword, "zones");
    let zone = &zones.children.as_ref().unwrap()[0];
    assert_eq!(zone.keyword, "security-zone");
    assert_eq!(zone.args, tok(&["trust"]));
}

#[test]
fn bracketed_list_values() {
    let stmts = parse(&tok(&[
        "application",
        "[",
        "junos-http",
        "junos-https",
        "]",
        ";",
    ]));
    assert_eq!(stmts[0].keyword, "application");
    assert_eq!(stmts[0].args, tok(&["junos-http", "junos-https"]));
    assert!(stmts[0].children.is_none());
}

#[test]
fn from_zone_to_zone_syntax() {
    let stmts = parse_config("policies { from-zone trust to-zone untrust { } }");
    let children = stmts[0].children.as_ref().unwrap();
    assert_eq!(children[0].keyword, "from-zone");
    assert_eq!(children[0].args, tok(&["trust", "to-zone", "untrust"]));
}

#[test]
fn repeated_leaf_same_key() {
    let stmts = parse_config("family inet { address 10.0.0.1/24; address 10.0.0.2/24; }");
    let inet_children = stmts[0].children.as_ref().unwrap();
    let addrs: Vec<_> = inet_children
        .iter()
        .filter(|s| s.keyword == "address")
        .collect();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].args, tok(&["10.0.0.1/24"]));
    assert_eq!(addrs[1].args, tok(&["10.0.0.2/24"]));
}

#[test]
fn multiword_statement_args() {
    let stmts = parse_config("address-set servers { address web; address db; }");
    assert_eq!(stmts[0].keyword, "address-set");
    assert_eq!(stmts[0].args, tok(&["servers"]));
    let members: Vec<_> = stmts[0]
        .children
        .as_ref()
        .unwrap()
        .iter()
        .filter(|s| s.keyword == "address")
        .map(|s| s.args[0].clone())
        .collect();
    assert!(members.contains(&"web".to_string()));
    assert!(members.contains(&"db".to_string()));
}

#[test]
fn real_interface_snippet() {
    let config = r#"
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
    "#;
    let stmts = parse_config(config);
    assert_eq!(stmts[0].keyword, "interfaces");
    let ge = &stmts[0].children.as_ref().unwrap()[0];
    assert_eq!(ge.keyword, "ge-0/0/0");
}
