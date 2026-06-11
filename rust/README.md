# netbat (Rust)

A pure-Rust port of [netbat](../README.md) — network configuration analysis for
Juniper firewalls, inspired by [Batfish](https://www.batfish.org/).

Parse JunOS hierarchical configs and ask questions about reachability, zone
membership, and policy correctness. No external crates: the standard library
only, including a small built-in IPv4 type.

## Build and test

```bash
cargo build --release
cargo test
```

Produces a `netbat` binary at `target/release/netbat`. The test suite (69 tests)
mirrors the Python suite across the tokenizer, parser, config builder, domain
models, and all four analysis functions.

## CLI

The CLI is output-compatible with the Python implementation:

```bash
# Is HTTP from a trust host to an external IP permitted?
netbat reachability fw.conf 192.168.1.50 203.0.113.2 --port 80
# Action:  PERMIT
# From:    trust
# To:      untrust
# Rule:    allow-http

# Which zone is this IP in?
netbat zone-of fw.conf 203.0.113.2          # untrust

# Are any policy rules unreachable?
netbat shadowed fw.conf                     # trust → untrust: rule 'never-reached' is shadowed

# List all configured subnets
netbat interfaces fw.conf

# Every subcommand accepts --json
netbat reachability fw.conf 192.168.1.50 203.0.113.2 --port 80 --json
```

```
netbat reachability CONFIG SRC DST [--protocol PROTO] [--port PORT] [--json]
netbat zone-of      CONFIG IP                                       [--json]
netbat shadowed     CONFIG                                          [--json]
netbat interfaces   CONFIG                                          [--json]
```

Exit code is `0` on success and `1` when the config file cannot be opened or an
argument (such as an IP address) is invalid.

## Library

```rust
use netbat::{build_network_config, reachability, zone_of_ip};

let text = std::fs::read_to_string("firewall.conf").unwrap();
let nc = build_network_config(&text);

// Which zone is this IP in?
let zone = zone_of_ip(&nc, "192.168.1.50").unwrap();   // Some("trust")

// Can a host in trust reach an external server over HTTPS?
let r = reachability(&nc, "192.168.1.50", "203.0.113.2", "tcp", Some(443)).unwrap();
assert_eq!(r.action, "permit");
assert_eq!(r.matching_rule.unwrap().name, "allow-https");
```

## Module layout

```
rust/src/
├── ipv4.rs          # dependency-free Ipv4Addr / Ipv4Network
├── parser/mod.rs    # tokenizer + recursive-descent parser
├── models.rs        # NetworkConfig, Interface, SecurityZone, AddressBook, …
├── applications.rs  # built-in junos-* application definitions
├── builder.rs       # AST → NetworkConfig
├── analysis.rs      # zone_of_ip, reachability, shadowed_rules, interface_ips
├── lib.rs           # crate root / re-exports
└── main.rs          # CLI (netbat binary)
rust/tests/
├── parser.rs
├── models.rs
├── builder.rs
└── analysis.rs
```

Behaviour and limitations match the Python implementation: routing, stateful
inspection, NAT, firewall filters, IPv6, and `set`-format configs are out of
scope.
