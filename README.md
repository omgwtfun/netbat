# netbat

A pure-Python network configuration analysis tool for Juniper firewalls, inspired by [Batfish](https://www.batfish.org/).

Parse JunOS hierarchical configs and ask questions about reachability, zone membership, and policy correctness — no Java, no Docker, no external dependencies.

## Features

- **Parser** — tokenizes and parses JunOS hierarchical config format into a structured AST
- **Config builder** — extracts interfaces, security zones, address books, security policies, and custom applications from the AST
- **Reachability analysis** — given source IP, destination IP, protocol and port, determines `permit`/`deny`/`unknown` and returns the matching rule
- **Zone lookup** — maps any IP to its security zone based on interface subnet membership
- **Shadowed rule detection** — finds policy rules that can never be evaluated because an earlier catch-all precedes them
- **Interface IP inventory** — lists all configured subnets across all interfaces

## Installation

```bash
pip install -e ".[dev]"   # includes pytest for running tests
```

Requires Python 3.9+. No third-party runtime dependencies.

## Quick start

```python
from netbat.builder import build_network_config
from netbat.analysis import reachability, zone_of_ip, shadowed_rules, interface_ips

config_text = open("firewall.conf").read()
nc = build_network_config(config_text)

# Which zone is this IP in?
print(zone_of_ip(nc, "192.168.1.50"))          # → "trust"

# Can a host in trust reach an external server over HTTPS?
r = reachability(nc, "192.168.1.50", "203.0.113.2", "tcp", 443)
print(r.action)                                 # → "permit"
print(r.matching_rule.name)                     # → "allow-https"

# Are any rules unreachable?
for policy, rule in shadowed_rules(nc):
    print(f"{policy.from_zone}→{policy.to_zone}: rule '{rule.name}' is shadowed")

# What subnets are configured?
for iface, unit, net in interface_ips(nc):
    print(f"{iface}.{unit}  {net}")
```

## Supported config sections

| JunOS section | What is extracted |
|---|---|
| `interfaces` | Interface names, unit IDs, IPv4 addresses, descriptions |
| `security zones` | Zone names, interface membership, per-zone address books |
| `security policies` | from-zone/to-zone direction, ordered rules, match criteria, actions |
| `address-book` (zone-level and global) | Named addresses and address-sets with recursive resolution |
| `applications` | Custom application definitions (protocol + destination port) |
| `application-sets` | Named groups of applications |

Built-in `junos-*` applications are pre-loaded (HTTP, HTTPS, SSH, Telnet, FTP, DNS, ping, BGP, NTP, SNMP, MySQL, RDP, and more).

## Analysis functions

### `zone_of_ip(nc, ip) → str | None`

Returns the name of the security zone whose member interface subnet contains `ip`, or `None` if no zone claims it.

### `reachability(nc, src_ip, dst_ip, protocol, dst_port) → ReachabilityResult`

Evaluates security policies in order and returns the first matching rule's action.

- `action`: `"permit"`, `"deny"`, or `"unknown"` (when a zone cannot be determined)
- `from_zone` / `to_zone`: resolved security zones
- `matching_rule`: the `PolicyRule` that matched, or `None` for implicit deny

Intra-zone traffic is always `permit`. Inter-zone traffic with no matching policy is implicitly `deny`.

### `shadowed_rules(nc) → list[(SecurityPolicy, PolicyRule)]`

Returns rules that follow a catch-all rule (source `any`, destination `any`, application `any`) and can therefore never be reached.

### `interface_ips(nc) → list[(iface_name, unit_id, IPv4Network)]`

Returns all configured IPv4 subnets, one entry per address statement.

## Running tests

```bash
pytest
```

71 tests covering the tokenizer, parser, config builder, domain models, and all four analysis functions.

## Project layout

```
netbat/
├── parser/
│   └── juniper.py      # tokenizer + recursive-descent parser
├── models.py           # dataclasses: NetworkConfig, Interface, SecurityZone,
│                       #   AddressBook, SecurityPolicy, PolicyRule, Application, …
├── applications.py     # built-in junos-* application definitions
├── builder.py          # AST → NetworkConfig
└── analysis.py         # zone_of_ip, reachability, shadowed_rules, interface_ips
tests/
├── test_parser.py
├── test_models.py
├── test_builder.py
└── test_analysis.py
```

## Limitations and future work

- **Routing is not modelled** — zone membership is inferred purely from interface subnets; the tool does not simulate a routing table to determine the actual egress interface for a given destination.
- **Stateful inspection is not modelled** — return traffic is not automatically permitted; policies must explicitly allow it.
- **NAT is not modelled** — source and destination NAT rules are parsed but not applied during reachability evaluation.
- **Firewall filters (stateless ACLs)** — the data model exists but filter evaluation is not yet wired into `reachability`.
- **IPv6** — only IPv4 is supported.
- **Set-format configs** — only JunOS hierarchical (curly-brace) format is supported; `set`-style flat configs are not.

## License

Apache 2.0 — see [LICENSE](LICENSE).
