"""Command-line interface for netbat."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from netbat.analysis import interface_ips, reachability, shadowed_rules, zone_of_ip
from netbat.builder import build_network_config


def _load(path: str):
    try:
        with open(path) as f:
            return build_network_config(f.read())
    except FileNotFoundError:
        print(f"error: config file not found: {path}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"error: failed to parse config: {exc}", file=sys.stderr)
        raise SystemExit(1)


def _cmd_reachability(args: argparse.Namespace) -> None:
    nc = _load(args.config)
    try:
        result = reachability(nc, args.src, args.dst, args.protocol, args.port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    rule_name = result.matching_rule.name if result.matching_rule else None

    if args.json:
        print(json.dumps({
            "action": result.action,
            "from_zone": result.from_zone,
            "to_zone": result.to_zone,
            "matching_rule": rule_name,
        }))
    else:
        print(f"Action:  {result.action.upper()}")
        if result.from_zone:
            print(f"From:    {result.from_zone}")
        if result.to_zone:
            print(f"To:      {result.to_zone}")
        if rule_name:
            print(f"Rule:    {rule_name}")


def _cmd_zone_of(args: argparse.Namespace) -> None:
    nc = _load(args.config)
    try:
        zone = zone_of_ip(nc, args.ip)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if args.json:
        print(json.dumps({"ip": args.ip, "zone": zone}))
    else:
        print(zone if zone is not None else "(not in any zone)")


def _cmd_shadowed(args: argparse.Namespace) -> None:
    nc = _load(args.config)
    results = shadowed_rules(nc)

    if args.json:
        print(json.dumps([
            {"from_zone": sp.from_zone, "to_zone": sp.to_zone, "rule": r.name}
            for sp, r in results
        ]))
    else:
        if not results:
            print("No shadowed rules found.")
        else:
            for sp, rule in results:
                print(f"{sp.from_zone} → {sp.to_zone}: rule '{rule.name}' is shadowed")


def _cmd_interfaces(args: argparse.Namespace) -> None:
    nc = _load(args.config)
    ips = interface_ips(nc)

    if args.json:
        print(json.dumps([
            {"interface": iface, "unit": unit, "network": str(net)}
            for iface, unit, net in ips
        ]))
    else:
        if not ips:
            print("No interfaces configured.")
        else:
            for iface, unit, net in ips:
                print(f"{iface}.{unit:<4}  {net}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netbat",
        description="Juniper firewall configuration analysis",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # -- reachability --------------------------------------------------------
    p = sub.add_parser(
        "reachability",
        help="check whether traffic between two IPs is permitted",
    )
    p.add_argument("config", metavar="CONFIG", help="path to JunOS config file")
    p.add_argument("src",    metavar="SRC",    help="source IP address")
    p.add_argument("dst",    metavar="DST",    help="destination IP address")
    p.add_argument("--protocol", default="tcp", metavar="PROTO",
                   help="IP protocol (default: tcp)")
    p.add_argument("--port", type=int, default=None, metavar="PORT",
                   help="destination port number")
    p.add_argument("--json", action="store_true", help="output as JSON")
    p.set_defaults(func=_cmd_reachability)

    # -- zone-of -------------------------------------------------------------
    p = sub.add_parser(
        "zone-of",
        help="find the security zone that contains an IP address",
    )
    p.add_argument("config", metavar="CONFIG", help="path to JunOS config file")
    p.add_argument("ip",     metavar="IP",     help="IP address to look up")
    p.add_argument("--json", action="store_true", help="output as JSON")
    p.set_defaults(func=_cmd_zone_of)

    # -- shadowed ------------------------------------------------------------
    p = sub.add_parser(
        "shadowed",
        help="list policy rules that can never be reached",
    )
    p.add_argument("config", metavar="CONFIG", help="path to JunOS config file")
    p.add_argument("--json", action="store_true", help="output as JSON")
    p.set_defaults(func=_cmd_shadowed)

    # -- interfaces ----------------------------------------------------------
    p = sub.add_parser(
        "interfaces",
        help="list all configured interface IP addresses",
    )
    p.add_argument("config", metavar="CONFIG", help="path to JunOS config file")
    p.add_argument("--json", action="store_true", help="output as JSON")
    p.set_defaults(func=_cmd_interfaces)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
