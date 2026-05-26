"""Built-in Junos application definitions used for policy matching."""

from netbat.models import Application

JUNOS_APPLICATIONS: dict[str, Application] = {
    "junos-http":      Application("junos-http",      "tcp",  "80"),
    "junos-https":     Application("junos-https",     "tcp",  "443"),
    "junos-ssh":       Application("junos-ssh",       "tcp",  "22"),
    "junos-telnet":    Application("junos-telnet",    "tcp",  "23"),
    "junos-ftp":       Application("junos-ftp",       "tcp",  "21"),
    "junos-smtp":      Application("junos-smtp",      "tcp",  "25"),
    "junos-dns-udp":   Application("junos-dns-udp",   "udp",  "53"),
    "junos-dns-tcp":   Application("junos-dns-tcp",   "tcp",  "53"),
    "junos-ping":      Application("junos-ping",      "icmp", None),
    "junos-icmp-all":  Application("junos-icmp-all",  "icmp", None),
    "junos-ntp":       Application("junos-ntp",       "udp",  "123"),
    "junos-snmp":      Application("junos-snmp",      "udp",  "161"),
    "junos-syslog":    Application("junos-syslog",    "udp",  "514"),
    "junos-bgp":       Application("junos-bgp",       "tcp",  "179"),
    "junos-ldap":      Application("junos-ldap",      "tcp",  "389"),
    "junos-mysql":     Application("junos-mysql",     "tcp",  "3306"),
    "junos-rdp":       Application("junos-rdp",       "tcp",  "3389"),
    "any":             Application("any",             None,   None),
}
