"""Turn raw scan data into findings.

Findings are based on service exposure and configuration evidence reported by the tools
(for example anonymous FTP or SMB signing not required). NET-STRIKE does not match versions
against CVE databases and never attempts exploitation.
"""

from __future__ import annotations

from .models import Finding, ScanSession

# port -> (severity, title, detail, recommendation)
EXPOSURE_RULES = {
    23: ("high", "Telnet service exposed", "Telnet sends credentials and data in clear text.",
         "Disable Telnet and use SSH."),
    21: ("medium", "FTP service exposed", "FTP transmits credentials in clear text.",
         "Use SFTP/FTPS and disable anonymous access."),
    512: ("high", "rexec (r-service) exposed", "Legacy r-services use weak, clear-text authentication.",
          "Disable r-services and use SSH."),
    513: ("high", "rlogin (r-service) exposed", "Legacy r-services use weak, clear-text authentication.",
          "Disable r-services and use SSH."),
    514: ("high", "rsh (r-service) exposed", "Legacy r-services use weak, clear-text authentication.",
          "Disable r-services and use SSH."),
    2375: ("high", "Docker API exposed without TLS", "The unencrypted Docker API is usually unauthenticated.",
           "Bind to a local socket or require mutual TLS."),
    3389: ("medium", "RDP exposed", "Remote Desktop is a frequent target for credential attacks.",
           "Restrict access with a VPN/firewall and enable NLA."),
    5900: ("medium", "VNC exposed", "VNC often has weak or no encryption/authentication.",
           "Tunnel VNC through SSH or a VPN and require strong passwords."),
    445: ("info", "SMB exposed", "SMB file sharing is reachable on the network.",
          "Restrict SMB to hosts that need it and disable SMBv1."),
    139: ("info", "NetBIOS session service exposed", "NetBIOS is reachable on the network.",
          "Disable NetBIOS over TCP/IP where not needed."),
    1433: ("medium", "Microsoft SQL Server reachable", "Database service is reachable from the audited network.",
           "Limit database access to application servers."),
    1521: ("medium", "Oracle listener reachable", "Database service is reachable from the audited network.",
           "Limit database access to application servers."),
    3306: ("medium", "MySQL/MariaDB reachable", "Database service is reachable from the audited network.",
           "Bind to localhost or restrict with a firewall."),
    5432: ("medium", "PostgreSQL reachable", "Database service is reachable from the audited network.",
           "Restrict listen_addresses and pg_hba.conf."),
    6379: ("high", "Redis reachable", "Redis commonly runs without authentication.",
           "Bind to localhost, enable AUTH/ACLs and TLS."),
    9200: ("medium", "Elasticsearch reachable", "Search clusters are often deployed without authentication.",
           "Enable security features and restrict network access."),
    11211: ("medium", "Memcached reachable", "Memcached has no authentication by default.",
            "Bind to localhost or restrict with a firewall."),
    27017: ("medium", "MongoDB reachable", "Database service is reachable from the audited network.",
            "Enable authentication and bind to trusted interfaces."),
}
UDP_RULES = {
    69: ("medium", "TFTP exposed", "TFTP has no authentication.", "Disable TFTP or restrict by ACL."),
    161: ("medium", "SNMP exposed", "SNMP v1/v2c uses community strings in clear text.",
          "Use SNMPv3 and restrict access."),
}


def _script_findings(host, port, session: ScanSession) -> None:
    for sid, out in port.scripts.items():
        low = out.lower()
        where = port.key
        if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
            session.add_finding(Finding("high", "Anonymous FTP login allowed",
                                        "The FTP server accepts anonymous logins.", host.ip, where,
                                        "Disable anonymous access unless explicitly required.", "nmap:ftp-anon"))
        if sid == "smb2-security-mode" and "not required" in low:
            session.add_finding(Finding("medium", "SMB signing not required",
                                        "SMB message signing is enabled but not required, which allows relay attacks.",
                                        host.ip, where, "Require SMB signing via Group Policy / Samba config.",
                                        "nmap:smb2-security-mode"))
        if sid == "smb-protocols" and ("nt lm 0.12" in low or "smbv1" in low):
            session.add_finding(Finding("medium", "SMBv1 enabled", "The legacy SMBv1 protocol is available.",
                                        host.ip, where, "Disable SMBv1.", "nmap:smb-protocols"))
        if sid == "ssl-enum-ciphers" and any(x in low for x in ("sslv3", "tlsv1.0", "tlsv1.1")):
            session.add_finding(Finding("low", "Deprecated TLS/SSL protocol versions offered",
                                        "The service offers SSLv3 / TLS 1.0 / TLS 1.1.", host.ip, where,
                                        "Allow TLS 1.2+ only.", "nmap:ssl-enum-ciphers"))
        if sid == "http-methods" and any(m in low for m in ("put", "delete", "trace")) and "potentially risky" in low:
            session.add_finding(Finding("low", "Risky HTTP methods enabled", out.strip()[:200], host.ip, where,
                                        "Disable unneeded HTTP methods.", "nmap:http-methods"))


def analyze(session: ScanSession) -> int:
    """Populate session.findings. Returns the number of findings."""
    for host in session.hosts.values():
        for port in host.open_ports():
            rules = EXPOSURE_RULES if port.proto == "tcp" else UDP_RULES
            rule = rules.get(port.port)
            if rule:
                sev, title, detail, rec = rule
                session.add_finding(Finding(sev, title, detail, host.ip, port.key, rec, "exposure-rule"))
            _script_findings(host, port, session)

        smb = host.smb or {}
        if smb.get("null_session"):
            session.add_finding(Finding("high", "SMB null session allowed",
                                        "Anonymous (null) sessions are accepted, exposing enumeration data.",
                                        host.ip, "445/tcp", "Restrict anonymous access (RestrictAnonymous / "
                                        "restrict anonymous = 2 in Samba).", "enum4linux-ng"))
        if smb.get("smb1_enabled"):
            session.add_finding(Finding("medium", "SMBv1 enabled", "The legacy SMBv1 protocol is available.",
                                        host.ip, "445/tcp", "Disable SMBv1.", "enum4linux-ng"))
        if smb.get("signing_required") is False:
            session.add_finding(Finding("medium", "SMB signing not required",
                                        "SMB signing is not enforced, which allows relay attacks.", host.ip,
                                        "445/tcp", "Require SMB signing.", "enum4linux-ng"))
        for share in smb.get("shares", []):
            writing = str(share.get("writing", "")).lower()
            listing = str(share.get("listing", "")).lower()
            mapping = str(share.get("mapping", "")).lower()
            if writing == "ok":
                session.add_finding(Finding("high", f"Writable SMB share '{share['name']}' (anonymous)",
                                            "The share allows anonymous write access.", host.ip, "445/tcp",
                                            "Remove anonymous access to the share.", "enum4linux-ng"))
            elif listing == "ok" or mapping == "ok":
                session.add_finding(Finding("medium", f"Readable SMB share '{share['name']}' (anonymous)",
                                            "The share can be listed or mapped anonymously.", host.ip, "445/tcp",
                                            "Require authentication for the share.", "enum4linux-ng"))
        if smb.get("users"):
            session.add_finding(Finding("medium", "User accounts enumerable over SMB/RPC",
                                        f"{len(smb['users'])} account name(s) were enumerated without credentials.",
                                        host.ip, "445/tcp", "Restrict anonymous RPC/SAMR enumeration.",
                                        "enum4linux-ng"))

    tr = session.traffic
    if tr:
        for item in tr.cleartext:
            session.add_finding(Finding("medium", f"Clear-text protocol observed: {item['protocol']}",
                                        f"{item['packets']} packet(s) of {item['protocol']} were seen on the wire. "
                                        "Credentials/data in these protocols can be read by anyone on the path.",
                                        "", "", "Migrate to an encrypted alternative (TLS/SSH).", "tshark"))
        for anomaly in tr.arp_anomalies:
            session.add_finding(Finding("high", "IP address claimed by multiple MAC addresses",
                                        f"{anomaly['ip']} was announced by {', '.join(anomaly['macs'])}. This can "
                                        "indicate ARP spoofing or an IP conflict.", anomaly["ip"], "",
                                        "Investigate the devices; enable dynamic ARP inspection on switches.",
                                        "tshark"))
    return len(session.findings)
