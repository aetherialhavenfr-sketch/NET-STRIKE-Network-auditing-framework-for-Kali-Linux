"""Central configuration for NET-STRIKE."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "NET-STRIKE"
CODENAME = "MSTFAXNAF"
VERSION = "1.0.0"


def _config_home() -> Path:
    """Config lives in the invoking user's home, even when started through sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd

            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, ImportError):
            pass
    return Path.home()


CONFIG_DIR = _config_home() / ".netstrike"
AUDIT_LOG = CONFIG_DIR / "audit.log"
DEFAULT_SCOPE_FILE = CONFIG_DIR / "scope.txt"
DEFAULT_OUTPUT_DIR = "reports"

# --- Safety limits -----------------------------------------------------------
MAX_TARGET_ADDRESSES = 65536      # nothing larger than a /16 in a single run
MAX_RATE = 25000                  # packets per second ceiling for masscan / nmap --min-rate
DEFAULT_RATE = 1000               # lab-friendly default
AUTH_PHRASE = "I AM AUTHORIZED"

# --- External tools ----------------------------------------------------------
TOOLS = {
    "nmap": {"role": "port scan / services / OS detection", "root": False, "version_args": ["--version"]},
    "masscan": {"role": "high-speed port sweep", "root": True, "version_args": ["--version"]},
    "tshark": {"role": "packet capture & analysis", "root": True, "version_args": ["--version"]},
    "netdiscover": {"role": "ARP host discovery", "root": True, "version_args": ["-h"]},
    "enum4linux-ng": {"role": "SMB / Windows enumeration", "root": False, "version_args": ["--version"]},
}

# --- Modules / pipeline ------------------------------------------------------
MODULE_ORDER = ["discovery", "hostid", "portscan", "services", "smb", "traffic"]
MODULE_TITLES = {
    "discovery": "Network Discovery",
    "hostid": "Host Identification",
    "portscan": "Port Scanning",
    "services": "Service Enumeration",
    "smb": "SMB / Windows Enum",
    "traffic": "Traffic Analysis",
    "analysis": "Findings Analysis",
    "report": "Report Generation",
}
MODULE_TOOLS = {
    "discovery": ["netdiscover", "nmap"],
    "hostid": ["nmap"],
    "portscan": ["masscan", "nmap"],
    "services": ["nmap"],
    "smb": ["enum4linux-ng"],
    "traffic": ["tshark"],
}

QUICK_PORTS = (
    "21-23,25,53,80,110,111,135,139,143,389,443,445,993,995,1433,1521,2049,"
    "3306,3389,5432,5900,6379,8000-8100,8443,9200,11211,27017"
)

PROFILES = {
    "quick": {
        "modules": ["discovery", "hostid", "portscan", "services"],
        "ports": QUICK_PORTS,
        "traffic_duration": 0,
        "description": "fast triage of common ports",
    },
    "standard": {
        "modules": ["discovery", "hostid", "portscan", "services", "smb", "traffic"],
        "ports": "1-10000",
        "traffic_duration": 20,
        "description": "balanced audit with SMB enumeration and a 20s capture",
    },
    "full": {
        "modules": ["discovery", "hostid", "portscan", "services", "smb", "traffic"],
        "ports": "1-65535",
        "traffic_duration": 45,
        "description": "all ports, all modules, 45s capture",
    },
}
