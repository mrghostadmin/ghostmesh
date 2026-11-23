"""
GHOSTMESH - Network Defense Console (full screen, real time)

Watches THIS Mac's real network activity and shows it on a full-screen,
military-style tactical display:

  * RADAR        every connection and every device on your Wi-Fi as a blip
  * THREATCON    overall threat level: NORMAL / ALPHA / BRAVO / CHARLIE / DELTA
  * TRAFFIC      live graph of download and upload speed (last 3 minutes)
  * TOP APPS     which apps on this Mac are using the internet right now
  * DEVICES      other devices on your network, with an alert when a new one joins
  * ALERTS       suspicious patterns, with a sound, a Mac notification, and a
                 saved log file (ghostmesh_alerts.log, next to this program)

It only WATCHES. It does not read the contents of your traffic, and it does not
block or change anything. No admin password needed.
This is an educational tool, not a replacement for real security software.

Run:      python3 ghostmesh.py            (live, watching this Mac)
          python3 ghostmesh.py --demo     (practice mode with made-up traffic)
Needs:    python3 -m pip install pygame-ce

Window:   opens as a normal window - drag its edges to resize it.
Keys:     ESC = quit        F = full screen on/off     SPACE = pause
          T = test alert    M = sound on/off
          (demo only) B = fake brute-force   P = fake port scan   N = fake new device
"""

import ipaddress
import math
import os
import queue
import random
import re
import socket
import subprocess
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict, deque

try:
    import pygame
except ImportError:
    print("Pygame is not installed. In the Terminal, type:")
    print("    python3 -m pip install pygame-ce")
    sys.exit(1)

# ======================================================================= settings
FPS = 50
HISTORY_SECONDS = 180          # traffic graph length
WINDOW_SECONDS = 10            # detection time window
DANGER_SECONDS = 6             # red "threat" state after an alert
LOG_FILE = "ghostmesh_alerts.log"

INBOUND_SCAN_PORTS = 4         # one address touching this many of your ports
INBOUND_REPEAT = 5             # one address connecting this many times to one port
OUTBOUND_SCAN_PORTS = 6        # this Mac contacting this many ports on one address
UNANSWERED_LIMIT = 8           # this many addresses not answering at once
BURST_LIMIT = 150              # new connections in 10 seconds

SUSPICIOUS_PORTS = {
    23: "Telnet - old, unencrypted remote login",
    1337: "often used by hacking tools",
    31337: "often used by hacking tools",
    4444: "default port of a common hacking tool",
    5555: "Android debug / often abused by malware",
    6667: "IRC - often used to control infected computers",
    6697: "IRC - often used to control infected computers",
    9050: "Tor network",
    9150: "Tor network",
}
SERVICES = {20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            465: "SMTP", 548: "AFP", 587: "SMTP", 993: "IMAP", 995: "POP3",
            3306: "MYSQL", 3389: "RDP", 5223: "APPLE-PUSH", 5228: "GOOGLE",
            5353: "BONJOUR", 5900: "SCREEN-SHARE", 7000: "AIRPLAY", 8080: "HTTP-ALT",
            8443: "HTTPS-ALT"}
SKIP_INTERFACES = ("lo", "utun", "gif", "stf", "awdl", "llw", "anpi", "bridge", "ap")
THREATCON = ["NORMAL", "ALPHA", "BRAVO", "CHARLIE", "DELTA"]

# colours: tactical blue, amber warnings, red threats
# (the names say GREEN for history - they are blue now)
BG = (3, 6, 14)
PANEL_BG = (6, 12, 26)
GREEN = (80, 190, 255)
GREEN_MID = (45, 120, 190)
GREEN_DIM = (28, 70, 120)
GREEN_FAINT = (14, 30, 56)
AMBER = (255, 180, 30)
RED = (255, 55, 55)
TEXT = (185, 220, 245)
WHITE = (235, 245, 255)
RADAR_BG = (4, 14, 30)
CON_COLORS = [GREEN, (255, 225, 80), AMBER, (255, 110, 40), RED]


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    t = max(0.0, min(1.0, t))
    return tuple(int(lerp(a, b, t)) for a, b in zip(c1, c2))


def fmt_rate(bps):
    if bps is None:
        return "-"
    if bps >= 999_500:
        return f"{bps / 1_000_000:.1f} MB/s"
    if bps >= 999.5:
        return f"{bps / 1_000:.0f} KB/s"
    return f"{bps:.0f} B/s"


def service_name(port):
    return SERVICES.get(port, "")


def is_loopback(ip):
    return ip.startswith("127.") or ip in ("::1", "localhost")


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


def ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


def here(name):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


# ======================================================================= reading the Mac's network
def run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def split_addr(addr):
    """macOS netstat writes addresses as 192.168.1.5.52344 or *.5000"""
    if "." not in addr:
        return None
    host, port = addr.rsplit(".", 1)
    return host.split("%")[0], (int(port) if port.isdigit() else None)


def parse_netstat(text):
    rows = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5 or not p[0].startswith("tcp"):
            continue
        local, remote = split_addr(p[3]), split_addr(p[4])
        if local is None or remote is None:
            continue
        rows.append((local[0], local[1], remote[0], remote[1], p[5] if len(p) > 5 else ""))
    return rows


def parse_ifstats(text):
    """Total packets/bytes in and out, from: netstat -ib"""
    lines = text.splitlines()
    if not lines:
        return None
    header = lines[0].split()
    if "Address" not in header or "Ipkts" not in header:
        return None
    tail = header[header.index("Address") + 1:]
    totals = {"Ipkts": 0, "Ibytes": 0, "Opkts": 0, "Obytes": 0}
    seen, found = set(), False
    for line in lines[1:]:
        p = line.split()
        if "<Link#" not in line or len(p) < len(tail) + 1:
            continue
        name = p[0].rstrip("*")
        if name in seen or name.startswith(SKIP_INTERFACES):
            continue
        row = dict(zip(tail, p[-len(tail):]))
        try:
            nums = {k: int(row[k]) for k in totals}
        except (KeyError, ValueError):
            continue
        seen.add(name)
        found = True
        for k in totals:
            totals[k] += nums[k]
    return totals if found else None


def parse_lsof(text):
    """local port -> app name, and app name -> number of connections (lsof -F pcn)"""
    names, conns, cmd = {}, Counter(), "?"
    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "c":
            cmd = val
        elif tag == "n":
            if "->" in val:
                conns[cmd] += 1
            local = val.split("->")[0]
            if ":" in local:
                port = local.rsplit(":", 1)[1]
                if port.isdigit():
                    names.setdefault(int(port), cmd)
    return names, conns


def parse_nettop(text):
    """nettop -P -L 1 -J bytes_in,bytes_out  ->  [(key, app, bytes_in, bytes_out)]"""
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    header = lines[0].split(",")
    if "bytes_in" not in header or "bytes_out" not in header:
        return []
    i_in, i_out = header.index("bytes_in"), header.index("bytes_out")
    i_name = header.index("") if "" in header else 0
    rows = []
    for line in lines[1:]:
        p = line.split(",")
        if len(p) <= max(i_in, i_out, i_name):
            continue
        key = p[i_name]
        try:
            b_in, b_out = int(p[i_in]), int(p[i_out])
        except ValueError:
            continue
        app = key.rsplit(".", 1)[0] if re.search(r"\.\d+$", key) else key
        rows.append((key, app, b_in, b_out))
    return rows


ARP_RE = re.compile(r"\(([0-9.]+)\) at ([0-9a-fA-F:]+) on (\S+)")


def parse_arp(text):
    out = []
    for line in text.splitlines():
        m = ARP_RE.search(line)
        if not m:
            continue
        ip, mac, iface = m.groups()
        parts = mac.lower().split(":")
        if len(parts) != 6:
            continue
        mac = ":".join(x.zfill(2) for x in parts)
        if mac == "ff:ff:ff:ff:ff:ff" or int(parts[0], 16) & 1:
            continue
        if ip.startswith(("224.", "239.", "255.")) or ip.endswith(".255"):
            continue
        out.append((ip, mac, iface))
    return out


def parse_gateway(text):
    for line in text.splitlines():
        if "gateway:" in line:
            return line.split("gateway:")[1].strip()
    return None


def own_ip(target):
    """This Mac's address on the network (no data is actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target or "192.168.0.1", 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def read_net():
    rows = parse_netstat(run(["netstat", "-an", "-p", "tcp"]))
    counters = parse_ifstats(run(["netstat", "-ib"]))
    if not rows and counters is None:
        return None
    return {"time": time.monotonic(), "rows": rows, "counters": counters}


def read_names():
    return parse_lsof(run(["lsof", "+c", "0", "-nP", "-iTCP", "-F", "pcn"]))


def read_apps():
    return {"time": time.monotonic(),
            "rows": parse_nettop(run(["nettop", "-P", "-L", "1", "-J", "bytes_in,bytes_out"], 10))}


def read_arp():
    gw = parse_gateway(run(["route", "-n", "get", "default"]))
    return {"entries": parse_arp(run(["arp", "-an"])), "gateway": gw, "me": own_ip(gw)}


class Collector:
    """Background threads that keep reading the network, so the screen never freezes."""

    def __init__(self):
        self.q = queue.Queue()
        self.stop = threading.Event()
        for tag, fn, every in (("net", read_net, 1.0), ("names", read_names, 3.0),
                               ("apps", read_apps, 3.0), ("arp", read_arp, 5.0)):
            threading.Thread(target=self.loop, args=(tag, fn, every), daemon=True).start()

    def loop(self, tag, fn, every):
        while not self.stop.is_set():
            try:
                data = fn()
            except Exception:                 # never let a reader crash the console
                data = None
            if data is not None:
                self.q.put((tag, data))
            self.stop.wait(every)

    def close(self):
        self.stop.set()


# ======================================================================= shared monitor logic
class Monitor:
    mode = ""
    keys_help = ""

    def __init__(self):
        self.t = 0.0
        self.feed = deque(maxlen=120)
        self.alerts = deque(maxlen=200)
        self.alert_times = deque()          # (t, level) for THREATCON
        self.threats = self.notices = 0
        self.last_threat = -1e9
        self.cooldown = {}
        self.flagged = {}
        self.history = deque(maxlen=HISTORY_SECONDS)
        self.blips = {}
        self.devices = []
        self.apps = []
        self.apps_have_rates = True
        self.on_alert = None

    # ---- events
    def add_feed(self, text, right, kind, ip=None):
        if ip and ip in self.flagged:
            kind = "bad"
        self.feed.append({"clock": time.strftime("%H:%M:%S"), "text": text,
                          "right": right, "kind": kind})

    def alert(self, level, key, title, detail, cooldown, ip=None):
        if self.t - self.cooldown.get(key, -1e9) < cooldown:
            return False
        self.cooldown[key] = self.t
        a = {"clock": time.strftime("%H:%M:%S"), "t": self.t, "level": level,
             "title": title, "detail": detail}
        self.alerts.append(a)
        self.alert_times.append((self.t, level))
        if level == "THREAT":
            self.threats += 1
            self.last_threat = self.t
            if ip:
                self.flagged[ip] = self.t
        else:
            self.notices += 1
        if ip and ip in self.blips:
            self.blips[ip]["level"] = "bad" if level == "THREAT" else "warn"
            self.blips[ip]["level_t"] = self.t
        if self.on_alert:
            self.on_alert(a, self.mode)
        return True

    def test_alert(self):
        self.alert("THREAT", ("test", self.t), "PRACTICE ALERT",
                   "Test started with the T key. Nothing is wrong.", 0)

    def blip(self, ip, kind, label):
        b = self.blips.get(ip)
        if b is None:
            h = zlib.crc32(ip.encode())
            if kind in ("dev", "lan"):
                r = 0.17 + (h >> 9) % 100 / 100 * 0.19
            else:
                r = 0.46 + (h >> 9) % 100 / 100 * 0.46
            b = self.blips[ip] = {"angle": h % 3600 / 10, "r": r, "kind": kind,
                                  "label": label, "level": None, "level_t": -1e9}
        if kind == "dev" or b["kind"] != "dev":
            b["kind"] = kind
        if label:
            b["label"] = label
        b["seen"] = self.t
        if ip in self.flagged and b["level"] != "bad":
            b["level"], b["level_t"] = "bad", self.t

    def tidy(self):
        for ip in [ip for ip, ft in self.flagged.items() if self.t - ft > 60]:
            del self.flagged[ip]
        for ip in [ip for ip, b in self.blips.items()
                   if self.t - b["seen"] > (60 if b["kind"] == "dev" else 20)]:
            del self.blips[ip]
        for b in self.blips.values():
            if b["level"] and self.t - b["level_t"] > 60:
                b["level"] = None
        while self.alert_times and self.t - self.alert_times[0][0] > 600:
            self.alert_times.popleft()

    # ---- status
    @property
    def danger(self):
        return self.t - self.last_threat < DANGER_SECONDS

    @property
    def threatcon(self):
        th = sum(1 for t, lv in self.alert_times if lv == "THREAT")
        no = sum(1 for t, lv in self.alert_times if lv == "NOTICE" and self.t - t < 300)
        if th >= 3 and self.t - self.last_threat < 60:
            return 4
        if th >= 2:
            return 3
        if th >= 1:
            return 2
        if no >= 1:
            return 1
        return 0

    def key(self, key):
        pass

    def close(self):
        pass


# ======================================================================= LIVE: this Mac
class LiveMonitor(Monitor):
    mode = "LIVE"
    keys_help = "ESC QUIT   F FULL SCREEN   SPACE PAUSE   T TEST ALERT   M SOUND"

    def __init__(self, first_net):
        super().__init__()
        self.names, self.app_conns = {}, Counter()
        self.prev_keys = None
        self.known_listen = set()
        self.prev_counters = self.prev_time = None
        self.pps_in = self.pps_out = self.bps_in = self.bps_out = 0.0
        self.active = 0
        self.inbound = defaultdict(deque)
        self.outbound = defaultdict(deque)
        self.new_times = deque()
        self.app_prev, self.app_prev_time = {}, None
        self.devmap = {}
        self.known_macs = None
        self.router_ip = self.router_mac = None
        self.me = None
        self.hostnames = {}
        self.sensors = {"net": True, "names": False, "apps": False, "arp": False}
        self.process_net(first_net)
        self.collector = Collector()

    def close(self):
        self.collector.close()

    def update(self, dt):
        self.t += dt
        while True:
            try:
                tag, data = self.collector.q.get_nowait()
            except queue.Empty:
                break
            self.sensors[tag] = True
            if tag == "net":
                self.process_net(data)
            elif tag == "names":
                self.names, self.app_conns = data
            elif tag == "apps":
                self.process_apps(data)
            elif tag == "arp":
                self.process_arp(data)
        self.tidy()

    # ---- connections and packet counters
    def process_net(self, snap):
        rows = snap["rows"]
        listen = {r[1] for r in rows if r[4] == "LISTEN" and r[1]}
        conns = {}
        for lip, lport, rip, rport, state in rows:
            if state == "LISTEN" or rip == "*" or rport is None or is_loopback(rip):
                continue
            conns[(lip, lport, rip, rport)] = state
        self.active = len(conns)

        c = snap["counters"]
        if c and self.prev_counters:
            gap = max(snap["time"] - self.prev_time, 0.3)
            self.pps_in = max(0, c["Ipkts"] - self.prev_counters["Ipkts"]) / gap
            self.pps_out = max(0, c["Opkts"] - self.prev_counters["Opkts"]) / gap
            self.bps_in = max(0, c["Ibytes"] - self.prev_counters["Ibytes"]) / gap
            self.bps_out = max(0, c["Obytes"] - self.prev_counters["Obytes"]) / gap
            self.history.append((self.bps_in, self.bps_out))
        if c:
            self.prev_counters, self.prev_time = c, snap["time"]

        for (lip, lport, rip, rport) in conns:
            self.blip(rip, "lan" if is_private(rip) else "net",
                      self.names.get(lport if lport not in listen else -1, ""))

        if self.prev_keys is None:
            self.prev_keys = set(conns)
            self.known_listen = set(listen)
            self.add_feed(f"SENSORS ONLINE - {len(conns)} OPEN CONNECTIONS, "
                          f"{len(listen)} LISTENING PORTS", "", "dim")
            return

        for k in conns:
            if k not in self.prev_keys:
                self.handle_new(k, conns[k], listen)
        self.prev_keys = set(conns)

        for port in sorted(listen - self.known_listen):
            self.known_listen.add(port)
            who = self.names.get(port, "A program")
            self.alert("NOTICE", ("listen", port), "NEW LISTENING PORT",
                       f"{who} is now accepting connections on port {port}", 600)
            self.add_feed(f"LISTEN {who[:20]} PORT {port} {service_name(port)}", "OPEN", "warn")

        waiting = {k[2] for k, s in conns.items() if s == "SYN_SENT"}
        if len(waiting) >= UNANSWERED_LIMIT:
            self.alert("NOTICE", "unanswered", "MANY UNANSWERED CONNECTIONS",
                       f"{len(waiting)} addresses not answering (network trouble, or a program scanning)", 60)

        while self.new_times and self.t - self.new_times[0] > WINDOW_SECONDS:
            self.new_times.popleft()
        if len(self.new_times) >= BURST_LIMIT:
            self.alert("NOTICE", "burst", "CONNECTION BURST",
                       f"{len(self.new_times)} new connections in {WINDOW_SECONDS}s", 60)

        for d in (self.inbound, self.outbound):
            for k in list(d):
                h = d[k]
                while h and self.t - h[0][0] > WINDOW_SECONDS:
                    h.popleft()
                if not h:
                    del d[k]

    def handle_new(self, k, state, listen):
        lip, lport, rip, rport = k
        self.new_times.append(self.t)
        if lport in listen:                                   # someone connecting IN
            svc = service_name(lport)
            self.add_feed(f"IN   {rip}:{rport} > PORT {lport} {svc}", state[:11],
                          "ok" if is_private(rip) else "warn", rip)
            h = self.inbound[rip]
            h.append((self.t, lport))
            ports = {p for _, p in h}
            if len(ports) >= INBOUND_SCAN_PORTS:
                self.alert("THREAT", ("inscan", rip), "POSSIBLE PORT SCAN",
                           f"{rip} touched {len(ports)} of your ports in {WINDOW_SECONDS}s", 60, rip)
            repeats = sum(1 for _, p in h if p == lport)
            if repeats >= INBOUND_REPEAT:
                self.alert("THREAT", ("brute", rip, lport), "REPEATED LOGIN ATTEMPTS",
                           f"{rip} connected {repeats}x to port {lport} {svc} - possible brute force",
                           60, rip)
        else:                                                 # this Mac connecting OUT
            who = self.names.get(lport, "?")
            svc = service_name(rport)
            self.add_feed(f"OUT  {who[:18]:<18} > {rip}:{rport} {svc}", state[:11], "ok", rip)
            h = self.outbound[rip]
            h.append((self.t, rport))
            ports = {p for _, p in h}
            if len(ports) >= OUTBOUND_SCAN_PORTS:
                self.alert("THREAT", ("outscan", rip), "PORT PROBING FROM THIS MAC",
                           f"{who} contacted {len(ports)} ports on {rip} in {WINDOW_SECONDS}s", 60, rip)
            if rport in SUSPICIOUS_PORTS:
                self.alert("THREAT", ("susp", rip, rport), "SUSPICIOUS PORT",
                           f"{who} > {rip} port {rport} ({SUSPICIOUS_PORTS[rport]})", 120, rip)
            if who != "?" and rip in self.blips:
                self.blips[rip]["label"] = who

    # ---- apps using the internet
    def process_apps(self, data):
        rows, now = data["rows"], data["time"]
        if not rows:                                         # nettop not available
            self.apps_have_rates = False
            self.apps = [(name, None, None, n) for name, n in self.app_conns.most_common(12)]
            return
        self.apps_have_rates = True
        rates = defaultdict(lambda: [0.0, 0.0])
        if self.app_prev_time is not None:
            gap = max(now - self.app_prev_time, 0.5)
            for key, app, b_in, b_out in rows:
                if key in self.app_prev:
                    p_in, p_out = self.app_prev[key]
                    r = rates[app]
                    r[0] += max(0, b_in - p_in) / gap
                    r[1] += max(0, b_out - p_out) / gap
        self.app_prev = {key: (b_in, b_out) for key, _, b_in, b_out in rows}
        self.app_prev_time = now

        def conns_for(app):
            a = app.lower()
            return sum(n for name, n in self.app_conns.items() if name.lower().startswith(a))

        apps = [(app, r[0], r[1], conns_for(app)) for app, r in rates.items()
                if r[0] + r[1] > 0]
        apps.sort(key=lambda x: -(x[1] + x[2]))
        self.apps = apps[:12]

    # ---- devices on the network
    def process_arp(self, data):
        entries, gw, me = data["entries"], data["gateway"], data["me"]
        self.me, self.router_ip = me, gw
        macs_by_ip = {ip: mac for ip, mac, _ in entries}
        first = self.known_macs is None
        if first:
            self.known_macs = {mac for _, mac, _ in entries}
            self.router_mac = macs_by_ip.get(gw)

        for ip, mac, iface in entries:
            if ip == me:
                continue
            d = self.devmap.get(mac)
            if d is None:
                d = self.devmap[mac] = {"mac": mac, "first": self.t, "new": not first}
                threading.Thread(target=self.lookup, args=(ip,), daemon=True).start()
            d["ip"], d["seen"] = ip, self.t
            d["name"] = self.hostnames.get(ip, "")
            if mac not in self.known_macs:
                self.known_macs.add(mac)
                if ip == gw and self.router_mac:          # handled by the router check below
                    continue
                self.alert("NOTICE", ("newdev", mac), "NEW DEVICE ON NETWORK",
                           f"{ip} ({mac}) just appeared on your network", 3600, ip)
                self.add_feed(f"NEW DEVICE {ip} {mac}", "JOINED", "warn")
            self.blip(ip, "dev", d["name"] or ("ROUTER" if ip == gw else ip))

        gw_mac = macs_by_ip.get(gw)
        if gw_mac and self.router_mac and gw_mac != self.router_mac:
            self.alert("THREAT", ("router", gw_mac), "ROUTER IDENTITY CHANGED",
                       f"Router {gw} changed from {self.router_mac} to {gw_mac} - possible ARP spoofing",
                       300, gw)
            self.router_mac = gw_mac
        elif gw_mac and not self.router_mac:
            self.router_mac = gw_mac
        if gw_mac:
            twins = [ip for ip, mac in macs_by_ip.items() if mac == gw_mac and ip != gw]
            if twins:
                self.alert("NOTICE", ("twin", twins[0]), "DUPLICATE ROUTER ADDRESS",
                           f"{twins[0]} uses the same hardware address as your router {gw}", 600)

        latest = {}
        for d in self.devmap.values():                       # one row per address, newest wins
            if self.t - d["seen"] < 1800 and (d["ip"] not in latest or d["seen"] >= latest[d["ip"]]["seen"]):
                latest[d["ip"]] = d
        devs = list(latest.values())
        for d in devs:
            d["role"] = "ROUTER" if d["ip"] == gw else ""
        if me:
            devs.append({"ip": me, "mac": "", "name": socket.gethostname().split(".")[0],
                         "role": "THIS MAC", "new": False, "first": 0, "seen": self.t})
        devs.sort(key=lambda d: (d["role"] != "ROUTER", d["role"] != "THIS MAC", ip_sort_key(d["ip"])))
        self.devices = devs

    def lookup(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.hostnames[ip] = name.split(".")[0] if not name.startswith(ip) else ""
        except (OSError, UnicodeError):
            pass

    def stats(self):
        return [("PKTS IN/s", f"{self.pps_in:,.0f}"), ("PKTS OUT/s", f"{self.pps_out:,.0f}"),
                ("DOWNLOAD", fmt_rate(self.bps_in)), ("UPLOAD", fmt_rate(self.bps_out)),
                ("CONNECTIONS", f"{self.active}"), ("DEVICES", f"{len(self.devices)}")]


# ======================================================================= DEMO: made-up traffic
class DemoMonitor(Monitor):
    mode = "DEMO"
    keys_help = ("ESC QUIT   F FULL SCREEN   SPACE PAUSE   T TEST   M SOUND   "
                 "B FAKE BRUTE-FORCE   P FAKE PORT SCAN   N FAKE NEW DEVICE")

    APPS = ["Safari", "Mail", "Spotify", "Dropbox", "Messages", "Music", "Slack",
            "Google Chrome", "Zoom", "softwareupdated"]

    def __init__(self):
        super().__init__()
        self.lan = [f"192.168.1.{i}" for i in (12, 23, 37, 44, 58, 71)]
        self.net = [f"{random.choice([17, 104, 142, 151, 172, 13, 52])}.{random.randint(1, 254)}."
                    f"{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(30)]
        self.habits = {ip: [443] + random.sample([443, 80, 53, 5223, 993, 22], 2)
                       for ip in self.lan + self.net}
        self.history_ip = defaultdict(deque)
        self.attacks = []
        self.next_conn = 0.0
        self.next_auto = random.uniform(12, 18)
        self.next_device = random.uniform(30, 45)
        self.bps_in = 400_000.0
        self.bps_out = 60_000.0
        self.next_sample = 0.0
        self.app_rates = {a: random.uniform(0, 200_000) for a in self.APPS}
        names = ["router", "iPhone", "iPad", "Living-Room-TV", "Printer", "Laptop"]
        self.devices = [{"ip": "192.168.1.1", "mac": "a4:83:e7:10:20:30", "name": "router",
                         "role": "ROUTER", "new": False, "first": 0}]
        for ip, n in zip(self.lan, names[1:]):
            self.devices.append({"ip": ip, "mac": ":".join(f"{random.randint(0, 255):02x}" for _ in range(6)),
                                 "name": n, "role": "", "new": False, "first": 0})
        self.devices.append({"ip": "192.168.1.5", "mac": "", "name": "this-mac",
                             "role": "THIS MAC", "new": False, "first": 0})
        self.add_feed("DEMO MODE - ALL TRAFFIC IS MADE UP", "", "dim")

    def key(self, key):
        if key == pygame.K_b:
            self.start_attack("brute")
        elif key == pygame.K_p:
            self.start_attack("scan")
        elif key == pygame.K_n:
            self.new_device()

    def start_attack(self, kind):
        ip = f"{random.choice(['185.220.101', '45.155.205', '91.240.118'])}.{random.randint(2, 254)}"
        ports = [22] * 12 if kind == "brute" else sorted(random.sample(range(1, 1025), 14))
        self.attacks.append({"ip": ip, "ports": ports, "kind": kind,
                             "gap": 0.4 if kind == "brute" else 0.25, "next": self.t})

    def new_device(self):
        ip = f"192.168.1.{random.randint(100, 200)}"
        mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
        self.devices.append({"ip": ip, "mac": mac, "name": "", "role": "", "new": True, "first": self.t})
        self.blip(ip, "dev", ip)
        self.alert("NOTICE", ("newdev", mac), "NEW DEVICE ON NETWORK",
                   f"{ip} ({mac}) just appeared on your network", 0, ip)
        self.add_feed(f"NEW DEVICE {ip} {mac}", "JOINED", "warn")

    def conn(self, ip, port, status, inbound=False):
        h = self.history_ip[ip]
        h.append((self.t, port, status))
        while h and self.t - h[0][0] > WINDOW_SECONDS:
            h.popleft()
        self.blip(ip, "lan" if is_private(ip) else "net", "")
        fails = Counter(p for _, p, s in h if s == "FAIL")
        if fails and max(fails.values()) >= 5:
            p, n = fails.most_common(1)[0]
            self.alert("THREAT", (ip, "brute"), "REPEATED LOGIN ATTEMPTS",
                       f"{ip} failed {n} {service_name(p)} logins in {WINDOW_SECONDS}s - possible brute force",
                       10, ip)
        ports = {p for _, p, _ in h}
        if len(ports) >= 6:
            self.alert("THREAT", (ip, "scan"), "POSSIBLE PORT SCAN",
                       f"{ip} touched {len(ports)} of your ports in {WINDOW_SECONDS}s", 10, ip)
        if inbound:
            self.add_feed(f"IN   {ip}:{random.randint(40000, 60000)} > PORT {port} {service_name(port)}",
                          status, "ok" if status == "OK" else "warn", ip)
        else:
            app = random.choice(self.APPS)
            self.add_feed(f"OUT  {app[:18]:<18} > {ip}:{port} {service_name(port)}",
                          "ESTABLISHED", "ok", ip)

    def update(self, dt):
        self.t += dt
        while self.t >= self.next_conn:
            self.next_conn += random.uniform(0.3, 1.2)
            ip = random.choice(self.net + self.lan[:2])
            self.conn(ip, random.choice(self.habits[ip]), "OK")
        for d in self.devices:
            if d["role"] != "THIS MAC":
                self.blip(d["ip"], "dev", d["name"] or d["ip"])
        if self.t >= self.next_auto:
            self.start_attack(random.choice(["brute", "scan"]))
            self.next_auto = self.t + random.uniform(25, 40)
        if self.t >= self.next_device:
            self.new_device()
            self.next_device = self.t + random.uniform(90, 150)
        for a in self.attacks:
            while a["ports"] and self.t >= a["next"]:
                self.conn(a["ip"], a["ports"].pop(0), "FAIL" if a["kind"] == "brute" else "CLOSED", True)
                a["next"] += a["gap"] * random.uniform(0.7, 1.3)
        self.attacks = [a for a in self.attacks if a["ports"]]
        if self.t >= self.next_sample:
            self.next_sample = self.t + 1
            self.bps_in = max(5_000, self.bps_in * random.uniform(0.7, 1.35) + random.uniform(-50_000, 80_000))
            self.bps_in = min(self.bps_in, 6_000_000)
            self.bps_out = max(2_000, self.bps_out * random.uniform(0.7, 1.3))
            self.bps_out = min(self.bps_out, 1_500_000)
            self.history.append((self.bps_in, self.bps_out))
            for a in self.app_rates:
                self.app_rates[a] = max(0, self.app_rates[a] * random.uniform(0.6, 1.4) + random.uniform(-20_000, 20_000))
            apps = [(a, r * 0.8, r * 0.2, random.randint(1, 9)) for a, r in self.app_rates.items() if r > 0]
            self.apps = sorted(apps, key=lambda x: -(x[1] + x[2]))[:12]
        self.tidy()

    def stats(self):
        pps = self.bps_in / 900
        return [("PKTS IN/s", f"{pps:,.0f}"), ("PKTS OUT/s", f"{pps * 0.6:,.0f}"),
                ("DOWNLOAD", fmt_rate(self.bps_in)), ("UPLOAD", fmt_rate(self.bps_out)),
                ("CONNECTIONS", f"{sum(1 for b in self.blips.values() if b['kind'] != 'dev')}"),
                ("DEVICES", f"{len(self.devices)}")]


# ======================================================================= sound, notifications, log
class Notifier:
    def __init__(self):
        self.muted = False
        self.last_sound = -1e9
        self.last_popup = -1e9
        self.log_path = here(LOG_FILE)
        self.mac = sys.platform == "darwin"

    def __call__(self, alert, mode):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  [{mode}]  {alert['level']:<6}  "
                        f"{alert['title']}  -  {alert['detail']}\n")
        except OSError:
            pass
        if not self.mac or self.muted:
            return
        now = time.monotonic()
        if now - self.last_sound > 3:
            self.last_sound = now
            sound = "Basso" if alert["level"] == "THREAT" else "Tink"
            self.spawn(["afplay", f"/System/Library/Sounds/{sound}.aiff"])
        if alert["level"] == "THREAT" and now - self.last_popup > 10:
            self.last_popup = now
            clean = lambda s: re.sub(r'["\\]', "", s)
            self.spawn(["osascript", "-e",
                        f'display notification "{clean(alert["detail"])}" '
                        f'with title "GhostMesh" subtitle "{clean(alert["title"])}"'])

    @staticmethod
    def spawn(cmd):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


# ======================================================================= drawing
def load_font(size, bold=False):
    return pygame.font.SysFont("menlo,monaco,consolas,dejavusansmono,couriernew",
                               max(9, int(size)), bold=bold)


def draw_text(surf, font, msg, color, pos, anchor="topleft", max_width=None):
    msg = str(msg)
    if max_width is not None and font.size(msg)[0] > max_width:
        while msg and font.size(msg + "..")[0] > max_width:
            msg = msg[:-1]
        msg += ".."
    img = font.render(msg, True, color)
    rect = img.get_rect(**{anchor: pos})
    surf.blit(img, rect)
    return rect


def brackets(surf, rect, color, length, width=2):
    x0, y0, x1, y1 = rect.left, rect.top, rect.right - 1, rect.bottom - 1
    for (x, y, dx, dy) in ((x0, y0, 1, 1), (x1, y0, -1, 1), (x0, y1, 1, -1), (x1, y1, -1, -1)):
        pygame.draw.line(surf, color, (x, y), (x + length * dx, y), width)
        pygame.draw.line(surf, color, (x, y), (x, y + length * dy), width)


def ghost_icon(surf, cx, cy, size, color):
    """Small ghost emblem for the logo."""
    r = size / 2
    pts = [(cx + math.cos(a) * r, cy - size * 0.1 + math.sin(a) * r)
           for a in [math.pi + math.pi * i / 16 for i in range(17)]]
    bottom = cy + size * 0.55
    for i in range(13):
        u = i / 12
        x = cx + r - 2 * r * u
        y = bottom - (size * 0.12 if i % 4 == 2 else 0)
        pts.append((x, y))
    pygame.draw.polygon(surf, mix(BG, color, 0.25), pts)
    pygame.draw.polygon(surf, color, pts, 2)
    for side in (-1, 1):
        pygame.draw.ellipse(surf, BG, (cx + side * size * 0.18 - size * 0.08, cy - size * 0.2,
                                       size * 0.16, size * 0.24))


class Console:
    def __init__(self, mon, notifier):
        self.mon = mon
        self.notifier = notifier
        self.size = None

    def build(self, size):
        self.size = W, H = size
        k = self.k = min(W / 1920, H / 1080)
        self.f = {"logo": load_font(34 * k, True), "h": load_font(18 * k, True),
                  "big": load_font(26 * k, True), "val": load_font(22 * k, True),
                  "mono": load_font(15 * k), "small": load_font(14 * k),
                  "tiny": load_font(12.5 * k), "con": load_font(20 * k, True)}
        m = self.m = int(16 * k)
        top = int(78 * k)
        bottom = H - int(30 * k)
        self.top, self.bottom = top, bottom
        side = int(W * 0.255)
        ch = bottom - top
        self.r_left = pygame.Rect(m, top, side, ch)
        self.r_right = pygame.Rect(W - m - side, top, side, ch)
        cx0, cx1 = self.r_left.right + m, self.r_right.left - m
        cw = cx1 - cx0
        radar_h = int(ch * 0.60)
        self.r_radar = pygame.Rect(cx0, top, cw, radar_h)
        self.r_tiles = pygame.Rect(cx0, top + radar_h + m, cw, int(64 * k))
        self.r_feed = pygame.Rect(cx0, self.r_tiles.bottom + m, cw, bottom - self.r_tiles.bottom - m)
        gh = int(ch * 0.44)
        self.r_graph = pygame.Rect(self.r_left.x, top, side, gh)
        self.r_apps = pygame.Rect(self.r_left.x, top + gh + m, side, ch - gh - m)
        ah = int(ch * 0.52)
        self.r_alerts = pygame.Rect(self.r_right.x, top, side, ah)
        self.r_devs = pygame.Rect(self.r_right.x, top + ah + m, side, ch - ah - m)

        # radar
        inner = self.r_radar.inflate(-2 * m, -2 * m)
        inner.top += int(28 * k)
        inner.height -= int(28 * k)
        self.R = R = max(40, min(inner.width, inner.height) // 2 - int(14 * k))
        self.rc = (inner.centerx, inner.centery)
        self.make_core_assets(R)

        gap = 8 * k
        tw = (self.r_tiles.width - gap * 5) / 6
        self.tile_rects = [pygame.Rect(self.r_tiles.x + i * (tw + gap), self.r_tiles.y, tw, self.r_tiles.height)
                           for i in range(6)]

        # everything that never changes is drawn ONCE here, then copied each frame (fast)
        st = pygame.Surface((W, H))
        st.fill(BG)
        step = int(48 * k)
        grid = mix(BG, GREEN_FAINT, 0.45)
        for x in range(0, W, step):
            pygame.draw.line(st, grid, (x, 0), (x, H))
        for y in range(0, H, step):
            pygame.draw.line(st, grid, (0, y), (W, y))
        for r in (self.r_graph, self.r_apps, self.r_radar, self.r_feed, self.r_alerts, self.r_devs):
            pygame.draw.rect(st, PANEL_BG, r)
            pygame.draw.rect(st, mix(PANEL_BG, GREEN, 0.35), r, max(1, int(k)))
        for r in self.tile_rects:
            pygame.draw.rect(st, PANEL_BG, r)
            pygame.draw.rect(st, GREEN_DIM, r, max(1, int(k)))
        ov = pygame.Surface((W, H), pygame.SRCALPHA)        # fine scanlines + darker edges
        line_gap = max(3, int(3 * k))
        for y in range(0, H, line_gap):
            pygame.draw.line(ov, (0, 0, 0, 30), (0, y), (W, y))
        steps = 30
        for i in range(steps):
            a = int(110 * (1 - i / steps) ** 2.2)
            w = int(i * k * 6)
            pygame.draw.rect(ov, (0, 0, 0, a), (w, w, W - 2 * w, H - 2 * w), int(6 * k) + 1)
        st.blit(ov, (0, 0))
        self.static = st

    def make_core_assets(self, R):
        """Pre-build the parts of the holographic core (done once per window size)."""
        k = self.k
        rng = random.Random(7)
        self.orb = R * 0.78                                   # radius of the particle sphere
        pts = []
        n = 420
        for i in range(n):                                    # even spread over a sphere
            y = 1 - 2 * (i + 0.5) / n
            rr = math.sqrt(1 - y * y)
            th = i * math.pi * (3 - math.sqrt(5))
            scale = rng.uniform(0.88, 1.0)
            pts.append((math.cos(th) * rr * scale, y * scale, math.sin(th) * rr * scale,
                        rng.uniform(0.6, 1.0)))
        for _ in range(140):                                  # dust inside the sphere
            v = [rng.gauss(0, 1) for _ in range(3)]
            m = math.sqrt(sum(c * c for c in v)) or 1
            r = rng.uniform(0.25, 0.85)
            pts.append((v[0] / m * r, v[1] / m * r, v[2] / m * r, rng.uniform(0.3, 0.7)))
        self.dust = pts

        def basis(tilt, turn):                                # two axes of a tilted ring
            u = (math.cos(turn), 0.0, math.sin(turn))
            v = (-math.sin(turn) * math.sin(tilt), math.cos(tilt), math.cos(turn) * math.sin(tilt))
            return u, v
        # radius, tilt, turn, arc length (deg), spin speed, thickness
        self.rings = [(0.42, 0.25, 0.3, 300, 70, 3.2), (0.62, 1.15, 1.1, 250, -45, 4.5),
                      (0.95, 1.38, 0.0, 210, 30, 6.0), (0.78, 0.55, 2.3, 140, -90, 2.5)]
        self.ring_basis = [basis(tl, tn) for _, tl, tn, *_ in self.rings]

        def glow(color, radius):
            size = int(radius * 2)
            g = pygame.Surface((size, size))
            g.fill((0, 0, 0))
            steps = 40
            for i in range(steps):
                f = i / steps
                r = radius * (1 - f)
                inten = (f ** 2.4) * 0.9
                pygame.draw.circle(g, tuple(int(c * inten) for c in color), (radius, radius), max(1, r))
            return g
        gr = int(self.orb * 0.75)
        self.core_glow = {False: glow((60, 170, 255), gr), True: glow((255, 50, 50), gr)}
        self.small_glow = {False: glow((120, 210, 255), int(30 * k)), True: glow((255, 90, 90), int(30 * k))}
        self.pulses = []

    def panel(self, surf, rect, title, color, right=None):
        k = self.k
        brackets(surf, rect, color, int(14 * k), max(2, int(2 * k)))
        pygame.draw.rect(surf, color, (rect.x + 10 * k, rect.y + 11 * k, 5 * k, 15 * k))
        draw_text(surf, self.f["h"], title, color, (rect.x + 22 * k, rect.y + 9 * k))
        if right:
            draw_text(surf, self.f["small"], right, mix(color, PANEL_BG, 0.35),
                      (rect.right - 12 * k, rect.y + 12 * k), "topright")
        y = rect.y + 34 * k
        pygame.draw.line(surf, mix(PANEL_BG, color, 0.3), (rect.x + 10 * k, y), (rect.right - 10 * k, y))
        return pygame.Rect(rect.x + 12 * k, y + 8 * k, rect.width - 24 * k, rect.bottom - y - 16 * k)

    # ---------------------------------------------------------------- frame
    def draw(self, surf, paused):
        mon, k, f = self.mon, self.k, self.f
        W, H = self.size
        danger = mon.danger
        level = mon.threatcon
        accent = CON_COLORS[level] if level >= 2 else GREEN
        t = mon.t

        surf.blit(self.static, (0, 0))
        self.draw_header(surf, level, t)
        self.draw_graph(surf)
        self.draw_apps(surf)
        self.draw_radar(surf, t, danger, accent)
        self.draw_tiles(surf)
        self.draw_feed(surf)
        self.draw_alerts(surf, t)
        self.draw_devices(surf, t)

        mute = "SOUND OFF" if self.notifier.muted else "SOUND ON"
        draw_text(surf, f["tiny"], f"{mon.keys_help}      [{mute}]", GREEN_MID,
                  (self.m, H - 10 * k), "midleft", max_width=W * 0.62)
        draw_text(surf, f["tiny"], f"WATCH-ONLY  //  NOTHING IS BLOCKED  //  LOG: {LOG_FILE}",
                  GREEN_MID, (W - self.m, H - 10 * k), "midright")

        if danger:
            pulse = (math.sin(t * 8) + 1) / 2
            pygame.draw.rect(surf, mix(BG, RED, 0.3 + 0.6 * pulse), (0, 0, W, H), int(8 * k) + 1)

        if paused:
            shade = pygame.Surface((W, H), pygame.SRCALPHA)
            shade.fill((0, 0, 0, 150))
            surf.blit(shade, (0, 0))
            draw_text(surf, f["logo"], "// PAUSED //", GREEN, (W / 2, H / 2), "center")
            draw_text(surf, f["small"], "PRESS SPACE TO RESUME", GREEN_MID, (W / 2, H / 2 + 34 * k), "center")

    def draw_header(self, surf, level, t):
        mon, k, f = self.mon, self.k, self.f
        W = self.size[0]
        y = 40 * k
        ghost_icon(surf, self.m + 22 * k, y, 34 * k, GREEN)
        r = draw_text(surf, f["logo"], "GHOSTMESH", GREEN, (self.m + 48 * k, y - 2 * k), "midleft")
        mode = "LIVE // WATCHING THIS MAC" if mon.mode == "LIVE" else "DEMO // MADE-UP TRAFFIC"
        if mon.mode == "LIVE":
            on = sum(1 for v in mon.sensors.values() if v)
            mode += f"  //  SENSORS {on}/4"
        r1 = draw_text(surf, f["small"], "NETWORK DEFENSE CONSOLE", GREEN_MID,
                       (r.right + 14 * k, y - 2 * k), "bottomleft")
        r2 = draw_text(surf, f["tiny"], mode, GREEN_DIM if mon.mode == "LIVE" else AMBER,
                       (r.right + 14 * k, y + 1 * k), "topleft")
        text_end = max(r1.right, r2.right)

        # THREATCON bar
        seg_w, seg_h = 86 * k, 26 * k
        total = seg_w * 5 + 6 * k * 4
        label_w = f["h"].size("THREATCON")[0] + 12 * k
        x0 = max(W / 2 - total / 2 + label_w / 2, text_end + 30 * k + label_w)
        draw_text(surf, f["h"], "THREATCON", GREEN_MID, (x0 - 12 * k, y), "midright")
        for i, name in enumerate(THREATCON):
            rect = pygame.Rect(x0 + i * (seg_w + 6 * k), y - seg_h / 2, seg_w, seg_h)
            col = CON_COLORS[i]
            if i == level:
                blink = level >= 3 and int(t * 3) % 2
                pygame.draw.rect(surf, mix(col, BG, 0.5 if blink else 0), rect)
                draw_text(surf, f["small"], name, BG, rect.center, "center")
            else:
                pygame.draw.rect(surf, mix(BG, col, 0.12), rect)
                pygame.draw.rect(surf, mix(BG, col, 0.4), rect, 1)
                draw_text(surf, f["small"], name, mix(BG, col, 0.55), rect.center, "center")

        zulu = time.strftime("%H:%M:%S", time.gmtime())
        local = time.strftime("%H:%M:%S")
        up = f"{int(t // 3600):02d}:{int(t // 60 % 60):02d}:{int(t % 60):02d}"
        draw_text(surf, f["con"], f"{local}", GREEN, (W - self.m, y - 10 * k), "midright")
        draw_text(surf, f["tiny"], f"ZULU {zulu}Z    UPTIME {up}", GREEN_MID, (W - self.m, y + 12 * k), "midright")

    def draw_graph(self, surf):
        mon, k, f = self.mon, self.k, self.f
        g = self.panel(surf, self.r_graph, "TRAFFIC", GREEN, "LAST 3 MIN")
        hist = list(mon.history)
        legend_y = g.y
        pygame.draw.rect(surf, GREEN, (g.x, legend_y + 4 * k, 10 * k, 10 * k))
        r = draw_text(surf, f["small"], "DOWNLOAD", GREEN, (g.x + 16 * k, legend_y))
        pygame.draw.rect(surf, AMBER, (r.right + 18 * k, legend_y + 4 * k, 10 * k, 10 * k))
        draw_text(surf, f["small"], "UPLOAD", AMBER, (r.right + 34 * k, legend_y))
        peak = max([max(a, b) for a, b in hist] + [10_000]) * 1.15
        lw = max(f["tiny"].size(fmt_rate(peak * i / 4))[0] for i in range(5)) + 10 * k
        plot = pygame.Rect(g.x + lw, g.y + 26 * k, g.width - lw - 6 * k, g.height - 48 * k)
        for i in range(5):
            yy = plot.bottom - plot.height * i / 4
            pygame.draw.line(surf, GREEN_FAINT, (plot.x, yy), (plot.right, yy))
            draw_text(surf, f["tiny"], fmt_rate(peak * i / 4), GREEN_DIM, (plot.x - 6 * k, yy), "midright")
        for i, lab in enumerate(["-3M", "-2M", "-1M", "NOW"]):
            xx = plot.x + plot.width * i / 3
            pygame.draw.line(surf, GREEN_FAINT, (xx, plot.y), (xx, plot.bottom))
            draw_text(surf, f["tiny"], lab, GREEN_DIM, (xx, plot.bottom + 4 * k), "midtop")
        if len(hist) >= 2:
            n = HISTORY_SECONDS
            off = n - len(hist)
            for idx, col in ((1, AMBER), (0, GREEN)):
                pts = [(plot.x + plot.width * (off + i) / (n - 1),
                        plot.bottom - plot.height * min(1, h[idx] / peak)) for i, h in enumerate(hist)]
                fill = pygame.Surface(plot.size, pygame.SRCALPHA)
                poly = [(x - plot.x, y - plot.y) for x, y in pts]
                poly += [(poly[-1][0], plot.height), (poly[0][0], plot.height)]
                pygame.draw.polygon(fill, (*col, 45), poly)
                surf.blit(fill, plot.topleft)
                pygame.draw.lines(surf, col, False, pts, max(2, int(2 * k)))
            pygame.draw.circle(surf, GREEN, (int(pts[-1][0]), int(pts[-1][1])), int(4 * k) + 1)
        else:
            draw_text(surf, f["small"], "COLLECTING DATA...", GREEN_DIM, plot.center, "center")

    def draw_apps(self, surf):
        mon, k, f = self.mon, self.k, self.f
        right = "DATA RATE" if mon.apps_have_rates else "CONNECTIONS"
        g = self.panel(surf, self.r_apps, "TOP APPS", GREEN, right)
        rows = mon.apps
        if not rows:
            draw_text(surf, f["small"], "WAITING FOR APP DATA...", GREEN_DIM, (g.x, g.y))
            return
        row_h = 24 * k
        maxv = max((a[1] + a[2]) if a[1] is not None else a[3] for a in rows) or 1
        name_w = g.width * 0.42
        bar_x, bar_w = g.x + name_w, g.width * 0.30
        for i, (name, rin, rout, n) in enumerate(rows):
            y = g.y + i * row_h
            if y + row_h > g.bottom:
                break
            v = (rin + rout) if rin is not None else n
            draw_text(surf, f["mono"], name.upper(), TEXT, (g.x, y), max_width=name_w - 8 * k)
            pygame.draw.rect(surf, GREEN_FAINT, (bar_x, y + 4 * k, bar_w, 10 * k))
            pygame.draw.rect(surf, GREEN if i else mix(GREEN, WHITE, 0.3),
                             (bar_x, y + 4 * k, max(2, bar_w * v / maxv), 10 * k))
            label = fmt_rate(v) if rin is not None else f"{n} CONN"
            draw_text(surf, f["mono"], label, GREEN, (g.right, y), "topright")

    def draw_radar(self, surf, t, danger, accent):
        """Holographic core: particle sphere, spinning rings, contacts and data pulses."""
        mon, k, f = self.mon, self.k, self.f
        count = len(mon.blips)
        self.panel(surf, self.r_radar, "CORE // CONTACTS", accent if danger else GREEN,
                   f"{count} CONTACTS")
        cx, cy = self.rc
        O = self.orb
        hot = RED if danger else GREEN
        traffic = mon.history[-1][0] if mon.history else 0
        energy = min(1.0, traffic / 3_000_000)
        spin = 1.0 + energy * 1.5 + (2.5 if danger else 0)
        self.spin_angle = getattr(self, "spin_angle", 0.0) + spin * 0.004
        yaw = self.spin_angle
        pitch = 0.32 + 0.08 * math.sin(t * 0.3)
        cyw, syw, cp, sp = math.cos(yaw), math.sin(yaw), math.cos(pitch), math.sin(pitch)

        def project(x, y, z):
            x1 = x * cyw + z * syw
            z1 = -x * syw + z * cyw
            y2 = y * cp - z1 * sp
            z2 = y * sp + z1 * cp
            persp = 3.2 / (3.2 + z2)
            return cx + x1 * persp * O, cy + y2 * persp * O, z2

        # glow behind everything
        pulse = 1 + 0.06 * math.sin(t * (9 if danger else 2.5)) + energy * 0.15
        g = self.core_glow[danger]
        if pulse != 1:
            size = int(g.get_width() * pulse)
            g = pygame.transform.scale(g, (size, size))
        surf.blit(g, g.get_rect(center=(cx, cy)), special_flags=pygame.BLEND_ADD)

        # outer HUD arcs (flat, slowly turning)
        for i, (rad, start, length, speed, width) in enumerate(
                ((1.18, 0, 70, 12, 3), (1.18, 150, 40, 12, 3), (1.18, 230, 95, 12, 3),
                 (1.10, 40, 120, -20, 2), (1.10, 220, 60, -20, 2), (1.26, 300, 25, 6, 5))):
            rr = O * rad
            a0 = math.radians(start + t * speed * (2 if danger else 1))
            rect = pygame.Rect(0, 0, rr * 2, rr * 2)
            rect.center = (cx, cy)
            pygame.draw.arc(surf, mix(PANEL_BG, hot, 0.55), rect, a0, a0 + math.radians(length),
                            max(1, int(width * k)))
        pygame.draw.circle(surf, mix(PANEL_BG, hot, 0.25), (cx, cy), int(O * 1.04), max(1, int(k)))

        # particle sphere (far side dim, near side bright)
        for x, y, z, b in self.dust:
            sx, sy, d = project(x, y, z)
            lit = (0.25 + 0.75 * (1 - (d + 1) / 2)) * b
            pygame.draw.circle(surf, mix(PANEL_BG, mix(hot, WHITE, 0.25), lit), (sx, sy),
                               max(1, (1.0 + lit * 1.6) * k))

        # tilted rings with spinning bright arcs
        for (r, _, _, length, speed, thick), (u, v) in zip(self.rings, self.ring_basis):
            start = math.radians(t * speed * spin)
            segs = 70
            span = math.radians(length)
            prev = None
            for i in range(segs + 1):
                th = start + span * i / segs
                c1, s1 = math.cos(th) * r, math.sin(th) * r
                p = project(c1 * u[0] + s1 * v[0], c1 * u[1] + s1 * v[1], c1 * u[2] + s1 * v[2])
                if prev:
                    fade = (i / segs) ** 0.8                  # bright head, fading tail
                    depth = 0.45 + 0.55 * (1 - (p[2] / r + 1) / 2)
                    col = mix(PANEL_BG, mix(hot, WHITE, 0.15 * fade), (0.2 + 0.8 * fade) * depth)
                    pygame.draw.line(surf, mix(PANEL_BG, col, 0.55), prev[:2], p[:2],
                                     max(2, int(thick * 2.6 * k)))
                    pygame.draw.line(surf, col, prev[:2], p[:2], max(1, int(thick * k)))
                prev = p

        # contacts: inner shell = your network, outer shell = internet
        spots = {}
        for ip, bl in mon.blips.items():
            h = zlib.crc32(ip.encode())
            lon = math.radians(bl["angle"])
            lat = math.radians(((h >> 16) % 140) - 70)
            rad = 0.48 + bl["r"] * 0.3 if bl["kind"] in ("dev", "lan") else 0.86 + (h >> 8) % 10 / 100
            x, y, z = math.cos(lat) * math.cos(lon) * rad, math.sin(lat) * rad, math.cos(lat) * math.sin(lon) * rad
            spots[ip] = project(x, y, z)

        # data pulses flowing into the core
        rate = 2 + energy * 14
        if spots and random.random() < rate / FPS:
            self.pulses.append([random.choice(list(spots)), 0.0])
        alive = []
        for pl in self.pulses:
            pl[1] += 1.2 / FPS
            if pl[1] < 1 and pl[0] in spots:
                sx, sy, _ = spots[pl[0]]
                e = pl[1] ** 1.6
                px, py = lerp(sx, cx, e), lerp(sy, cy, e)
                pygame.draw.line(surf, mix(PANEL_BG, hot, 0.35 * (1 - pl[1])), (sx, sy), (px, py), max(1, int(k)))
                pygame.draw.circle(surf, mix(hot, WHITE, 0.6), (px, py), max(2, 2.5 * k))
                alive.append(pl)
        self.pulses = alive[-80:]

        threats = []
        for ip, (sx, sy, d) in sorted(spots.items(), key=lambda kv: -kv[1][2]):
            bl = mon.blips[ip]
            front = 0.35 + 0.65 * (1 - (d + 1) / 2)
            if bl["level"] == "bad":
                col = RED
                threats.append((sx, sy, ip))
                pygame.draw.line(surf, mix(PANEL_BG, RED, 0.5), (sx, sy), (cx, cy), max(1, int(k)))
            elif bl["level"] == "warn":
                col = AMBER
            else:
                col = mix(GREEN, WHITE, 0.35)
            c = mix(PANEL_BG, col, front)
            size = (3.2 if bl["kind"] != "dev" else 4.2) * k + 1
            if bl["kind"] == "dev":
                pygame.draw.rect(surf, c, (sx - size, sy - size, size * 2, size * 2), max(1, int(k)))
                if bl["label"] and front > 0.6:
                    draw_text(surf, f["tiny"], bl["label"].upper()[:14], mix(PANEL_BG, TEXT, front * 0.8),
                              (sx + 8 * k, sy - 7 * k))
            else:
                pygame.draw.circle(surf, c, (sx, sy), size)

        # bright core in the middle
        sg = self.small_glow[danger]
        surf.blit(sg, sg.get_rect(center=(cx, cy)), special_flags=pygame.BLEND_ADD)
        ring_r = O * (0.2 + 0.015 * math.sin(t * 3))
        pygame.draw.circle(surf, mix(PANEL_BG, hot, 0.7), (cx, cy), ring_r, max(2, int(5 * k)))
        pygame.draw.circle(surf, mix(hot, WHITE, 0.5), (cx, cy), ring_r, max(1, int(1.5 * k)))
        pygame.draw.circle(surf, mix(hot, WHITE, 0.85), (cx, cy), O * (0.07 + 0.01 * energy))

        for x, y, ip in threats[:6]:                          # target-lock boxes on threats
            sz = (14 + 3 * math.sin(t * 6)) * k
            box = pygame.Rect(0, 0, sz * 2, sz * 2)
            box.center = (x, y)
            brackets(surf, box, RED, int(6 * k) + 2, max(2, int(2 * k)))
            pygame.draw.line(surf, RED, (x + sz, y - sz), (x + sz + 18 * k, y - sz - 14 * k), max(1, int(k)))
            draw_text(surf, f["small"], f"HOSTILE {ip}", RED, (x + sz + 20 * k, y - sz - 22 * k))

        level = "CORE LOAD " + fmt_rate(traffic)
        draw_text(surf, f["tiny"], level, GREEN_MID,
                  (self.r_radar.x + 14 * k, self.r_radar.bottom - 12 * k), "bottomleft")
        draw_text(surf, f["tiny"], "O CONNECTION    [] DEVICE    RED = HOSTILE", GREEN_MID,
                  (self.r_radar.right - 14 * k, self.r_radar.bottom - 12 * k), "bottomright")

        if t < 4.5:                                           # start-up sequence
            lines = ["> PACKET COUNTERS ........ ONLINE", "> CONNECTION TABLE ....... ONLINE",
                     "> APP TRAFFIC SENSOR ..... ONLINE", "> NETWORK DEVICE SENSOR .. ONLINE",
                     "> THREAT ENGINE .......... ARMED"]
            for i, line in enumerate(lines[:int(t / 0.7)]):
                draw_text(surf, f["small"], line, GREEN,
                          (self.r_radar.x + 16 * k, self.r_radar.y + 48 * k + i * 18 * k))
        if danger and int(t * 3) % 2 == 0:
            draw_text(surf, f["big"], "!! THREAT DETECTED !!", RED, (cx, self.r_radar.y + 52 * k), "center")

    def draw_tiles(self, surf):
        mon, k, f = self.mon, self.k, self.f
        stats = mon.stats()
        for (label, value), t in zip(stats, self.tile_rects):
            tw = t.width
            brackets(surf, t, GREEN_MID, int(8 * k), max(1, int(k)))
            draw_text(surf, f["tiny"], label, GREEN_DIM, (t.x + 8 * k, t.y + 7 * k), max_width=tw - 12 * k)
            draw_text(surf, f["val"], value, GREEN, (t.x + 8 * k, t.y + 24 * k), max_width=tw - 12 * k)

    def draw_feed(self, surf):
        mon, k, f = self.mon, self.k, self.f
        g = self.panel(surf, self.r_feed, "LIVE CONNECTIONS", GREEN, "NEWEST FIRST")
        row = 18 * k
        colors = {"ok": GREEN, "warn": AMBER, "bad": RED, "dim": GREEN_DIM}
        for i, e in enumerate(list(mon.feed)[::-1]):
            y = g.y + i * row
            if y + row > g.bottom:
                break
            c = colors[e["kind"]]
            rr = draw_text(surf, f["mono"], e["right"], c, (g.right, y), "topright")
            text_col = RED if e["kind"] == "bad" else (GREEN_DIM if e["kind"] == "dim" else TEXT)
            draw_text(surf, f["mono"], f"{e['clock']}  {e['text']}", text_col, (g.x, y),
                      max_width=rr.left - g.x - 12 * k)

    def draw_alerts(self, surf, t):
        mon, k, f = self.mon, self.k, self.f
        col = RED if mon.threats else GREEN
        g = self.panel(surf, self.r_alerts, "ALERTS", col,
                       f"{mon.threats} THREATS / {mon.notices} NOTICES")
        if not mon.alerts:
            draw_text(surf, f["mono"], "NO SUSPICIOUS ACTIVITY.", GREEN, (g.x, g.y))
            draw_text(surf, f["mono"], "ALL CLEAR.", GREEN, (g.x, g.y + 18 * k))
            return
        y = g.y
        for a in list(mon.alerts)[::-1]:
            if y + 44 * k > g.bottom:
                break
            base = RED if a["level"] == "THREAT" else AMBER
            fresh = t - a["t"] < DANGER_SECONDS
            c = base if fresh else mix(base, PANEL_BG, 0.35)
            tag = pygame.Rect(g.x, y, 70 * k, 18 * k)
            pygame.draw.rect(surf, c, tag)
            draw_text(surf, f["tiny"], a["level"], PANEL_BG, tag.center, "center")
            draw_text(surf, f["mono"], f"{a['clock']}  {a['title']}", c, (tag.right + 8 * k, y),
                      max_width=g.right - tag.right - 8 * k)
            draw_text(surf, f["small"], a["detail"], mix(TEXT, PANEL_BG, 0.25), (g.x, y + 20 * k),
                      max_width=g.width)
            y += 46 * k

    def draw_devices(self, surf, t):
        mon, k, f = self.mon, self.k, self.f
        g = self.panel(surf, self.r_devs, "NETWORK DEVICES", GREEN, f"{len(mon.devices)} SEEN")
        if not mon.devices:
            draw_text(surf, f["small"], "SCANNING YOUR NETWORK TABLE...", GREEN_DIM, (g.x, g.y))
            return
        row = 22 * k
        for i, d in enumerate(mon.devices):
            y = g.y + i * row
            if y + row > g.bottom:
                draw_text(surf, f["small"], f"+{len(mon.devices) - i} MORE", GREEN_DIM, (g.x, y))
                break
            new = d.get("new") and mon.t - d.get("first", 0) < 300
            hostile = d["ip"] in mon.flagged and d.get("role") != "THIS MAC"
            col = RED if hostile else (AMBER if new else GREEN)
            pygame.draw.rect(surf, col, (g.x, y + 5 * k, 8 * k, 8 * k))
            draw_text(surf, f["mono"], d["ip"], TEXT, (g.x + 16 * k, y))
            name = (d.get("name") or d.get("mac") or "").upper()
            tag = d.get("role") or ("NEW" if new else "")
            rr = draw_text(surf, f["small"], tag, col, (g.right, y + 1 * k), "topright") if tag else \
                pygame.Rect(g.right, y, 0, 0)
            draw_text(surf, f["small"], name, GREEN_MID, (g.x + g.width * 0.40, y + 1 * k),
                      max_width=rr.left - (g.x + g.width * 0.40) - 8 * k)


# ======================================================================= the window (sharp on Retina)
class Display:
    """Draws at the screen's full pixel detail on Retina Macs, so nothing is blurry.
    Falls back to a normal window on older pygame versions."""

    TITLE = "GhostMesh - Network Defense Console"
    MIN_SIZE = (900, 580)

    def __init__(self):
        desktop = pygame.display.get_desktop_sizes()[0]
        self.desktop = desktop
        self.window_size = (int(desktop[0] * 0.92), int(desktop[1] * 0.86))
        self.full = False
        self.sharp = False
        try:
            from pygame._sdl2.video import Renderer, Texture
            self.Texture = Texture
            self.window = pygame.Window(self.TITLE, self.window_size, resizable=True, allow_high_dpi=True)
            try:
                self.window.minimum_size = self.MIN_SIZE
            except Exception:
                pass
            self.renderer = Renderer(self.window, vsync=False)
            self.sharp = True
        except Exception:
            self.window = None
        self.canvas = None
        self.texture = None
        self.make_canvas()

    def pixel_size(self):
        if self.sharp:
            vp = self.renderer.get_viewport()
            if vp.width > 0 and vp.height > 0:
                return vp.size
            return self.window.size
        return pygame.display.get_surface().get_size()

    def make_canvas(self):
        if self.sharp:
            size = self.pixel_size()
            self.canvas = pygame.Surface(size)
            self.texture = self.Texture(self.renderer, size, streaming=True)
        else:
            pygame.display.set_caption(self.TITLE)
            flags = pygame.FULLSCREEN if self.full else pygame.RESIZABLE
            self.canvas = pygame.display.set_mode(self.desktop if self.full else self.window_size, flags)

    def check_resize(self):
        """True if the window changed size (the screen layout must be rebuilt)."""
        if self.sharp:
            self.renderer.set_viewport(None)          # make sure we measure the whole window
            if self.pixel_size() != self.canvas.get_size():
                self.make_canvas()
                return True
            return False
        size = pygame.display.get_surface().get_size()
        if size != self.canvas.get_size():
            self.canvas = pygame.display.get_surface()
            if not self.full:
                self.window_size = size
            return True
        return False

    def toggle_fullscreen(self):
        self.full = not self.full
        if self.sharp:
            if self.full:
                self.window.set_fullscreen(desktop=True)
            else:
                self.window.set_windowed()
        else:
            self.make_canvas()

    def present(self):
        if self.sharp:
            self.texture.update(self.canvas)
            self.renderer.blit(self.texture, self.texture.get_rect())
            self.renderer.present()
        else:
            pygame.display.flip()


# ======================================================================= main
def main():
    demo = "--demo" in sys.argv
    mon = None
    if not demo:
        if sys.platform == "darwin":
            print("GhostMesh: bringing sensors online...")
            first = read_net()
            if first:
                mon = LiveMonitor(first)
                print("GhostMesh: LIVE. Press ESC in the GhostMesh screen to quit.")
        if mon is None:
            print("GhostMesh: live mode only works on a Mac, starting DEMO mode.")
    if mon is None:
        mon = DemoMonitor()

    notifier = Notifier()
    mon.on_alert = notifier

    pygame.init()
    display = Display()
    console = Console(mon, notifier)
    console.build(display.canvas.get_size())
    clock = pygame.time.Clock()
    paused = False

    try:
        while True:
            dt = min(clock.tick(FPS) / 1000.0, 0.1)
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    return
                if event.type == pygame.KEYDOWN:
                    if event.key in (pygame.K_ESCAPE, pygame.K_q):
                        return
                    if event.key == pygame.K_SPACE:
                        paused = not paused
                    elif event.key == pygame.K_m:
                        notifier.muted = not notifier.muted
                    elif event.key == pygame.K_f:
                        display.toggle_fullscreen()
                    elif not paused and event.key == pygame.K_t:
                        mon.test_alert()
                    elif not paused:
                        mon.key(event.key)
            if display.check_resize():
                console.build(display.canvas.get_size())
            if not paused:
                mon.update(dt)
            console.draw(display.canvas, paused)
            display.present()
    finally:
        mon.close()
        pygame.quit()


if __name__ == "__main__":
    main()
