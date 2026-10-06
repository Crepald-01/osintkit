#!/usr/bin/env python3
"""osintkit - 19 defensive/research OSINT tools in one stdlib-only CLI.

  headers   analyze raw email headers (relay path, SPF/DKIM/DMARC, spoof flags)
  company   company registries (SEC EDGAR, Companies House, OpenCorporates)
  wayback   what changed on a page over time (Wayback Machine diff)
  fly       aircraft (ADS-B) lookup / watch / geofence alerts
  vessel    ship (AIS) lookup via Digitraffic (Finnish/Baltic coverage)
  sat       Sentinel-2 scene search and before/after comparison
  monitor   keyword monitor for RSS/Atom feeds and public Telegram channels
  meta      document metadata leaks (local files or a site's public docs)
  ioc       IP/domain/URL/hash enrichment with one verdict
  brand     brand-side exposure check (HIBP domain breaches, GitHub mentions)
  factcheck claim lookup via Google Fact Check API (+ reverse-image links)
  domain    domain recon: DNS, SPF/DMARC, RDAP age, security headers, subdomains
  typosquat find registered lookalike domains of your brand
  username  check where a username exists across ~28 sites
  exposure  open ports + known CVEs for an IP/domain (Shodan InternetDB)
  cve       CVE severity, exploited-in-the-wild (CISA KEV), EPSS
  tls       TLS certificate inspector + related names
  exif      photo metadata and embedded GPS
  ip        IP location, network owner, Tor-exit check
  setup     guided API key setup
  doctor    show which API keys are configured

Use only on public data, your own assets, or with authorization.
"""
import argparse, base64, difflib, html, io, ipaddress, json, math, os, re, sys, time, zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from email import policy, utils as eutils
from email.parser import Parser
from urllib import error, parse, request

KEYFILE = os.path.join(os.path.expanduser("~"), ".osintkit", "keys.json")
try:  # keys saved by `osintkit setup`; real environment variables win
    for _k, _v in json.load(open(KEYFILE)).items():
        os.environ.setdefault(_k, _v)
except Exception:
    pass
CONTACT = os.environ.get("OSINTKIT_CONTACT", "osintkit-user@example.com")
UA = f"osintkit/1.0 ({CONTACT})"
STATE = os.path.join(os.path.expanduser("~"), ".osintkit")

KEYS = {
    "OSINTKIT_CONTACT": "your email, sent in User-Agent (SEC requires one)",
    "COMPANIES_HOUSE_KEY": "Companies House API key (company)",
    "OPENCORPORATES_KEY": "OpenCorporates API token (company)",
    "VT_API_KEY": "VirusTotal (ioc)",
    "ABUSEIPDB_KEY": "AbuseIPDB (ioc)",
    "ABUSECH_KEY": "abuse.ch Auth-Key for URLhaus (ioc)",
    "GREYNOISE_KEY": "GreyNoise, optional (ioc)",
    "HIBP_KEY": "Have I Been Pwned, domain search (brand)",
    "GITHUB_TOKEN": "GitHub code search (brand)",
    "GOOGLE_API_KEY": "Google Fact Check Tools (factcheck)",
}


# ---------------------------------------------------------------- helpers
class Err(Exception):
    pass


# ---------------------------------------------------------------- UI layer
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
os.system("")  # enables ANSI escape codes in Windows consoles
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_print = print


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else s


RULES = [  # (regex, ansi) first match wins; applied per output line when color is on
    (r"\[!\]|ALERT|MALICIOUS|HIGH\b|LIKELY FALSE|(?<!no )\bfail\b|= fail", "1;31"),
    (r"SUSPICIOUS|MEDIUM|MIXED|warn", "33"),
    (r"skipped|not present|no Received", "2;33"),
    (r"NO KNOWN BAD|\bLOW\b|LIKELY TRUE|\bpass\b|No spoofing", "32"),
    (r"^\s*\[\d+\]", "36"),
]


def print(*args, **kw):  # noqa: A001 - module-wide colorizing print
    if COLOR and not kw.get("file") and args and all(isinstance(x, str) for x in args) and "\033" not in "".join(args):
        out = []
        for line in kw.pop("sep", " ").join(args).split("\n"):
            for rx, code in RULES:
                if re.search(rx, line):
                    line = c(code, line)
                    break
            out.append(line)
        return _print("\n".join(out), **kw)
    return _print(*args, **kw)


NOSPIN = False  # set while worker threads make many requests at once


class Spinner:
    FR = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, msg):
        self.msg = msg
        self.on = sys.stderr.isatty() and not os.environ.get("NO_COLOR") and not NOSPIN

    def __enter__(self):
        if self.on:
            import threading
            self.stop = threading.Event()
            self.t = threading.Thread(target=self._spin, daemon=True)
            self.t.start()
        return self

    def _spin(self):
        i = 0
        while not self.stop.wait(0.08):
            sys.stderr.write(f"\r\033[36m{self.FR[i % len(self.FR)]}\033[0m \033[2m{self.msg}\033[0m\033[K")
            sys.stderr.flush()
            i += 1

    def __exit__(self, *a):
        if self.on:
            self.stop.set()
            self.t.join()
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


BANNER = r"""
  ___  ____ ___ _   _ _____ _  _____ _____
 / _ \/ ___|_ _| \ | |_   _| |/ /_ _|_   _|
| | | \___ \| ||  \| | | | | ' / | |  | |
| |_| |___) | || |\  | | | | . \ | |  | |
 \___/|____/___|_| \_| |_| |_|\_\___| |_|
"""


def banner():
    if not COLOR:
        _print("osintkit - open-source intelligence toolkit")
        return
    for i, l in enumerate(BANNER.strip("\n").splitlines()):
        _print(f"\033[1;38;5;{[51, 45, 39, 33, 27][i % 5]}m{l}\033[0m")
    _print(c("2", f" {len(MENU) - 2} tools · public data only · use on assets you own or are authorized to assess\n"))


def http(url, headers=None, data=None, method=None, js=False, raw=False, timeout=30):
    h = {"User-Agent": UA, "Accept": "application/json" if js else "*/*"}
    h.update(headers or {})
    if isinstance(data, dict):
        data = parse.urlencode(data).encode()
    req = request.Request(url, data=data, headers=h, method=method)
    try:
        with Spinner(f"fetching {parse.urlparse(url).netloc}"), request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except error.HTTPError as e:
        raise Err(f"HTTP {e.code} from {parse.urlparse(url).netloc}: {e.read()[:200].decode('utf8','replace')}")
    except Exception as e:
        raise Err(f"request to {parse.urlparse(url).netloc} failed: {e}")
    if raw:
        return body
    text = body.decode("utf8", "replace")
    return json.loads(text) if js else text


def need(var):
    v = os.environ.get(var)
    if not v:
        raise Err(f"set {var} ({KEYS.get(var, '')})")
    return v


def h1(t):
    _print("\n" + (c("1;36", f"── {t} " + "─" * max(2, 60 - len(t))) if COLOR else f"=== {t} ==="))


def strip_html(s):
    s = re.sub(r"(?is)<(script|style|noscript).*?</\1>", " ", s)
    s = re.sub(r"(?i)<(br|/p|/div|/li|/h\d|/tr)[^>]*>", "\n", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = html.unescape(s)
    lines = (re.sub(r"[ \t]+", " ", l).strip() for l in s.splitlines())
    return "\n".join(l for l in lines if l)


def haversine_km(a, b, c, d):
    p = math.pi / 180
    x = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742 * math.asin(math.sqrt(x))


def load_state(name):
    try:
        with open(os.path.join(STATE, name)) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(name, obj):
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, name), "w") as f:
        json.dump(obj, f)


# ---------------------------------------------------------------- 11 headers
def cmd_headers(a):
    raw = open(a.file, encoding="utf8", errors="replace").read() if a.file else sys.stdin.read()
    msg = Parser(policy=policy.default).parsestr(raw, headersonly=True)
    flags = []

    h1("Relay path (origin -> destination)")
    hops = msg.get_all("Received") or []
    prev = None
    for i, r in enumerate(reversed(hops), 1):
        r1 = " ".join(str(r).split())
        frm = re.search(r"from\s+(\S+)", r1)
        by = re.search(r"\bby\s+([^\s;]+)", r1)
        ips = re.findall(r"[\[(](\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,})[\])]", r1)
        ts = None
        if ";" in r1:
            try:
                ts = eutils.parsedate_to_datetime(r1.rsplit(";", 1)[1].strip())
            except Exception:
                pass
        delay = ""
        if ts and prev:
            d = (ts - prev).total_seconds()
            delay = f"  (+{d:.0f}s)"
            if d < -60:
                flags.append(f"hop {i}: timestamp goes backwards ({d:.0f}s) - forged or clock-skewed header")
            if d > 3600:
                flags.append(f"hop {i}: {d/3600:.1f}h delay between hops")
        if ts:
            prev = ts
        print(f" {i}. from {frm.group(1) if frm else '?'} -> by {by.group(1) if by else '?'} "
              f"ips={','.join(ips) or '-'}  {ts.isoformat() if ts else ''}{delay}")
    if not hops:
        flags.append("no Received headers (stripped or not a real delivered message)")

    h1("Authentication")
    auth = " ".join(str(x) for x in (msg.get_all("Authentication-Results") or []))
    res = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{k}=(\w+)", auth, re.I)
        res[k] = m.group(1).lower() if m else None
    rspf = msg.get("Received-SPF")
    if rspf and not res["spf"]:
        res["spf"] = str(rspf).split()[0].lower()
    for k, v in res.items():
        print(f" {k.upper():6} {v or 'not present'}")
        if v is None:
            flags.append(f"no {k.upper()} result recorded")
        elif v not in ("pass", "none") and not (k == "dmarc" and v == "bestguesspass"):
            flags.append(f"{k.upper()} = {v}")
    dkim_d = re.search(r"header\.d=([\w.-]+)", auth) or re.search(r"\bd=([\w.-]+)", str(msg.get("DKIM-Signature", "")))

    h1("Identity checks")
    fname, faddr = eutils.parseaddr(str(msg.get("From", "")))
    fdom = faddr.rpartition("@")[2].lower()
    rp = eutils.parseaddr(str(msg.get("Return-Path", "")))[1]
    rpdom = rp.rpartition("@")[2].lower()
    reply = eutils.parseaddr(str(msg.get("Reply-To", "")))[1]
    print(f" From:        {fname!r} <{faddr}>")
    print(f" Return-Path: {rp or '-'}")
    print(f" Reply-To:    {reply or '-'}")
    print(f" Subject:     {msg.get('Subject', '')}")
    org = lambda d: ".".join(d.split(".")[-2:])
    if rpdom and fdom and org(rpdom) != org(fdom):
        flags.append(f"Return-Path domain ({rpdom}) differs from From domain ({fdom})")
    if reply and fdom and org(reply.rpartition("@")[2].lower()) != org(fdom):
        flags.append(f"Reply-To domain ({reply.rpartition('@')[2]}) differs from From domain ({fdom})")
    if dkim_d and fdom and org(dkim_d.group(1).lower()) != org(fdom):
        flags.append(f"DKIM signing domain ({dkim_d.group(1)}) not aligned with From domain ({fdom})")
    em = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", fname or "")
    if em and em.group(0).lower() != faddr.lower():
        flags.append(f"display name contains a different address ({em.group(0)})")
    if re.search(r"xn--", fdom):
        flags.append(f"From domain is punycode/IDN ({fdom}) - check for homoglyphs")
    if msg.get("X-Mailer") or msg.get("User-Agent"):
        print(f" Client:      {msg.get('X-Mailer') or msg.get('User-Agent')}")

    h1("Verdict")
    if not flags:
        print(" No spoofing indicators found (not proof of legitimacy).")
    else:
        for f in flags:
            print(" [!]", f)
        score = len(flags)
        lvl = "HIGH" if score >= 4 else "MEDIUM" if score >= 2 else "LOW"
        panel("Spoofing risk", [f"{lvl} - {score} indicator(s) found"], "31" if lvl == "HIGH" else "33" if lvl == "MEDIUM" else "32")


# ---------------------------------------------------------------- 12 company
def _sec(name, n=8):
    tick = http("https://www.sec.gov/files/company_tickers.json", js=True)
    q = name.lower()
    hits = [v for v in tick.values() if q in v["title"].lower() or q == v["ticker"].lower()][:n]
    if not hits:
        print(" SEC: no listed company matched (SEC ticker file covers public filers only)")
    for c in hits:
        cik = str(c["cik_str"]).zfill(10)
        s = http(f"https://data.sec.gov/submissions/CIK{cik}.json", js=True)
        print(f"\n SEC  {s['name']} ({c['ticker']})  CIK {cik}  SIC {s.get('sic')} {s.get('sicDescription','')}")
        print(f"      state={s.get('stateOfIncorporation')}  fiscal-year-end={s.get('fiscalYearEnd')}  "
              f"former names: {', '.join(x['name'] for x in s.get('formerNames', [])) or '-'}")
        rec = s["filings"]["recent"]
        for i in range(min(8, len(rec["form"]))):
            acc = rec["accessionNumber"][i].replace("-", "")
            print(f"      {rec['filingDate'][i]} {rec['form'][i]:8} "
                  f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{acc}/{rec['primaryDocument'][i]}")


def _ch(name, number=None):
    auth = {"Authorization": "Basic " + base64.b64encode((need("COMPANIES_HOUSE_KEY") + ":").encode()).decode()}
    api = "https://api.company-information.service.gov.uk"
    if not number:
        r = http(f"{api}/search/companies?q={parse.quote(name)}&items_per_page=5", auth, js=True)
        for c in r.get("items", []):
            print(f" CH   {c['title']}  #{c['company_number']}  {c.get('company_status')}  {c.get('address_snippet','')}")
        items = r.get("items", [])
        if not items:
            return
        number = items[0]["company_number"]
    print(f"\n Companies House detail for #{number}")
    for o in http(f"{api}/company/{number}/officers", auth, js=True).get("items", [])[:15]:
        print(f"   officer: {o['name']} - {o.get('officer_role')}"
              f"{' (resigned ' + o['resigned_on'] + ')' if o.get('resigned_on') else ''}")
    try:
        for p in http(f"{api}/company/{number}/persons-with-significant-control", auth, js=True).get("items", [])[:10]:
            print(f"   PSC: {p['name']} - {', '.join(p.get('natures_of_control', []))}")
    except Err:
        pass


def _oc(name):
    r = http(f"https://api.opencorporates.com/v0.4/companies/search?q={parse.quote(name)}"
             f"&api_token={need('OPENCORPORATES_KEY')}", js=True)
    for c in r["results"]["companies"][:8]:
        c = c["company"]
        print(f" OC   {c['name']}  [{c['jurisdiction_code']}/{c['company_number']}]  "
              f"{c.get('current_status')}  inc {c.get('incorporation_date')}  {c['opencorporates_url']}")


def cmd_company(a):
    for label, fn in (("sec", lambda: _sec(a.name)), ("ch", lambda: _ch(a.name, a.number)),
                      ("oc", lambda: _oc(a.name))):
        if a.source in ("all", label):
            try:
                fn()
            except Err as e:
                print(f" [{label}] skipped: {e}")


# ---------------------------------------------------------------- 13 wayback
def _snapshots(url, limit):
    rows = http("https://web.archive.org/cdx/search/cdx?" + parse.urlencode(
        {"url": url, "output": "json", "fl": "timestamp,digest,statuscode", "collapse": "digest",
         "filter": "statuscode:200", "limit": limit}), js=True)
    return rows[1:] if rows else []


def _fetch_snap(ts, url):
    return strip_html(http(f"https://web.archive.org/web/{ts}id_/{url}", timeout=60))


def cmd_wayback(a):
    snaps = _snapshots(a.url, a.limit)
    if len(snaps) < 2:
        raise Err("fewer than two distinct archived versions found")
    h1(f"{len(snaps)} distinct versions of {a.url}")
    for i, (ts, dg, st) in enumerate(snaps):
        print(f" [{i}] {ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}  {dg[:8]}")
    i, j = (a.a, a.b) if a.a is not None else (len(snaps) - 2, len(snaps) - 1)
    j = len(snaps) - 1 if j is None else j
    old, new = snaps[i][0], snaps[j][0]
    h1(f"Diff [{i}] {old} -> [{j}] {new}")
    d = list(difflib.unified_diff(_fetch_snap(old, a.url).splitlines(), _fetch_snap(new, a.url).splitlines(),
                                  old, new, lineterm="", n=0))
    if not d:
        print(" No visible text changes (markup-only change).")
    for l in d[: a.max_lines]:
        print(("\033[32m" if l.startswith("+") else "\033[31m" if l.startswith("-") else "") + l + "\033[0m"
              if sys.stdout.isatty() else l)
    removed = sum(1 for l in d if l.startswith("-") and not l.startswith("---"))
    added = sum(1 for l in d if l.startswith("+") and not l.startswith("+++"))
    print(f"\n {added} line(s) added, {removed} removed")


# ---------------------------------------------------------------- 14 fly / vessel
def _ac_line(x):
    return (f"{x.get('hex','?'):6} {(x.get('flight') or '').strip():8} {x.get('r') or '-':8} {x.get('t') or '-':5} "
            f"alt={x.get('alt_baro','-')} gs={x.get('gs','-')} trk={x.get('track','-')} "
            f"pos={x.get('lat','-')},{x.get('lon','-')}")


def _ac_query(a):
    base = "https://api.adsb.lol/v2"
    if a.hex:
        return http(f"{base}/hex/{a.hex}", js=True).get("ac", [])
    if a.callsign:
        return http(f"{base}/callsign/{a.callsign}", js=True).get("ac", [])
    if a.near:
        lat, lon, nm = (float(x) for x in a.near.split(","))
        return http(f"{base}/point/{lat}/{lon}/{nm}", js=True).get("ac", [])
    raise Err("give --hex, --callsign or --near lat,lon,radius_nm")


def cmd_fly(a):
    fence = [float(x) for x in a.fence.split(",")] if a.fence else None
    inside = set()
    while True:
        ac = _ac_query(a)
        stamp = time.strftime("%H:%M:%S")
        if not a.watch:
            h1(f"{len(ac)} aircraft")
        for x in ac:
            if fence and "lat" in x:
                d = haversine_km(fence[0], fence[1], x["lat"], x["lon"])
                if d <= fence[2] and x["hex"] not in inside:
                    inside.add(x["hex"])
                    print(f"[{stamp}] ALERT enters fence ({d:.1f} km): {_ac_line(x)}")
                elif d > fence[2]:
                    inside.discard(x["hex"])
            elif not a.watch or not fence:
                print(f"[{stamp}] {_ac_line(x)}")
        if not a.watch:
            return
        time.sleep(a.watch)


def cmd_vessel(a):
    base = "https://meri.digitraffic.fi/api/ais/v1"
    if a.mmsi:
        loc = http(f"{base}/locations?mmsi={a.mmsi}", js=True).get("features", [])
        try:
            v = http(f"{base}/vessels/{a.mmsi}", js=True)
            print(f" {v.get('name')}  IMO {v.get('imo')}  call {v.get('callSign')}  dest {v.get('destination')}  "
                  f"type {v.get('shipType')}")
        except Err:
            print(" (no vessel metadata)")
    elif a.near:
        lat, lon, km = (float(x) for x in a.near.split(","))
        loc = [f for f in http(f"{base}/locations", js=True, timeout=90).get("features", [])
               if haversine_km(lat, lon, f["geometry"]["coordinates"][1], f["geometry"]["coordinates"][0]) <= km]
    else:
        raise Err("give --mmsi or --near lat,lon,km")
    for f in loc[:50]:
        p, (lo, la) = f["properties"], f["geometry"]["coordinates"]
        print(f" mmsi {p['mmsi']}  pos {la:.4f},{lo:.4f}  sog {p.get('sog')}kn cog {p.get('cog')}  "
              f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(p['timestampExternal']/1000))}Z")
    if not loc:
        print(" no AIS data (coverage is Finnish/Baltic waters only; use aisstream.io for global)")


# ---------------------------------------------------------------- 15 sat
STAC = "https://earth-search.aws.element84.com/v1/search"


def _bbox(a):
    if a.bbox:
        return [float(x) for x in a.bbox.split(",")]
    lat, lon = (float(x) for x in a.point.split(","))
    dlat = a.radius_km / 111.0
    dlon = a.radius_km / (111.0 * max(math.cos(math.radians(lat)), 0.01))
    return [lon - dlon, lat - dlat, lon + dlon, lat + dlat]


def _stac(bbox, rng, cloud, limit=50):
    r = http(STAC, js=True, method="POST", headers={"Content-Type": "application/json"}, data=json.dumps(
        {"collections": ["sentinel-2-l2a"], "bbox": bbox, "datetime": "{}T00:00:00Z/{}T23:59:59Z".format(*rng.split(":")), "limit": limit,
         "query": {"eo:cloud_cover": {"lt": cloud}}, "sortby": [{"field": "properties.datetime", "direction": "asc"}]}
    ).encode())
    return r.get("features", [])


def cmd_sat(a):
    bb = _bbox(a)
    if a.action == "search":
        for f in _stac(bb, a.range, a.cloud):
            p = f["properties"]
            print(f" {p['datetime'][:10]}  cloud {p['eo:cloud_cover']:5.1f}%  {f['id']}  "
                  f"{f['assets'].get('thumbnail', {}).get('href', '')}")
        return
    tile = lambda f: f["id"].split("_")[1]
    bs, ns = _stac(bb, a.before, a.cloud), _stac(bb, a.after, a.cloud)
    common = {tile(f) for f in bs} & {tile(f) for f in ns}  # same tile => pixel-aligned comparison
    cc = lambda f: f["properties"]["eo:cloud_cover"]
    b = min((f for f in bs if tile(f) in common), key=cc, default=None)
    n = min((f for f in ns if b and tile(f) == tile(b)), key=cc, default=None)
    if not b or not n:
        raise Err("no low-cloud scene in one of the ranges (raise --cloud or widen ranges)")
    os.makedirs(a.out, exist_ok=True)
    paths = []
    for tag, f in (("before", b), ("after", n)):
        p = os.path.join(a.out, f"{tag}_{f['properties']['datetime'][:10]}.jpg")
        with open(p, "wb") as fh:
            fh.write(http(f["assets"]["thumbnail"]["href"], raw=True))
        paths.append(p)
        print(f" {tag}: {f['id']} cloud {f['properties']['eo:cloud_cover']:.1f}%  -> {p}")
    try:
        from PIL import Image, ImageChops
        i1, i2 = (Image.open(p).convert("RGB") for p in paths)
        i2 = i2.resize(i1.size)
        diff = ImageChops.difference(i1, i2).convert("L")
        changed = sum(diff.point(lambda v: 1 if v > 40 else 0).histogram()[1:]) / (diff.width * diff.height)
        out = os.path.join(a.out, "diff.png")
        diff.point(lambda v: 255 if v > 40 else 0).save(out)
        print(f" change heatmap -> {out}  ({changed*100:.1f}% of pixels changed noticeably)")
    except ImportError:
        print(" (pip install pillow for an automatic diff image; open the two thumbnails side by side meanwhile)")
    print(" Note: thumbnails are low-res previews; large 'change' can be seasons/cloud shadow, not construction.")


# ---------------------------------------------------------------- 16 monitor
def _rss(url):
    root = ET.fromstring(http(url, raw=True))
    out = []
    for it in root.iter():
        t = it.tag.split("}")[-1]
        if t in ("item", "entry"):
            g = lambda n: next((c for c in it if c.tag.split("}")[-1] == n), None)
            title, desc, link = g("title"), g("description") or g("summary") or g("content"), g("link")
            href = (link.get("href") or link.text) if link is not None else url
            out.append({"id": href, "text": (title.text or "") + ". " + strip_html(desc.text or "") if desc is not None
                        else (title.text or ""), "url": href})
    return out


def _tg(ch):
    page = http(f"https://t.me/s/{ch}")
    out = []
    for m in re.finditer(r'data-post="([^"]+)".*?class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', page, re.S):
        out.append({"id": m.group(1), "text": strip_html(m.group(2)), "url": f"https://t.me/{m.group(1)}"})
    return out


def _summary(text, n=2):
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if len(s.strip()) > 20]
    if len(sents) <= n:
        return " ".join(sents) or text[:200]
    freq = Counter(w for w in re.findall(r"\w{4,}", text.lower()))
    top = sorted(sents, key=lambda s: -sum(freq[w] for w in re.findall(r"\w{4,}", s.lower())) / (len(s) ** 0.5))[:n]
    return " ".join(s for s in sents if s in top)


def cmd_monitor(a):
    kws = [k.lower() for k in a.kw]
    seen = load_state("seen.json")
    while True:
        srcs = [("rss", f, _rss) for f in a.feed] + [("tg", c.lstrip("@"), _tg) for c in a.tg]
        for kind, ref, fn in srcs:
            try:
                items = fn(ref)
            except Err as e:
                print(f" [{ref}] {e}")
                continue
            for it in items:
                key = f"{kind}:{it['id']}"
                if key in seen:
                    continue
                seen[key] = int(time.time())
                hit = [k for k in kws if k in it["text"].lower()] if kws else ["*"]
                if hit:
                    print(f"\n[{ref}] matched {','.join(hit)}\n  {it['url']}\n  {_summary(it['text'])}")
        save_state("seen.json", seen)
        if not a.loop:
            return
        time.sleep(a.loop)


# ---------------------------------------------------------------- 17 meta
DOC_EXT = (".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")
PATH_RE = re.compile(rb"(?:[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\x00\"<>|]{1,40}|/(?:home|Users)/[\w.-]{1,40})")


def _meta_bytes(name, data):
    info, leaks = {}, set(m.group(0).decode("latin1") for m in PATH_RE.finditer(data[:5_000_000]))
    low = name.lower()
    if low.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            for part in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
                if part in z.namelist():
                    for el in ET.fromstring(z.read(part)).iter():
                        t = el.tag.split("}")[-1]
                        if el.text and t in ("creator", "lastModifiedBy", "created", "modified", "Application",
                                             "AppVersion", "Company", "Manager", "initial-creator", "generator"):
                            info[t] = el.text.strip()
            for n in z.namelist():
                if n.endswith((".xml", ".rels")):
                    leaks |= {m.group(0).decode("latin1") for m in PATH_RE.finditer(z.read(n))}
        except zipfile.BadZipFile:
            info["error"] = "not a valid zip/OOXML file"
    elif low.endswith(".pdf"):
        for k in ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate"):
            m = re.search(rb"/" + k.encode() + rb"\s*\(([^)]{1,120})\)", data)
            if m:
                info[k] = m.group(1).decode("latin1")
    return info, leaks


def cmd_meta(a):
    targets = []
    if re.match(r"https?://", a.target):
        page = http(a.target)
        links = {parse.urljoin(a.target, h) for h in re.findall(r'href=["\']([^"\'#]+)', page)}
        docs = sorted(l for l in links if parse.urlparse(l).path.lower().endswith(DOC_EXT))[: a.max]
        print(f" found {len(docs)} document link(s) on page")
        for d in docs:
            try:
                targets.append((d, http(d, raw=True, timeout=60)))
            except Err as e:
                print(f" skip {d}: {e}")
    else:
        paths = [os.path.join(r, f) for r, _, fs in os.walk(a.target) for f in fs] if os.path.isdir(a.target) \
            else [a.target]
        for p in paths:
            if p.lower().endswith(DOC_EXT):
                targets.append((p, open(p, "rb").read()))
    people, tools = Counter(), Counter()
    for name, data in targets:
        info, leaks = _meta_bytes(name, data)
        print(f"\n {name}")
        for k, v in info.items():
            print(f"   {k}: {v}")
            if k in ("creator", "lastModifiedBy", "Author", "Manager", "initial-creator"):
                people[v] += 1
            if k in ("Application", "AppVersion", "Creator", "Producer", "generator"):
                tools[f"{k}={v}"] += 1
        for l in sorted(leaks):
            print(f"   [!] internal path: {l}")
    if targets:
        h1("Summary - what to scrub")
        print(" people exposed:", dict(people) or "none")
        print(" software exposed:", dict(tools) or "none")
        print(" Tip: strip metadata before publishing (Word: Inspect Document; PDF: exiftool -all= or qpdf).")


# ---------------------------------------------------------------- 18 ioc
def cmd_ioc(a):
    v = a.value.strip()
    try:
        ipaddress.ip_address(v)
        kind = "ip"
    except ValueError:
        kind = ("hash" if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v)
                else "url" if re.match(r"https?://", v) else "domain")
    print(f" {v}  ({kind})")
    signals = []

    def run(name, fn):
        try:
            r = fn()
            if r:
                signals.append((name, *r))
                print(f"  {name:11} {r[1]}")
        except Err as e:
            print(f"  {name:11} skipped: {e}")

    def vt():
        ep = {"ip": f"ip_addresses/{v}", "domain": f"domains/{v}", "hash": f"files/{v}",
              "url": "urls/" + base64.urlsafe_b64encode(v.encode()).decode().strip("=")}[kind]
        s = http(f"https://www.virustotal.com/api/v3/{ep}", {"x-apikey": need("VT_API_KEY")}, js=True)
        st = s["data"]["attributes"]["last_analysis_stats"]
        return ("bad" if st["malicious"] >= 3 else "warn" if st["malicious"] + st["suspicious"] else "ok",
                f"{st['malicious']} malicious / {st['suspicious']} suspicious / {st['harmless']} harmless engines")

    def abuse():
        if kind != "ip":
            return None
        d = http(f"https://api.abuseipdb.com/api/v2/check?ipAddress={v}&maxAgeInDays=90",
                 {"Key": need("ABUSEIPDB_KEY")}, js=True)["data"]
        sc = d["abuseConfidenceScore"]
        return ("bad" if sc >= 75 else "warn" if sc >= 25 else "ok",
                f"abuse score {sc}/100, {d['totalReports']} reports, {d.get('isp')}, {d.get('countryCode')}")

    def urlhaus():
        hdr = {"Auth-Key": need("ABUSECH_KEY")}
        if kind == "url":
            r = http("https://urlhaus-api.abuse.ch/v1/url/", hdr, {"url": v}, js=True)
        elif kind in ("ip", "domain"):
            r = http("https://urlhaus-api.abuse.ch/v1/host/", hdr, {"host": v}, js=True)
        else:
            k = "sha256_hash" if len(v) == 64 else "md5_hash" if len(v) == 32 else None
            if not k:
                return None
            r = http("https://urlhaus-api.abuse.ch/v1/payload/", hdr, {k: v}, js=True)
        if r.get("query_status") in ("no_results", "invalid_host", "invalid_hash"):
            return ("ok", "not listed")
        return ("bad", f"listed ({r.get('url_count') or r.get('urlhaus_reference') or r.get('threat') or 'hit'})")

    def grey():
        if kind != "ip":
            return None
        h = {"key": os.environ["GREYNOISE_KEY"]} if os.environ.get("GREYNOISE_KEY") else {}
        try:
            d = http(f"https://api.greynoise.io/v3/community/{v}", h, js=True)
        except Err as e:
            if "404" in str(e):
                return ("ok", "not seen scanning the internet")
            raise
        c = d.get("classification")
        return ("bad" if c == "malicious" else "ok", f"{c}, noise={d.get('noise')} riot={d.get('riot')} {d.get('name','')}")

    for n, f in (("VirusTotal", vt), ("AbuseIPDB", abuse), ("URLhaus", urlhaus), ("GreyNoise", grey)):
        run(n, f)
    h1("Verdict")
    bad = sum(s[1] == "bad" for s in signals)
    warn = sum(s[1] == "warn" for s in signals)
    if not signals:
        panel("IOC verdict", ["UNKNOWN - no source answered", "add API keys: osintkit setup --only ioc"], "33")
    else:
        panel("IOC verdict", [f"{'MALICIOUS' if bad else 'SUSPICIOUS' if warn else 'NO KNOWN BAD'}",
                              f"{bad} bad, {warn} warn, {len(signals)} source(s) answered"],
              "31" if bad else "33" if warn else "32")


# ---------------------------------------------------------------- 19 brand
def cmd_brand(a):
    d = a.domain
    print(f" Checking exposure for {d} (only run this on domains you own or are authorized for)")
    h1("Have I Been Pwned - breached addresses on your domain")
    try:
        r = http(f"https://haveibeenpwned.com/api/v3/breacheddomain/{d}", {"hibp-api-key": need("HIBP_KEY")}, js=True)
        print(f" {len(r)} mailbox(es) in breaches (domain must be verified in your HIBP dashboard)")
        for k, v in list(r.items())[:25]:
            print(f"   {k}@{d}: {', '.join(v)}")
    except Err as e:
        print(f" skipped: {e}")
    h1("GitHub - public code mentioning your domain")
    try:
        r = http(f"https://api.github.com/search/code?q={parse.quote(chr(34) + d + chr(34))}&per_page=30",
                 {"Authorization": "Bearer " + need("GITHUB_TOKEN"), "Accept": "application/vnd.github+json"}, js=True)
        print(f" {r['total_count']} result(s)")
        for it in r["items"]:
            risky = " [!] likely secrets file" if re.search(r"\.env|credential|secret|id_rsa|config|\.pem|\.key",
                                                           it["name"], re.I) else ""
            print(f"   {it['repository']['full_name']}/{it['path']}{risky}\n     {it['html_url']}")
    except Err as e:
        print(f" skipped: {e}")
    h1("Certificate transparency - subdomains (crt.sh)")
    try:
        subs = sorted({n.strip() for x in http(f"https://crt.sh/?q=%25.{d}&output=json", js=True, timeout=60)
                       for n in x["name_value"].splitlines() if not n.startswith("*")})
        print(f" {len(subs)} hostname(s)")
        for s in subs[:40]:
            print("   ", s)
    except Err as e:
        print(f" skipped: {e}")


# ---------------------------------------------------------------- 20 factcheck
def cmd_factcheck(a):
    if a.image:
        h1("Reverse image search (open in a browser)")
        u = parse.quote(a.image, safe="")
        print(f" Google Lens: https://lens.google.com/uploadbyurl?url={u}")
        print(f" TinEye:      https://tineye.com/search?url={u}")
        print(f" Yandex:      https://yandex.com/images/search?rpt=imageview&url={u}")
        print(f" Bing:        https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}")
    if not a.claim:
        return
    r = http("https://factchecktools.googleapis.com/v1alpha1/claims:search?" + parse.urlencode(
        {"query": a.claim, "languageCode": a.lang, "pageSize": 10, "key": need("GOOGLE_API_KEY")}), js=True)
    claims = r.get("claims", [])
    h1(f"{len(claims)} published fact-check(s)")
    FALSE = re.compile(r"false|fake|misleading|incorrect|pants|hoax|fabricated|no evidence|unproven|satire", re.I)
    TRUE = re.compile(r"\btrue\b|correct|accurate|\bfact\b|confirmed", re.I)
    f = t = o = 0
    for c in claims:
        for cr in c.get("claimReview", []):
            rating = cr.get("textualRating", "")
            f, t, o = (f + 1, t, o) if FALSE.search(rating) else (f, t + 1, o) if TRUE.search(rating) else (f, t, o + 1)
            print(f" - \"{c.get('text','')[:120]}\" ({c.get('claimant','?')})\n"
                  f"   {cr['publisher']['name']}: {rating}\n   {cr['url']}")
    if claims:
        print(f"\n Tally: {f} false/misleading, {t} true, {o} mixed/other")
        lean = "LIKELY FALSE/MISLEADING" if f > t and f >= o else "LIKELY TRUE" if t > f and t >= o else "MIXED / DISPUTED"
        print(f" Lean: {lean} (keyword heuristic over ratings; read the sources)")
    else:
        print(" No published fact-checks. Try fewer keywords, or check primary sources (court records, filings, official statements).")


# ---------------------------------------------------------------- doctor / main
# ---------------------------------------------------------------- 21 domain
DNS_T = {"A": 1, "AAAA": 28, "NS": 2, "MX": 15, "TXT": 16, "CAA": 257, "CNAME": 5}


def doh(name, typ="A"):
    """DNS over HTTPS (Google). Returns list of answers, [] if none, None on network error."""
    try:
        r = http(f"https://dns.google/resolve?name={parse.quote(name)}&type={typ}", js=True, timeout=10)
    except Err:
        return None
    return [x["data"] for x in r.get("Answer", []) if x.get("type") == DNS_T[typ]]


def _rdap(d):
    r = http(f"https://rdap.org/domain/{d}", js=True, timeout=30)
    ev = {e["eventAction"]: e["eventDate"] for e in r.get("events", [])}
    reg = next((i[3] for e in r.get("entities", []) if "registrar" in e.get("roles", [])
                for i in e.get("vcardArray", [0, []])[1] if i[0] == "fn"), "?")
    return ev, reg, r.get("status", []), [n["ldhName"] for n in r.get("nameservers", [])]


def _days_ago(iso):
    from datetime import datetime, timezone
    t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - t).days


def cmd_domain(a):
    d = re.sub(r"^https?://", "", a.domain.lower().strip()).split("/")[0]
    h1(f"DNS records for {d}")
    for t in DNS_T:
        for v in doh(d, t) or []:
            print(f" {t:5} {v if len(v) < 100 else v[:97] + '...'}")

    h1("Email spoofing protection")
    txt = " ".join(doh(d, "TXT") or [])
    spf = re.search(r"v=spf1[^\"]*", txt)
    dm = " ".join(doh("_dmarc." + d, "TXT") or [])
    if not spf:
        print(" [!] no SPF record - anyone can forge mail from this domain")
    else:
        print(f" SPF   {spf.group(0).strip()}")
        if re.search(r"\+all\b|\?all\b", spf.group(0)):
            print(" [!] SPF allows everyone (+all / ?all)")
        elif "~all" in spf.group(0):
            print(" warn: SPF is soft-fail (~all); -all is stricter")
    if "v=DMARC1" not in dm:
        print(" [!] no DMARC record - spoofed mail will not be rejected")
    else:
        pol = re.search(r"p=(\w+)", dm)
        print(f" DMARC {dm.strip()}")
        if pol and pol.group(1) == "none":
            print(" warn: DMARC policy is p=none (monitor only, nothing blocked)")

    h1("Registration (RDAP)")
    try:
        ev, reg, status, ns = _rdap(d)
        print(f" registrar: {reg}\n status:    {', '.join(status)}\n nameservers: {', '.join(ns)}")
        for k in ("registration", "last changed", "expiration"):
            if k in ev:
                print(f" {k:13} {ev[k][:10]}")
        if "registration" in ev and _days_ago(ev["registration"]) < 90:
            print(f" [!] domain is only {_days_ago(ev['registration'])} days old")
        if "expiration" in ev and -30 < -_days_ago(ev["expiration"]) < 30:
            print(" [!] domain expires within 30 days")
    except Err as e:
        print(f" skipped: {e}")

    h1("Web security headers")
    try:
        with Spinner("connecting"), request.urlopen(request.Request(f"https://{d}", headers={"User-Agent": UA}), timeout=15) as r:
            hd = {k.lower(): v for k, v in r.headers.items()}
        print(f" server: {hd.get('server', 'hidden')}   powered-by: {hd.get('x-powered-by', '-')}")
        miss = [n for n, k in (("HSTS", "strict-transport-security"), ("CSP", "content-security-policy"),
                               ("X-Frame-Options", "x-frame-options"), ("X-Content-Type-Options", "x-content-type-options"),
                               ("Referrer-Policy", "referrer-policy")) if k not in hd]
        print(" [!] missing: " + ", ".join(miss) if miss else " all common security headers present")
    except Exception as e:
        print(f" skipped: {e}")

    h1("Subdomains (certificate transparency)")
    try:
        subs = sorted({n.strip() for x in http(f"https://crt.sh/?q=%25.{d}&output=json", js=True, timeout=60)
                       for n in x["name_value"].splitlines() if not n.startswith("*")})
        print(f" {len(subs)} hostname(s)")
        for s_ in subs[: a.max]:
            print("   ", s_)
    except Err as e:
        print(f" skipped: {e}")


# ---------------------------------------------------------------- 22 typosquat
KB = {c: n for c, n in zip("qwertyuiopasdfghjklzxcvbnm", [
    "wa", "qes", "wrd", "etf", "rygt", "tuh", "yij", "uok", "ipl", "op", "qwsz", "aedxz", "swrfcx", "dtgvc", "frhbv",
    "gtjnb", "hyknm", "juiml", "kio", "azx", "zsdc", "xdfv", "cfgb", "vghn", "bhjm", "njk"])}
HOMO = {"o": ["0"], "l": ["1", "i"], "i": ["l", "1"], "m": ["rn"], "w": ["vv"], "a": ["4"], "e": ["3"], "s": ["5"], "g": ["q"]}
TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "app", "online", "site", "top", "support", "help", "shop"]
WORDS = ["login", "secure", "support", "account", "verify", "mail", "pay", "help", "online", "app"]


def _perms(n):
    out = set()
    for i in range(len(n)):
        out.add(n[:i] + n[i + 1:])
        out.add(n[:i] + n[i] + n[i:])
        out.update(n[:i] + ch + n[i + 1:] for ch in KB.get(n[i], ""))
        out.update(n[:i] + h + n[i + 1:] for h in HOMO.get(n[i], []))
        if i:
            out.add(n[:i] + "-" + n[i:])
    out.update(n[:i] + n[i + 1] + n[i] + n[i + 2:] for i in range(len(n) - 1))
    out.update(w + n for w in WORDS)
    out.update(n + w for w in WORDS)
    out.update(n + "-" + w for w in WORDS)
    return {p for p in out if p and p != n and not p.startswith("-") and not p.endswith("-")}


def cmd_typosquat(a):
    global NOSPIN
    d = a.domain.lower().strip()
    sld, _, tld = d.partition(".")
    if not tld:
        raise Err("give a full domain like example.com")
    cands = sorted({f"{p}.{tld}" for p in _perms(sld)} | {f"{sld}.{t}" for t in TLDS if t != tld})
    cands = cands[: a.max]
    print(f" testing {len(cands)} lookalike variants of {d} ...")
    from concurrent.futures import ThreadPoolExecutor

    def probe(c_):
        ips = doh(c_, "A")
        out = c_, ips, bool(doh(c_, "MX")) if ips else False
        prog.tick()
        return out

    prog = Progress(len(cands), "resolving variants")

    NOSPIN = True
    try:
        with ThreadPoolExecutor(16) as ex:
            res = [r for r in ex.map(probe, cands) if r[1]]
    finally:
        NOSPIN = False
        prog.done()
    h1(f"{len(res)} lookalike(s) resolve")
    for dom, ips, mx in res:
        print(f" {dom:32} {', '.join(ips[:2]):32} {'[!] has MX (can send/receive mail)' if mx else ''}")
        if a.age and len(res) <= 25:
            try:
                ev = _rdap(dom)[0]
                if "registration" in ev:
                    print(f"   registered {ev['registration'][:10]} ({_days_ago(ev['registration'])} days ago)")
            except Err:
                pass
    if not res:
        print(" nothing registered among the tested variants")
    else:
        print("\n Resolving does not prove abuse: check each site, then report impostors to the registrar/host.")


# ---------------------------------------------------------------- 23 username
SITES = [
    ("GitHub", "https://github.com/{}"), ("GitLab", "https://gitlab.com/{}"), ("Codeberg", "https://codeberg.org/{}"),
    ("Bitbucket", "https://bitbucket.org/{}/"), ("Reddit", "https://www.reddit.com/user/{}/about.json"),
    ("Hacker News", "https://hacker-news.firebaseio.com/v0/user/{}.json"), ("Keybase", "https://keybase.io/{}"),
    ("dev.to", "https://dev.to/{}"), ("Medium", "https://medium.com/@{}"), ("npm", "https://www.npmjs.com/~{}"),
    ("PyPI", "https://pypi.org/user/{}/"), ("Docker Hub", "https://hub.docker.com/u/{}/"),
    ("Replit", "https://replit.com/@{}"), ("Lichess", "https://lichess.org/@/{}"),
    ("Chess.com", "https://api.chess.com/pub/player/{}"), ("Gravatar", "https://en.gravatar.com/{}.json"),
    ("About.me", "https://about.me/{}"), ("Behance", "https://www.behance.net/{}"),
    ("Dribbble", "https://dribbble.com/{}"), ("SoundCloud", "https://soundcloud.com/{}"),
    ("Pastebin", "https://pastebin.com/u/{}"), ("Telegram", "https://t.me/{}"),
    ("Mastodon.social", "https://mastodon.social/@{}"), ("Twitch", "https://www.twitch.tv/{}"),
    ("Steam", "https://steamcommunity.com/id/{}"), ("Linktree", "https://linktr.ee/{}"),
    ("Patreon", "https://www.patreon.com/{}"), ("Product Hunt", "https://www.producthunt.com/@{}"),
]


def _site_status(url):
    try:
        with request.urlopen(request.Request(url, headers={"User-Agent": "Mozilla/5.0 osintkit"}), timeout=12) as r:
            body = r.read(200_000).decode("utf8", "replace")
            return r.status, body
    except error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def cmd_username(a):
    global NOSPIN
    u = a.name.strip().lstrip("@")
    if not re.fullmatch(r"[\w.-]{1,40}", u):
        raise Err("username may only contain letters, digits, _ . -")
    print(c("2", " Only search handles you own or have consent to look up; do not use this to track private individuals."))
    from concurrent.futures import ThreadPoolExecutor

    def probe(s_):
        code, body = _site_status(s_[1].format(parse.quote(u)))
        if s_[0] == "Telegram" and code == 200 and "tgme_page_title" not in body:
            code = 404
        if s_[0] == "Hacker News" and code == 200 and body.strip() == "null":
            code = 404
        prog.tick()
        return s_[0], s_[1].format(u), code

    prog = Progress(len(SITES), "checking sites")

    NOSPIN = True
    try:
        with ThreadPoolExecutor(12) as ex:
            res = list(ex.map(probe, SITES))
    finally:
        NOSPIN = False
        prog.done()
    found = [r for r in res if r[2] == 200]
    unk = [r for r in res if r[2] not in (200, 404)]
    h1(f"{len(found)} profile(s) found for '{u}'")
    for n, url, _ in found:
        print(f" [+] {n:16} {url}")
    print(c("2", f"\n {len(res) - len(found) - len(unk)} not found; {len(unk)} inconclusive "
            f"({', '.join(n for n, _, _ in unk) or '-'}: blocked or rate-limited)"))
    print(c("2", " Note: a match means the handle exists, not that it is the same person."))


LINKS = {
    "OSINTKIT_CONTACT": "just your email address (free)",
    "COMPANIES_HOUSE_KEY": "https://developer.company-information.service.gov.uk/ (free)",
    "OPENCORPORATES_KEY": "https://opencorporates.com/api_accounts/new (free for some users, otherwise paid)",
    "VT_API_KEY": "https://www.virustotal.com/gui/join-us (free tier)",
    "ABUSEIPDB_KEY": "https://www.abuseipdb.com/register (free tier)",
    "ABUSECH_KEY": "https://auth.abuse.ch/ (free)",
    "GREYNOISE_KEY": "https://viz.greynoise.io/signup (free, optional)",
    "HIBP_KEY": "https://haveibeenpwned.com/API/Key (paid, a few $/month)",
    "GITHUB_TOKEN": "https://github.com/settings/tokens (free; no scopes needed)",
    "GOOGLE_API_KEY": "https://console.cloud.google.com/ -> enable 'Fact Check Tools API' -> Credentials (free)",
}


GROUPS = [
    ("Quick start (free, ~2 min)", ["OSINTKIT_CONTACT", "VT_API_KEY", "ABUSEIPDB_KEY", "ABUSECH_KEY", "GOOGLE_API_KEY"]),
    ("Optional (free)", ["COMPANIES_HOUSE_KEY", "GITHUB_TOKEN", "GREYNOISE_KEY"]),
    ("Paid / only if you need it", ["HIBP_KEY", "OPENCORPORATES_KEY"]),
]
TOOL_KEYS = {  # tool -> every key it can use
    "ioc": ["VT_API_KEY", "ABUSEIPDB_KEY", "ABUSECH_KEY", "GREYNOISE_KEY"],
    "company": ["OSINTKIT_CONTACT", "COMPANIES_HOUSE_KEY", "OPENCORPORATES_KEY"],
    "brand": ["HIBP_KEY", "GITHUB_TOKEN"],
    "factcheck": ["GOOGLE_API_KEY"],
}
REQUIRED = {  # keys a tool needs to be fully "ready" (each tool also has a keyless part)
    "ioc": ["VT_API_KEY", "ABUSEIPDB_KEY", "ABUSECH_KEY"],
    "company": ["OSINTKIT_CONTACT", "COMPANIES_HOUSE_KEY"],
    "brand": ["HIBP_KEY", "GITHUB_TOKEN"],
    "factcheck": ["GOOGLE_API_KEY"],
}
KEYLESS = ["headers", "wayback", "fly", "vessel", "sat", "monitor", "meta", "domain", "typosquat", "username",
           "exposure", "cve", "tls", "exif", "ip"]

_TESTS = {  # one cheap authenticated call per service
    "VT_API_KEY": lambda v: http("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {"x-apikey": v}, js=True),
    "ABUSEIPDB_KEY": lambda v: http("https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1", {"Key": v}, js=True),
    "ABUSECH_KEY": lambda v: http("https://urlhaus-api.abuse.ch/v1/host/", {"Auth-Key": v}, {"host": "8.8.8.8"}, js=True),
    "GREYNOISE_KEY": lambda v: http("https://api.greynoise.io/v3/community/8.8.8.8", {"key": v}, js=True),
    "GITHUB_TOKEN": lambda v: http("https://api.github.com/user", {"Authorization": "Bearer " + v}, js=True),
    "GOOGLE_API_KEY": lambda v: http("https://factchecktools.googleapis.com/v1alpha1/claims:search?query=test&key=" + v, js=True),
    "COMPANIES_HOUSE_KEY": lambda v: http("https://api.company-information.service.gov.uk/search/companies?q=test",
                                          {"Authorization": "Basic " + base64.b64encode((v + ":").encode()).decode()}, js=True),
    "HIBP_KEY": lambda v: http("https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com", {"hibp-api-key": v}, js=True),
    "OPENCORPORATES_KEY": lambda v: http("https://api.opencorporates.com/v0.4/companies/search?q=test&api_token=" + v, js=True),
}


def _validate(k, v):
    """(True|False|None, message): works / rejected / could not tell."""
    if k == "OSINTKIT_CONTACT":
        ok = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.\w+", v))
        return ok, "looks like an email" if ok else "does not look like an email address"
    try:
        _TESTS[k](v)
        return True, "key works"
    except Err as e:
        m = str(e)
        if "HTTP 404" in m:  # authenticated fine, just nothing found
            return True, "key works"
        if re.search(r"HTTP (400|401|403)", m):
            return False, "rejected by the service (" + m.split(":")[0] + ")"
        return None, "could not verify (network problem?)"


def _mask(v):
    return v[:3] + "…" + v[-4:] if len(v) > 10 else "set"


def _signup_url(k):
    m = re.search(r"https?://[^\s)]+", LINKS.get(k, ""))
    return m.group(0) if m else None


def _load_keys():
    try:
        return json.load(open(KEYFILE))
    except Exception:
        return {}


def _save_keys(saved):
    os.makedirs(os.path.dirname(KEYFILE), exist_ok=True)
    if os.path.exists(KEYFILE):  # keep the previous version so a bad save is never destructive
        import shutil
        shutil.copy2(KEYFILE, KEYFILE + ".bak")
    json.dump(saved, open(KEYFILE, "w"), indent=2)
    os.environ.update(saved)  # take effect immediately in this process


def _ask_key(k, saved):
    import getpass
    import webbrowser
    cur = saved.get(k) or os.environ.get(k)
    url = _signup_url(k)
    print(f"\n{c('1', k)}  {c('2', KEYS[k])}")
    print(c("2", f"  {LINKS.get(k, '')}"))
    if cur:
        print(f"  currently set: {_mask(cur)}")
    prompt = f"  paste it ({'Enter=keep' if cur else 'Enter=skip'}{', o=open signup page' if url else ''}): "
    while True:
        v = (input if k == "OSINTKIT_CONTACT" else getpass.getpass)(prompt).strip()
        if v.lower() == "o" and url:
            webbrowser.open(url)
            print(c("2", "  opened in your browser - come back and paste the key"))
            continue
        if not v:
            return None
        with Spinner("checking key"):
            ok, msg = _validate(k, v)
        if ok:
            print(c("32", f"  ✓ {msg}"))
            return v
        if ok is None:
            print(c("33", f"  ? {msg} - saving anyway"))
            return v
        print(c("31", f"  ✗ {msg}"))
        ch = input("  [r]etry / [s]ave anyway / Enter=skip: ").strip().lower()
        if ch == "s":
            return v
        if ch != "r":
            return None


def cmd_setup(a):
    saved = _load_keys()
    # --- non-interactive modes
    if a.set or a.from_env is not None:
        incoming = {}
        for item in a.set or []:
            name, _, val = item.partition("=")
            if name not in KEYS or not val:
                raise Err(f"--set expects NAME=VALUE with NAME one of: {', '.join(KEYS)}")
            incoming[name] = val
        if a.from_env is not None:
            src = dict(os.environ)
            if a.from_env:
                src = {}
                for line in open(a.from_env, encoding="utf8"):
                    n, _, val = line.strip().partition("=")
                    if n and not n.startswith("#"):
                        src[n.strip()] = val.strip().strip("\"'")
            incoming.update({k: src[k] for k in KEYS if src.get(k)})
        saved.update(incoming)
        _save_keys(saved)
        print(f"Saved {len(incoming)} key(s): {', '.join(incoming) or '-'}  ->  {KEYFILE}")
        return
    if not sys.stdin.isatty():
        raise Err("setup is interactive; for scripts use: setup --set NAME=VALUE  or  setup --from-env [FILE]")

    # --- choose which keys to ask for
    if a.only:
        keys = TOOL_KEYS[a.only]
    elif a.quick:
        keys = GROUPS[0][1]
    else:
        print(c("1", "What would you like to set up?"))
        print(f"  {c('1;36', '1')}  Quick start - the 5 free keys that unlock most tools {c('2', '(recommended)')}")
        print(f"  {c('1;36', '2')}  Everything - all {len(KEYS)} keys, grouped by cost")
        print(f"  {c('1;36', '3')}  One tool only ({', '.join(TOOL_KEYS)})")
        print(f"  {c('1;36', 'q')}  Cancel")
        ch = input(c("1;35", "\n choice [1]: ")).strip().lower() or "1"
        if ch == "q":
            return
        if ch == "3":
            t = input(f" which tool ({'/'.join(TOOL_KEYS)}): ").strip().lower()
            if t not in TOOL_KEYS:
                raise Err("unknown tool")
            keys = TOOL_KEYS[t]
        elif ch == "2":
            keys = [k for _, ks in GROUPS for k in ks]
        else:
            keys = GROUPS[0][1]
    print(c("2", "\nTip: type 'o' at any prompt to open that service's signup page. Input is hidden. Keys are checked as you paste them."))

    group_of = {k: g for g, ks in GROUPS for k in ks}
    last = None
    for k in keys:
        if group_of[k] != last:
            last = group_of[k]
            h1(last)
        v = _ask_key(k, saved)
        if v:
            saved[k] = v
            _save_keys(saved)  # save as we go so Ctrl+C never loses work
    print(f"\n{c('32', '✓')} Saved to {KEYFILE} (plain text - keep it private)\n")
    cmd_doctor(None)


def _have(k):
    return bool(os.environ.get(k))


def cmd_doctor(a):
    h1("Tool readiness")
    for t in KEYLESS:
        print(f" {t:10} {c('32', 'ready')}      {c('2', 'no key needed')}")
    for t, req in REQUIRED.items():
        missing = [k for k in req if not _have(k)]
        if not missing:
            print(f" {t:10} {c('32', 'ready')}")
        else:
            print(f" {t:10} {c('33', 'partial')}    {c('2', 'missing ' + ', '.join(missing))}  ->  osintkit setup --only {t}")
    print(c("2", "\n 'partial' tools still run; they just skip the sources that need the missing keys."))
    print(c("2", f" Saved keys file: {KEYFILE}"))


def first_run():
    """One-time offer to run quick setup on the very first interactive launch."""
    marker = os.path.join(STATE, "first_run")
    if os.path.exists(KEYFILE) or os.path.exists(marker) or any(_have(k) for k in KEYS):
        return
    os.makedirs(STATE, exist_ok=True)
    open(marker, "w").write("1")  # ask only once, whatever the answer
    try:
        ans = input(c("1", " Welcome! No API keys set yet.") + " Run the 2-minute quick setup now? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ans in ("", "y", "yes"):
        run(["setup", "--quick"])
        print()
    else:
        print(c("2", " No problem - 10 tools work without keys. Run 'setup' from the menu any time.\n"))


# ---------------------------------------------------------------- UI helpers
import shlex, socket, ssl, struct, textwrap

ANSI_RE = re.compile(r"\033\[[\d;]*m")


class _Tee:
    """stdout wrapper for --save: mirrors output to a file with colors stripped."""

    def __init__(self, real, f):
        self.real, self.f, self.encoding = real, f, getattr(real, "encoding", "utf-8")

    def write(self, s):
        self.real.write(s)
        self.f.write(ANSI_RE.sub("", s))
        return len(s)

    def flush(self):
        self.real.flush()
        self.f.flush()

    def isatty(self):
        return self.real.isatty()


def panel(title, lines, color="36"):
    """Boxed summary. lines are plain strings."""
    if not COLOR:
        _print(f"\n[{title}]")
        for l in lines:
            _print("  " + l)
        return
    inner = max([len(title) + 4] + [len(l) + 2 for l in lines])
    _print("\n" + c(color, "┌─ ") + c("1;" + color, title) + c(color, " " + "─" * (inner - len(title) - 3) + "┐"))
    for l in lines:
        _print(c(color, "│ ") + l.ljust(inner - 2) + c(color, " │"))
    _print(c(color, "└" + "─" * inner + "┘"))


class Progress:
    def __init__(self, total, label):
        self.t, self.n, self.label = max(total, 1), 0, label
        self.on = sys.stderr.isatty() and not os.environ.get("NO_COLOR")

    def tick(self):
        self.n += 1
        if self.on:
            f = int(24 * self.n / self.t)
            sys.stderr.write(f"\r\033[36m{'█' * f}{'░' * (24 - f)}\033[0m {self.n}/{self.t} \033[2m{self.label}\033[0m\033[K")
            sys.stderr.flush()

    def done(self):
        if self.on:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


def cached(url, name, ttl=43200, js=False):
    """Download big public lists once and reuse them for `ttl` seconds."""
    path = os.path.join(STATE, name)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        txt = open(path, encoding="utf8").read()
    else:
        txt = http(url, timeout=90)
        os.makedirs(STATE, exist_ok=True)
        open(path, "w", encoding="utf8").write(txt)
    return json.loads(txt) if js else txt


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host(s):
    return re.sub(r"^https?://", "", s.strip()).split("/")[0]


# ---------------------------------------------------------------- 24 exposure
RISKY = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
         5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
PORTS = {22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
         587: "SMTP", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-alt", 8443: "HTTPS-alt"}


def cmd_exposure(a):
    t = _host(a.target)
    ips = [t] if _is_ip(t) else (doh(t, "A") or [])
    if not ips:
        raise Err(f"could not resolve {t}")
    for ip in ips[:4]:
        h1(ip + ("" if ip == t else f"  ({t})"))
        try:
            r = http(f"https://internetdb.shodan.io/{ip}", js=True)
        except Err as e:
            if "404" in str(e):
                print(" no exposure data - nothing known to be listening (good)")
                continue
            raise
        ports, vulns = sorted(r.get("ports", [])), sorted(r.get("vulns", []))
        risky = [p for p in ports if p in RISKY]
        for p in ports:
            name = RISKY.get(p) or PORTS.get(p) or ""
            print(f" {p:<6} {name}" + (f"   [!] {name} should not be internet-facing" if p in RISKY else ""))
        if r.get("hostnames"):
            print(f"\n hostnames: {', '.join(r['hostnames'][:8])}")
        if r.get("tags"):
            print(f" tags:      {', '.join(r['tags'])}")
        if r.get("cpes"):
            print(f" software:  {', '.join(r['cpes'][:8])}")
        if vulns:
            print(f"\n known CVEs ({len(vulns)}):")
            for v in vulns[: a.max]:
                print(f"   [!] {v}")
            print(c("2", f"   details: osintkit cve {vulns[0]}"))
        panel("Exposure", [f"{len(ports)} open port(s), {len(risky)} risky, {len(vulns)} known CVE(s)",
                           "passive snapshot (updated about weekly), not a live scan"],
              "31" if risky or vulns else "32")


# ---------------------------------------------------------------- 25 cve
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def cmd_cve(a):
    kev = None
    for cid in a.ids:
        cid = cid.upper()
        h1(cid)
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
            print(" not a valid CVE id (format: CVE-2021-44228)")
            continue
        vs = http(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}", js=True, timeout=40).get("vulnerabilities")
        if not vs:
            print(" not found in the NVD")
            continue
        cve = vs[0]["cve"]
        desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        score = sev = vector = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if cve.get("metrics", {}).get(k):
                m = cve["metrics"][k][0]
                score, vector = m["cvssData"].get("baseScore"), m["cvssData"].get("vectorString")
                sev = m["cvssData"].get("baseSeverity") or m.get("baseSeverity")
                break
        if kev is None:
            try:
                kev = {x["cveID"]: x for x in cached(KEV_URL, "kev.json", js=True)["vulnerabilities"]}
            except Err:
                kev = {}
        epss = pct = None
        try:
            e = http(f"https://api.first.org/data/v1/epss?cve={cid}", js=True).get("data")
            if e:
                epss, pct = float(e[0]["epss"]), float(e[0]["percentile"])
        except (Err, ValueError, KeyError):
            pass
        for line in textwrap.wrap(desc, 96):
            print(" " + line)
        print(f"\n CVSS:      {score if score is not None else 'n/a'} {sev or ''}   {vector or ''}")
        print(f" EPSS:      {f'{epss*100:.1f}% chance of exploitation in 30 days (top {max(100 - pct * 100, 0.1):.1f}% most likely)' if epss is not None else 'n/a'}")
        print(f" published: {cve.get('published', '')[:10]}   weaknesses: "
              f"{', '.join(d['value'] for w in cve.get('weaknesses', []) for d in w['description']) or '-'}")
        if cid in kev:
            k = kev[cid]
            print(f" [!] CISA KEV: exploited in the wild. Added {k['dateAdded']}, fix due {k['dueDate']}.")
        for r in cve.get("references", [])[:4]:
            print(c("2", f"   {r['url']}"))
        if cid in kev:
            pri, col = "PATCH NOW - actively exploited in the wild", "31"
        elif (epss or 0) >= 0.1 or (score or 0) >= 9:
            pri, col = "HIGH priority - severe or likely to be exploited", "33"
        elif (score or 0) >= 7:
            pri, col = "MEDIUM priority - schedule a fix", "33"
        else:
            pri, col = "LOW priority", "32"
        panel("Patch priority", [pri], col)


# ---------------------------------------------------------------- 26 tls
def cmd_tls(a):
    host, _, port = _host(a.host).partition(":")
    port = int(port or 443)
    cert = err = None

    def connect(ctx):
        with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.getpeercert(), ss.version(), ss.cipher()

    try:
        with Spinner(f"handshaking with {host}:{port}"):
            cert, proto, cipher = connect(ssl.create_default_context())
    except ssl.SSLCertVerificationError as e:
        err = e.verify_message
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            _, proto, cipher = connect(ctx)
        except OSError as e2:
            raise Err(f"connection failed: {e2}")
    except (OSError, ssl.SSLError) as e:
        raise Err(f"could not connect to {host}:{port}: {e}")
    h1(f"TLS certificate for {host}:{port}")
    print(f" protocol: {proto}   cipher: {cipher[0]} ({cipher[2]} bit)")
    flags = []
    if err:
        flags.append(f"certificate NOT trusted: {err}")
        print(c("1;31", f" [!] certificate not trusted: {err}"))
    if cert:
        sub, iss = (dict(x[0] for x in cert[k]) for k in ("subject", "issuer"))
        end = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((end - time.time()) / 86400)
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        print(f" subject:  {sub.get('commonName', '-')}   org: {sub.get('organizationName', '-')}")
        print(f" issuer:   {iss.get('commonName', '-')} ({iss.get('organizationName', '-')})")
        print(f" valid:    {time.strftime('%Y-%m-%d', time.gmtime(ssl.cert_time_to_seconds(cert['notBefore'])))} -> "
              f"{time.strftime('%Y-%m-%d', time.gmtime(end))}  ({days} days left)")
        print(f" serial:   {cert.get('serialNumber')}")
        if days < 0:
            flags.append(f"certificate EXPIRED {-days} days ago")
        elif days < 21:
            flags.append(f"certificate expires in {days} days")
        if sub == iss:
            flags.append("self-signed certificate")
        others = [s for s in sans if s != host]
        h1(f"{len(sans)} name(s) on this certificate (often sibling sites of the same owner)")
        for s in sans[:40]:
            print("   " + s)
        if len(sans) > 40:
            print(c("2", f"   ... and {len(sans) - 40} more"))
        if any(s.startswith("*.") for s in sans):
            print(c("2", " note: includes a wildcard, so any subdomain can share this certificate"))
    if proto in ("TLSv1", "TLSv1.1"):
        flags.append(f"outdated protocol {proto}")
    panel("TLS verdict", flags or ["certificate valid and trusted, modern protocol"], "31" if flags else "32")


# ---------------------------------------------------------------- 27 exif
def _tiff(t):
    e = "<" if t[:2] == b"II" else ">"
    u = lambda f, o: struct.unpack_from(e + f, t, o)
    SZ = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

    def ifd(off):
        out = {}
        try:
            for k in range(u("H", off)[0]):
                o = off + 2 + 12 * k
                tag, typ, cnt = u("HHI", o)
                size = SZ.get(typ, 1) * cnt
                vo = o + 8 if size <= 4 else u("I", o + 8)[0]
                if typ == 2:
                    v = t[vo:vo + cnt].split(b"\0")[0].decode("latin1").strip()
                elif typ == 3:
                    v = list(u(f"{cnt}H", vo))
                elif typ == 4:
                    v = list(u(f"{cnt}I", vo))
                elif typ in (5, 10):
                    n = u(f"{2 * cnt}{'I' if typ == 5 else 'i'}", vo)
                    v = [n[i] / n[i + 1] if n[i + 1] else 0 for i in range(0, len(n), 2)]
                elif typ in (1, 7):
                    v = t[vo:vo + cnt]
                else:
                    continue
                out[tag] = v[0] if isinstance(v, list) and len(v) == 1 else v
        except struct.error:
            pass
        return out

    d = {"ifd0": ifd(u("I", 4)[0])}
    for name, tag in (("exif", 0x8769), ("gps", 0x8825)):
        if isinstance(d["ifd0"].get(tag), int):
            d[name] = ifd(d["ifd0"][tag])
    return d


def _exif(data):
    if data[:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 4 <= len(data) and data[i] == 0xFF and data[i + 1] != 0xDA:
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        if data[i + 1] == 0xE1 and data[i + 4:i + 10] == b"Exif\0\0":
            return _tiff(data[i + 10:i + 2 + ln])
        i += 2 + ln
    return {}


def _deg(v, ref):
    if not isinstance(v, list) or len(v) != 3:
        return None
    d = v[0] + v[1] / 60 + v[2] / 3600
    return -d if ref in ("S", "W") else d


def cmd_exif(a):
    files = []
    for t in a.paths:
        if re.match(r"https?://", t):
            files.append((t, http(t, raw=True, timeout=60)))
        elif os.path.isdir(t):
            for r, _, fs in os.walk(t):
                files += [(os.path.join(r, f), open(os.path.join(r, f), "rb").read())
                          for f in fs if f.lower().endswith((".jpg", ".jpeg"))]
        else:
            files.append((t, open(t, "rb").read()))
    leaks = 0
    for name, data in files:
        h1(name)
        hit = False
        d = _exif(data)
        if d is None:
            print(" not a JPEG (EXIF is read from JPEG photos)")
            continue
        if not d:
            print(" no EXIF metadata (stripped, or a screenshot/edited export)")
            continue
        i0, ex, gps = d.get("ifd0", {}), d.get("exif", {}), d.get("gps", {})
        for label, val in (("Camera", " ".join(x for x in (i0.get(0x010F), i0.get(0x0110)) if x)),
                           ("Lens", ex.get(0xA434)), ("Software", i0.get(0x0131)),
                           ("Taken", ex.get(0x9003) or i0.get(0x0132)), ("Owner/Artist", ex.get(0xA430) or i0.get(0x013B)),
                           ("Copyright", i0.get(0x8298)), ("Body serial", ex.get(0xA431))):
            if val:
                print(f" {label + ':':13} {val}")
        if ex.get(0xA431) or ex.get(0xA430):
            print(" [!] contains a camera serial number / owner name that can identify the device or person")
            hit = True
        lat, lon = _deg(gps.get(2), gps.get(1)), _deg(gps.get(4), gps.get(3))
        if lat is not None and lon is not None:
            leaks += 1
            print(f"\n [!] GPS location embedded: {lat:.6f}, {lon:.6f}")
            if isinstance(gps.get(6), (int, float)):
                print(f"     altitude: {gps[6]:.0f} m")
            print(f"     https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
            print(f"     https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=17/{lat:.6f}/{lon:.6f}")
        else:
            print("\n no GPS coordinates in this file")
    if files:
        panel("Metadata summary", [f"{len(files)} image(s) checked, {leaks} with identifying data",
                                   "tip: strip with `exiftool -all= photo.jpg` before sharing"], "33" if leaks else "32")


# ---------------------------------------------------------------- 28 ip
def _abuse_email(ents):
    for e in ents or []:
        if "abuse" in e.get("roles", []):
            for i in e.get("vcardArray", [0, []])[1]:
                if i[0] == "email":
                    return i[3]
        r = _abuse_email(e.get("entities"))
        if r:
            return r


def cmd_ip(a):
    t = _host(a.target)
    ip = t if _is_ip(t) else next(iter(doh(t, "A") or []), None)
    if not ip:
        raise Err(f"could not resolve {t}")
    obj = ipaddress.ip_address(ip)
    if obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local:
        raise Err(f"{ip} is a private/reserved address - no public intel exists for it")
    h1(f"{ip}" + ("" if ip == t else f"  ({t})"))
    notes = []
    try:
        g = http(f"https://ipwho.is/{ip}", js=True)
        if g.get("success"):
            cn = g.get("connection", {})
            print(f" location: {g.get('city')}, {g.get('region')}, {g.get('country')}  ({g.get('latitude')}, {g.get('longitude')})")
            print(f" network:  AS{cn.get('asn')} {cn.get('org')}  (ISP: {cn.get('isp')})")
            print(f" timezone: {g.get('timezone', {}).get('id')}")
            print(c("2", " note: IP geolocation is city-level at best and wrong for VPNs/CDNs"))
    except Err as e:
        print(f" geolocation skipped: {e}")
    try:
        r = http(f"https://dns.google/resolve?name={obj.reverse_pointer}&type=PTR", js=True, timeout=10)
        ptr = [x["data"] for x in r.get("Answer", []) if x.get("type") == 12]
        print(f" reverse DNS: {', '.join(ptr) or 'none'}")
    except Err:
        pass
    try:
        r = http(f"https://rdap.org/ip/{ip}", js=True, timeout=30)
        print(f"\n registered block: {r.get('startAddress')} - {r.get('endAddress')}  ({r.get('name')}, {r.get('country', '?')})")
        ab = _abuse_email(r.get("entities"))
        if ab:
            print(f" abuse contact:    {ab}")
    except Err as e:
        print(f" RDAP skipped: {e}")
    try:
        if ip in set(cached("https://check.torproject.org/torbulkexitlist", "tor_exits.txt").split()):
            notes.append("this IP is a TOR EXIT NODE")
            print(c("1;31", " [!] Tor exit node: traffic from here is anonymized"))
    except Err:
        pass
    panel("IP summary", notes or ["not a known Tor exit"], "33" if notes else "32")
    print(c("2", f" next: osintkit exposure {ip}   |   osintkit ioc {ip}"))


# ---------------------------------------------------------------- menu / run
# (command, description, [(prompt, flag or None for positional, default)])
MENU = [
    ("headers", "Email header analyzer (phishing triage)", [("Header file (blank = paste, then Ctrl+Z/Ctrl+D)", None, "")]),
    ("username", "Username footprint across sites", [("Username (yours)", None, "")]),
    ("factcheck", "Claim verification + reverse-image links", [("Claim text", None, ""), ("Image URL for reverse search", "--image", "")]),
    ("domain", "Domain recon: DNS, email security, WHOIS, subdomains", [("Domain", None, "")]),
    ("typosquat", "Lookalike / phishing domain hunter", [("Your domain", None, "")]),
    ("tls", "TLS certificate inspector + related names", [("host[:port]", None, "")]),
    ("ip", "IP intel: location, ASN, owner, Tor check", [("IP or domain", None, "")]),
    ("exposure", "Open ports & known CVEs (Shodan InternetDB)", [("IP or domain", None, "")]),
    ("brand", "Brand exposure monitor (your domain)", [("Your domain", None, "")]),
    ("ioc", "Threat-intel IOC enricher", [("IP / domain / URL / hash", None, "")]),
    ("cve", "CVE lookup: severity, exploited-in-wild, EPSS", [("CVE id (e.g. CVE-2021-44228)", None, "")]),
    ("company", "Company registries (SEC / Companies House / OpenCorporates)", [("Company name", None, "")]),
    ("wayback", "Wayback change tracker", [("Page URL", None, "")]),
    ("meta", "Document metadata extractor", [("File, folder or page URL", None, "")]),
    ("exif", "Photo metadata & GPS extractor", [("Image file, folder or URL", None, "")]),
    ("fly", "Aircraft tracker (ADS-B)", [("Callsign", "--callsign", ""), ("Hex code", "--hex", ""),
                                         ("Near lat,lon,radius_nm", "--near", "")]),
    ("vessel", "Vessel tracker (AIS, Baltic)", [("MMSI", "--mmsi", ""), ("Near lat,lon,km", "--near", "")]),
    ("sat", "Satellite imagery (search / compare)", [("Action (search|compare)", None, "search"),
                                                     ("Point lat,lon", "--point", ""),
                                                     ("Range start:end (search)", "--range", "2025-01-01:2025-03-01")]),
    ("monitor", "Feed + Telegram keyword monitor", [("RSS/Atom feed URL", "--feed", ""), ("Telegram channel", "--tg", ""),
                                                    ("Keyword", "--kw", "")]),
    ("setup", "Guided API key setup", []),
    ("doctor", "Which tools are ready", []),
]
MENU_BY = {m[0]: m for m in MENU}
CATS = [
    ("Email & identity", ["headers", "username", "factcheck"]),
    ("Domains & network", ["domain", "typosquat", "tls", "ip", "exposure", "brand"]),
    ("Threat intel", ["ioc", "cve"]),
    ("Records & media", ["company", "wayback", "meta", "exif"]),
    ("Tracking & imagery", ["fly", "vessel", "sat"]),
    ("Monitoring", ["monitor"]),
    ("Setup", ["setup", "doctor"]),
]
ORDER = [cmd for _, cs in CATS for cmd in cs]


def run(argv):
    global COLOR
    if argv and not argv[0].startswith("-") and argv[0] not in MENU_BY:
        sug = difflib.get_close_matches(argv[0], ORDER, 1, 0.5)
        _print(c("1;31", f"unknown command '{argv[0]}'") + (f" - did you mean '{sug[0]}'?" if sug else "")
               + c("2", "   (osintkit -h lists everything)"))
        return
    try:
        a = build_parser().parse_args(argv)
    except SystemExit:
        return
    if a.no_color:
        COLOR = False
    real, f = sys.stdout, None
    if a.save:
        try:
            f = open(a.save, "w", encoding="utf8")
        except OSError as e:
            _print(c("1;31", f"error: cannot write {a.save}: {e}"))
            return
        sys.stdout = _Tee(real, f)
    try:
        a.fn(a)
    except Err as e:
        _print(c("1;31", f"error: {e}"))
    except EOFError:
        _print(c("1;31", "error: this command needs interactive input (no terminal attached)"))
    except KeyboardInterrupt:
        _print()
    finally:
        if f:
            sys.stdout = real
            f.close()
            _print(c("2", f"report saved to {a.save}"))


def _status(cmd):
    req = REQUIRED.get(cmd)
    if not req:
        return c("32", "●")
    return c("32", "●") if all(_have(k) for k in req) else c("33", "○")


def show_menu():
    n = 0
    for title, cmds in CATS:
        _print("\n " + c("1;35", title.upper()))
        for cmd in cmds:
            n += 1
            _print(f"  {c('1;36', f'{n:>2}')}  {_status(cmd)} {c('1', cmd.ljust(10))} {c('2', MENU_BY[cmd][1])}")
    _print(c("2", "\n  ● ready   ○ works, more sources with API keys (run: setup)"))


def _resolve_cmd(tok):
    tok = tok.lower()
    if tok.isdigit() and 1 <= int(tok) <= len(ORDER):
        return ORDER[int(tok) - 1]
    if tok in MENU_BY:
        return tok
    pref = [x for x in ORDER if x.startswith(tok)]
    return pref[0] if len(pref) == 1 else None


HELP = f""" {c('1', 'How to use')}
  {c('1;36', 'number or name')}    pick a tool; you'll be asked for its inputs        e.g.  10   or   ioc
  {c('1;36', 'full command')}      run it in one line                                 e.g.  ioc 8.8.8.8
  {c('1;36', '?name')}             show that tool's options                           e.g.  ?fly
  {c('1;36', '!')}                 repeat the last command
  {c('1;36', 'l')}  list tools   {c('1;36', 'k')}  key status   {c('1;36', 'h')}  this help   {c('1;36', 'q')}  quit
  {c('2', 'Tip: unique prefixes work (hea = headers). Add --save report.txt to any command to keep the output.')}"""


def menu():
    banner()
    first_run()
    try:
        import readline
        readline.set_completer(lambda t, i: ([x for x in ORDER if x.startswith(t)] + [None])[i])
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass
    if not any(_have(k) for k in KEYS):
        _print(c("2", " tip: type 'setup' to unlock more sources in ioc, factcheck, brand and company\n"))
    show_menu()
    _print(c("2", "\n  type a number or name  ·  'h' help  ·  'q' quit"))
    last = None
    while True:
        try:
            line = input(c("1;35", "\n osint› ")).strip()
        except (EOFError, KeyboardInterrupt):
            _print()
            return
        low = line.lower()
        if not low:
            continue
        if low in ("q", "quit", "exit"):
            return
        if low in ("h", "help", "?"):
            _print(HELP)
            continue
        if low in ("l", "list", "ls"):
            show_menu()
            continue
        if low in ("k", "keys", "status"):
            cmd_doctor(None)
            continue
        if low == "!":
            if last:
                run(last)
            else:
                _print(c("33", " nothing to repeat yet"))
            continue
        try:
            parts = [p.strip("\"'") for p in shlex.split(line, posix=(os.name != "nt"))]
        except ValueError:
            _print(c("33", " unbalanced quotes"))
            continue
        help_only = parts[0].startswith("?")
        cmd = _resolve_cmd(parts[0].lstrip("?"))
        if not cmd:
            sug = difflib.get_close_matches(parts[0].lstrip("?"), ORDER, 1, 0.5)
            _print(c("33", f" no tool called '{parts[0]}'") + (f" - did you mean '{sug[0]}'?" if sug else "") + c("2", "  ('l' lists tools)"))
            continue
        if help_only:
            run([cmd, "-h"])
            continue
        if len(parts) > 1:
            argv = [cmd] + parts[1:]
        else:
            args, pos = [], []
            try:
                for label, flag, default in MENU_BY[cmd][2]:
                    v = input(f"  {label}{c('2', f' [{default}]') if default else ''}: ").strip() or default
                    if v:
                        (args.extend if flag else pos.extend)([flag, v] if flag else [v])
            except (EOFError, KeyboardInterrupt):
                _print()
                continue
            argv = [cmd] + pos + args  # positionals first for argparse
        last = argv
        run(argv)


def build_parser():
    p = argparse.ArgumentParser(prog="osintkit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="osintkit 1.2.0")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--save", metavar="FILE", help="also write the output to FILE (put before the command)")
    s = p.add_subparsers(dest="cmd", required=True)

    x = s.add_parser("headers", help="analyze raw email headers"); x.add_argument("file", nargs="?", help="file (default stdin)")
    x.set_defaults(fn=cmd_headers)

    x = s.add_parser("company", help="company registries"); x.add_argument("name")
    x.add_argument("--source", choices=["all", "sec", "ch", "oc"], default="all")
    x.add_argument("--number", help="Companies House number for officers/PSC detail"); x.set_defaults(fn=cmd_company)

    x = s.add_parser("wayback", help="diff archived versions of a page"); x.add_argument("url")
    x.add_argument("--a", type=int, help="older version index"); x.add_argument("--b", type=int, help="newer version index")
    x.add_argument("--limit", type=int, default=60); x.add_argument("--max-lines", type=int, default=80)
    x.set_defaults(fn=cmd_wayback)

    x = s.add_parser("fly", help="aircraft via ADS-B (adsb.lol)")
    x.add_argument("--hex"); x.add_argument("--callsign"); x.add_argument("--near", help="lat,lon,radius_nm")
    x.add_argument("--fence", help="lat,lon,km - alert when aircraft enters"); x.add_argument("--watch", type=int, help="poll every N s")
    x.set_defaults(fn=cmd_fly)

    x = s.add_parser("vessel", help="ships via AIS (Digitraffic)"); x.add_argument("--mmsi"); x.add_argument("--near", help="lat,lon,km")
    x.set_defaults(fn=cmd_vessel)

    x = s.add_parser("sat", help="Sentinel-2 search / compare"); x.add_argument("action", choices=["search", "compare"])
    x.add_argument("--point", help="lat,lon"); x.add_argument("--bbox", help="minlon,minlat,maxlon,maxlat")
    x.add_argument("--radius-km", type=float, default=2.0); x.add_argument("--cloud", type=float, default=20)
    x.add_argument("--range", default="2024-01-01:2024-12-31", help="search: start:end")
    x.add_argument("--before", default="2020-01-01:2020-12-31"); x.add_argument("--after", default="2024-01-01:2024-12-31")
    x.add_argument("--out", default="sat_out"); x.set_defaults(fn=cmd_sat)

    x = s.add_parser("monitor", help="keyword monitor for feeds / Telegram")
    x.add_argument("--feed", action="append", default=[]); x.add_argument("--tg", action="append", default=[], help="public channel name")
    x.add_argument("--kw", action="append", default=[], help="keyword (repeatable); none = show all new")
    x.add_argument("--loop", type=int, help="repeat every N seconds"); x.set_defaults(fn=cmd_monitor)

    x = s.add_parser("meta", help="document metadata leaks"); x.add_argument("target", help="file, folder or page URL")
    x.add_argument("--max", type=int, default=15); x.set_defaults(fn=cmd_meta)

    x = s.add_parser("ioc", help="enrich IP/domain/URL/hash"); x.add_argument("value"); x.set_defaults(fn=cmd_ioc)

    x = s.add_parser("brand", help="brand-side exposure check"); x.add_argument("domain"); x.set_defaults(fn=cmd_brand)

    x = s.add_parser("factcheck", help="claim / image verification"); x.add_argument("claim", nargs="?")
    x.add_argument("--image", help="image URL for reverse-search links"); x.add_argument("--lang", default="en")
    x.set_defaults(fn=cmd_factcheck)

    x = s.add_parser("domain", help="full domain recon"); x.add_argument("domain")
    x.add_argument("--max", type=int, default=40, help="max subdomains to list"); x.set_defaults(fn=cmd_domain)

    x = s.add_parser("typosquat", help="find lookalike/phishing domains"); x.add_argument("domain")
    x.add_argument("--max", type=int, default=400, help="max variants to test")
    x.add_argument("--age", action="store_true", help="show registration age of hits"); x.set_defaults(fn=cmd_typosquat)

    x = s.add_parser("username", help="username footprint across sites"); x.add_argument("name")
    x.set_defaults(fn=cmd_username)

    x = s.add_parser("exposure", help="open ports and known CVEs (Shodan InternetDB)"); x.add_argument("target")
    x.add_argument("--max", type=int, default=15, help="max CVEs to list"); x.set_defaults(fn=cmd_exposure)

    x = s.add_parser("cve", help="CVE severity, exploited-in-wild, EPSS"); x.add_argument("ids", nargs="+", metavar="CVE-ID")
    x.set_defaults(fn=cmd_cve)

    x = s.add_parser("tls", help="TLS certificate inspector"); x.add_argument("host", help="host or host:port")
    x.set_defaults(fn=cmd_tls)

    x = s.add_parser("exif", help="photo metadata and GPS extractor"); x.add_argument("paths", nargs="+", help="JPEG file(s), folder, or URL")
    x.set_defaults(fn=cmd_exif)

    x = s.add_parser("ip", help="IP location, network owner, Tor check"); x.add_argument("target", help="IP or domain")
    x.set_defaults(fn=cmd_ip)

    x = s.add_parser("setup", help="guided API key setup")
    x.add_argument("--quick", action="store_true", help="just the 5 recommended free keys")
    x.add_argument("--only", choices=list(TOOL_KEYS), help="only the keys one tool uses")
    x.add_argument("--set", action="append", metavar="NAME=VALUE", help="save a key non-interactively (repeatable)")
    x.add_argument("--from-env", nargs="?", const="", default=None, metavar="FILE",
                   help="import keys from the environment, or from a .env file")
    x.set_defaults(fn=cmd_setup)
    x = s.add_parser("doctor", help="show which tools are ready"); x.set_defaults(fn=cmd_doctor)

    return p


def main():
    if len(sys.argv) == 1 and sys.stdin.isatty():
        return menu()
    if COLOR and sys.argv[1:2] not in (["-h"], ["--help"]):
        banner()
    run(sys.argv[1:])


if __name__ == "__main__":
    main()
