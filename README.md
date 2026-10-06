# osintkit

A stdlib-only Python CLI bundling 19 open-source-intelligence tools, with a categorized interactive menu, progress bars and result panels.

![osintkit demo](docs/demo.gif)

<p>
  <img src="docs/menu.png" alt="Interactive menu" width="48%">
  <img src="docs/screenshot.png" alt="Email header analysis" width="48%">
</p>

## Install & first run

```
pip install git+https://github.com/Crepald-01/osintkit   # gives you a global `osintkit` command
osintkit                                                   # opens the menu; offers a 2-minute key setup on first launch
```

If `osintkit` isn't found afterwards, Python's Scripts folder isn't on your PATH; use `python -m osintkit` instead (or install with `pipx`).

No install? Just clone and run `python osintkit.py` (Windows: `osintkit.bat`). Python 3.8+, no dependencies.

Most tools work with no keys. Four (`ioc`, `company`, `brand`, `factcheck`) get more sources when you add free API keys:

```
osintkit setup                  # guided: quick start / everything / one tool; opens signup pages; checks each key as you paste it
osintkit setup --only ioc       # just the keys one tool uses
osintkit setup --set VT_API_KEY=xxxx --set ABUSEIPDB_KEY=yyyy   # non-interactive
osintkit setup --from-env .env  # import from a .env file (or the environment if no file given)
osintkit doctor                 # which tools are ready, and what each missing key unlocks
```

Keys are saved in plain text to `~/.osintkit/keys.json`; real environment variables take priority.

## Tools

| Command | Purpose | Keys |
|---|---|---|
| `headers` | Email header analyzer: relay path, SPF/DKIM/DMARC, spoof flags | none |
| `username` | Username footprint across ~28 sites | none |
| `factcheck` | Fact-check lookup + reverse-image links | claim lookup: Google key |
| `domain` | DNS, email security, RDAP age, security headers, subdomains | none |
| `typosquat` | Find registered lookalike / phishing domains | none |
| `tls` | TLS certificate inspector + related names (SANs) | none |
| `ip` | IP location, ASN, owner, abuse contact, Tor-exit check | none |
| `exposure` | Open ports and known CVEs for an IP/domain (Shodan InternetDB) | none |
| `brand` | Brand exposure: HIBP, GitHub mentions, certificate transparency | optional |
| `ioc` | IP/domain/URL/hash enrichment (VirusTotal, AbuseIPDB, URLhaus, GreyNoise) | optional |
| `cve` | CVE severity, exploited-in-the-wild (CISA KEV), EPSS | none |
| `company` | SEC EDGAR / Companies House / OpenCorporates | SEC: none |
| `wayback` | Diff archived versions of a page | none |
| `meta` | Document metadata leak finder (PDF/Office) | none |
| `exif` | Photo metadata and embedded GPS extractor | none |
| `fly` / `vessel` | Aircraft (ADS-B) and ship (AIS) tracking, geofence alerts | none |
| `sat` | Sentinel-2 search and before/after comparison | none |
| `monitor` | Keyword monitor for RSS feeds and public Telegram channels | none |

15 of 19 tools need no keys at all.

## Using the menu

Run `osintkit` with no arguments. Type a number or name, or the whole command in one line:

```
osint› 11                  # pick by number, you'll be asked for the inputs
osint› cve CVE-2021-44228  # or run it in one line
osint› hea                 # unique prefixes work
osint› ?fly                # show a tool's options
osint› !                   # repeat the last command
```

`●` means a tool is fully ready, `○` means it works but gains sources once you add API keys.

Global options go before the command: `osintkit --save report.txt ip 1.1.1.1` keeps a plain-text copy of the output, `--no-color` disables colors, and mistyped commands get a "did you mean" suggestion.

Most tools need no key. Run `python osintkit.py doctor` to see which API keys are set.

## Responsible use
Public data only. Use on assets you own or are authorized to assess; do not use to profile or track private individuals.
