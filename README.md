# osintkit

A stdlib-only Python CLI bundling 13 open-source-intelligence tools, with a colored interactive menu.

![osintkit demo](docs/demo.gif)

<p>
  <img src="docs/menu.png" alt="Interactive menu" width="48%">
  <img src="docs/screenshot.png" alt="Email header analysis" width="48%">
</p>

## Quick start

```
python osintkit.py          # interactive menu
python osintkit.py -h       # all commands
python osintkit.py setup    # save API keys (optional)
```

| Command | Purpose |
|---|---|
| `headers` | Email header analyzer: relay path, SPF/DKIM/DMARC, spoof flags |
| `company` | SEC EDGAR / Companies House / OpenCorporates lookups |
| `wayback` | Diff archived versions of a page |
| `fly` / `vessel` | Aircraft (ADS-B) and ship (AIS) tracking, geofence alerts |
| `sat` | Sentinel-2 search and before/after comparison |
| `monitor` | Keyword monitor for RSS feeds and public Telegram channels |
| `meta` | Document metadata leak finder |
| `ioc` | IP/domain/URL/hash enrichment (VirusTotal, AbuseIPDB, URLhaus, GreyNoise) |
| `brand` | Brand exposure check (HIBP, GitHub, certificate transparency) |
| `factcheck` | Fact-check lookup and reverse-image links |
| `domain` | DNS, email security, RDAP, security headers, subdomains |
| `typosquat` | Find registered lookalike domains |
| `username` | Username footprint across ~28 sites |

Most tools need no key. Run `python osintkit.py doctor` to see which API keys are set.

## Responsible use
Public data only. Use on assets you own or are authorized to assess; do not use to profile or track private individuals.
