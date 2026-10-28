# vulnscan

A small web scanner written in Python with two classes: one that probes a target, one that turns the results into a report.

## What it does

- **`VulnScanner`** checks whether a URL is reachable and prints its HTTP status code, then pulls and prints every response header (colour-coded in the terminal with colorama).
- **`ReportGenerator`** takes the collected results and writes a dark-themed `report.html` table: URL, status code, response headers.
- **`database.py`** creates a SQLite `scans` table (URL, status code, headers) for storing scan history.

Response headers are where a lot of web security starts: missing `Content-Security-Policy`, `Strict-Transport-Security` or `X-Frame-Options`, or a `Server` header that leaks a version number, are all visible here.

## Tech

Python · requests · sqlite3 · colorama · OOP

## Run it

```
pip install requests colorama
python database.py   # create vulnscan.db
python scanner.py    # scans the target set at the bottom of scanner.py
```

Open `report.html` in a browser to see the results.

## Next steps

- Take the target URL from the command line instead of hard-coding it
- Flag missing security headers automatically
- Call `save_results` so every scan lands in the database

> Only scan sites you own or have written permission to test.
