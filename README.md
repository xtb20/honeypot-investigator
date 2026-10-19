# Honeypot Investigator

A local Cowrie CSV importer and session investigation screen. No VPS changes required.

## Start on Windows

Install Python 3.11 or newer if `py --version` does not work. Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Open the local URL printed in the terminal. Choose the Cowrie CSV in the sidebar and click Import CSV. Select “Only sessions with commands” and open a session. Press Ctrl+C in the terminal to stop.

Expected totals from the previously inspected export: 8,561 Cowrie events, 1,645 sessions, 508 command-input events. Its other 152 NGINX rows are skipped. These counts must be checked against the original file when available.

## Import without the interface

```powershell
py importer.py "C:\path\to\Cowrie.csv"
```

The importer uses Python's standard library. Original records stay in `events.sqlite3` alongside normalized fields. Reimporting the same `_index` and `_id` does not create duplicates. A malformed Cowrie record rolls back the entire current import. Sessions are grouped by sensor and session ID. Timezone-free export times are preserved without assuming UTC; do not combine exports using different display timezones.

## Privacy and interpretation

Some supplied CSV rows have more values than the header defines. The importer preserves trailing values as `_unmapped_trailing_values` and displays a warning. They are not interpreted. Validate mapped fields against the original source before relying on findings; a fresh JSON export is preferable for final analysis.

Keep the database and original CSV private: they contain captured credentials and infrastructure details. The interface hides credentials through an allowlist, but command text and downloaded session reports may still contain sensitive data. Captured commands and URLs are never executed or fetched. Honeypot login success is not evidence of real-system compromise. File-download events establish what Cowrie recorded, not malware classification or subsequent execution.

## Verification

```powershell
py -m unittest discover -s tests -v
```

Tests use synthetic events for duplicate imports, sensor separation, mixed sensor exports, and rollback on malformed input. No live honeypot required.
