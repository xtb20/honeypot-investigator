"""Import Kibana Cowrie CSV exports without executing captured content."""
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).with_name('events.sqlite3')


def connect(path=DEFAULT_DB):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute('''CREATE TABLE IF NOT EXISTS events (
        index_name TEXT NOT NULL, event_id TEXT NOT NULL,
        timestamp TEXT NOT NULL, sensor TEXT NOT NULL, session TEXT,
        source_ip TEXT, event_type TEXT, command TEXT, details TEXT,
        PRIMARY KEY (index_name, event_id))''')
    return db


def value(row, *names):
    for name in names:
        text = row.get(name)
        if text is not None and text.strip() not in ('', '-'):
            return text
    return None


def timestamp(text):
    # Kibana display timestamps have no timezone: preserve them as local display time.
    for fmt in ('%b %d, %Y @ %H:%M:%S.%f', '%b %d, %Y @ %H:%M:%S'):
        try:
            return datetime.strptime(text, fmt).isoformat(timespec='milliseconds')
        except ValueError:
            pass
    return datetime.fromisoformat(text.replace('Z', '+00:00')).isoformat()


def import_csv(stream, db):
    reader = csv.DictReader(stream)
    required = {'_index', '_id', 'session', 'eventid'}
    fields = set(reader.fieldnames or [])
    if not required.issubset(fields) or not fields.intersection({'type', 'Type (type)'}):
        raise ValueError('Select a Kibana Cowrie CSV with _index, _id, session, eventid and type columns.')
    counts = dict(read=0, imported=0, duplicates=0, skipped=0, extra_column_rows=0)
    with db:
        for line, row in enumerate(reader, 2):
            counts['read'] += 1
            if value(row, 'type', 'Type (type)') != 'Cowrie':
                counts['skipped'] += 1
                continue
            try:
                if not all(value(row, f) for f in required):
                    raise ValueError('missing identity or session fields, or malformed CSV')
                if None in row:
                    # Some Discover exports append columns without updating the header.
                    # Preserve these values without inventing field names or meanings.
                    row['_unmapped_trailing_values'] = row.pop(None)
                    counts['extra_column_rows'] += 1
                time = timestamp(value(row, '@timestamp', 'timestamp') or '')
                sensor = value(row, 'sensor', 'T-Pot Hostname (t-pot_hostname)', 't-pot_hostname', 'host')
                if not sensor:
                    raise ValueError('missing sensor identity')
                result = db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)', (
                    row['_index'], row['_id'], time, sensor, row['session'],
                    value(row, 'src_ip'), row['eventid'], value(row, 'input'), json.dumps(row)))
                counts['imported' if result.rowcount else 'duplicates'] += 1
            except (ValueError, TypeError) as exc:
                raise ValueError(f'CSV row {line}: {exc}. This import was rolled back.') from exc
    return counts


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv', type=Path)
    parser.add_argument('--database', type=Path, default=DEFAULT_DB)
    args = parser.parse_args()
    with args.csv.open(encoding='utf-8-sig', newline='') as source, connect(args.database) as db:
        print(json.dumps(import_csv(source, db), indent=2))
