import io
import json
import streamlit as st
from importer import connect, import_csv

st.set_page_config(page_title='Honeypot Investigator', layout='wide')
st.title('Honeypot Investigator')
st.caption('Cowrie session evidence. Captured commands are displayed as text only. Times retain the export timezone.')
db = connect()
upload = st.sidebar.file_uploader('Choose your Cowrie CSV', type=['csv'])
if st.sidebar.button('Import CSV', disabled=upload is None):
    try:
        counts = import_csv(io.StringIO(upload.getvalue().decode('utf-8-sig')), db)
        st.sidebar.success(f"Imported {counts['imported']:,}; duplicates {counts['duplicates']:,}; non-Cowrie rows skipped {counts['skipped']:,}.")
        if counts['extra_column_rows']:
            st.sidebar.warning(f"{counts['extra_column_rows']:,} Cowrie rows have extra unnamed columns. Preserved privately; verify mapped fields against the source before drawing conclusions.")
    except (ValueError, UnicodeError) as exc:
        st.sidebar.error(str(exc))

summary = db.execute('''SELECT COUNT(*) AS events,
    SUM(event_type='cowrie.command.input') AS commands FROM events''').fetchone()
sessions = [dict(row) for row in db.execute('''SELECT sensor, session,
    MIN(timestamp) AS first_event, MAX(timestamp) AS last_event,
    MAX(source_ip) AS source_ip, COUNT(*) AS events,
    SUM(event_type IN ('cowrie.login.failed','cowrie.login.success')) AS login_attempts,
    SUM(event_type='cowrie.login.success') AS honeypot_logins,
    SUM(event_type='cowrie.command.input') AS commands,
    SUM(event_type='cowrie.session.file_download') AS downloads,
    MAX(event_type='cowrie.session.connect') AS has_connection,
    MAX(event_type='cowrie.session.closed') AS has_closure
    FROM events GROUP BY sensor,session ORDER BY first_event DESC''')]
a, b, c = st.columns(3)
a.metric('Cowrie events', summary['events'])
b.metric('Sessions', len(sessions))
c.metric('Command input events', summary['commands'] or 0)
if not sessions:
    st.info('Upload your Cowrie export in the sidebar, then click Import CSV.')
    st.stop()

query = st.text_input('Filter by source IP or session ID').strip()
commands_only = st.checkbox('Only sessions with commands')
filtered = [s for s in sessions if (not commands_only or s['commands']) and
            (not query or query in (s['source_ip'] or '') or query in s['session'])]
st.dataframe(filtered, use_container_width=True, hide_index=True)
if not filtered:
    st.info('No sessions match these filters.')
    st.stop()
selected = st.selectbox('Investigate a session', range(len(filtered)),
    format_func=lambda i: f"{filtered[i]['first_event']} | {filtered[i]['source_ip']} | {filtered[i]['session']}")
session = filtered[selected]
if not session['has_connection'] or not session['has_closure']:
    st.warning('This export does not contain both connection and closure events for this session.')
st.caption('A successful honeypot login means the honeypot accepted credentials. It does not establish compromise of a real system.')
rows = db.execute('SELECT * FROM events WHERE sensor=? AND session=? ORDER BY timestamp,event_id',
                  (session['sensor'], session['session'])).fetchall()
report = []
for row in rows:
    # Allowlisted evidence avoids exposing passwords and authentication responses.
    raw = json.loads(row['details'])
    evidence = {k: raw[k] for k in ('input','url','outfile','shasum','protocol','version','duration')
                if raw.get(k) and raw[k] != '-'}
    item = {'timestamp': row['timestamp'], 'event': row['event_type'],
            'index': row['index_name'], 'id': row['event_id'], 'evidence': evidence}
    report.append(item)
    with st.expander(f"{row['timestamp']} — {row['event_type']}"):
        st.json(item)
st.download_button('Download session evidence (JSON)',
    json.dumps({'session': session, 'timeline': report}, indent=2),
    file_name='session-evidence.json', mime='application/json')
st.caption('Session exports can contain source IPs and sensitive command text. Review before publishing. The local database retains original records, including credentials.')
db.close()
