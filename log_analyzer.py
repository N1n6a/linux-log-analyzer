#!/usr/bin/env python3
"""
Linux Log Analyzer
===================
Parses Linux authentication / system logs (auth.log, secure, syslog, or
journalctl short-iso style output; plain or .gz) and produces:
    1. An interactive HTML report with tabs for log entries, failed login attempts, successful logins, sudo commands, suspicious events, and top source IPs (failed logins)
    2. A JSON file with the same findings, structured for machine use.

Usage:
    python3 log_analyzer.py -i <log_path> -o <analyzer_output_file>
    python3 log_analyzer.py -i <log_path> -o <analyzer_output_file> --allowlist-ip <IP_address>
    python3 log_analyzer.py -i <log_path> -o <analyzer_output_file> --brute-force-threshold <brute_force_threshold_limit> --brute-force-window <brute_force_window_in_seconds>
    python3 log_analyzer.py -i <log_path> -o <analyzer_output_file> --year <year>

Known limitations:
  - Classic syslog timestamps don't include a year, so one is assumed (via --year, or current year by default). This can misattribute entries for logs spanning a year boundary; pass --year explicitly if analyzing archived/rotated logs from a prior year.
  - A truly blank username field is left unparsed rather than guessed at from ambiguous data.
  - Windows event log support is intentionally out of scope for this version.
  - Multi-file input works fully in the CLI (`-i file1.log file2.log ...` aggregates all of them into one combined report), but the web dashboard does not currently parse correctly when multiple files are uploaded at once. Use the CLI if you need to analyze more than one log file in a single run.
"""

import argparse
import gzip
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from html import escape





RE_TIMESTAMP_SYSLOG = re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+')
RE_TIMESTAMP_ISO = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+')

RE_FAILED_PASSWORD = re.compile(
    r'Failed (?:password|none|keyboard-interactive/pam) for (?:(?P<invalid>invalid user)\s+)?'
    r'(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)'
)
RE_ACCEPTED = re.compile(
    r'Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)'
)
RE_INVALID_USER = re.compile(r'Invalid user\s+(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)')
RE_AUTH_FAILURE = re.compile(
    r'authentication failure;.*?rhost=(?P<ip>[\d.:a-fA-F]*)(?:\s+user=(?P<user>\S+))?'
)


RE_PAM_MORE_FAILURES = re.compile(
    r'PAM (?P<count>\d+) more authentication failures?;.*?rhost=(?P<ip>[\d.:a-fA-F]*)(?:\s+user=(?P<user>\S+))?'
)


RE_MESSAGE_REPEATED = re.compile(r'message repeated (?P<count>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]?\s*$')
RE_FAILED_SU = re.compile(r'FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)')
RE_MAX_AUTH_EXCEEDED = re.compile(
    r'maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)'
)
RE_PRIV_ESCALATION = re.compile(
    r"add\s+'?(?P<user>\S+?)'?\s+to\s+group\s+'?(?P<group>sudo|wheel|admin|root)'?", re.IGNORECASE
)
RE_SUDO = re.compile(
    r'sudo:\s*(?P<user>\S+)\s*:\s*(?:(?P<fail>\d+) incorrect password attempts?\s*;\s*)?'
    r'TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<asuser>\S+)\s*;\s*COMMAND=(?P<command>.*)'
)
RE_SUDO_SESSION_OPENED = re.compile(r'sudo:session\)?:\s*session opened for user (?P<user>\S+)')
RE_BREAKIN = re.compile(r'POSSIBLE BREAK-IN ATTEMPT', re.IGNORECASE)
RE_ROOT_LOGIN = re.compile(r'\b(user|for)\s+root\b', re.IGNORECASE)
RE_NEW_USER = re.compile(r'new user:\s*name=(?P<user>\S+)', re.IGNORECASE)
RE_NEW_GROUP = re.compile(r'new group:\s*name=(?P<group>\S+)', re.IGNORECASE)
RE_CRON = re.compile(r'\bCRON\b')
RE_DISCONNECT_PREAUTH = re.compile(r'Disconnected from (?:invalid user )?\S* ?(?P<ip>[\d.:a-fA-F]+) port \d+ \[preauth\]')


RISKY_SUDO_PATTERNS = [
    (re.compile(r'curl[^|;]*\|\s*(sudo\s+)?(ba)?sh\b', re.IGNORECASE),
     "Downloads and executes remote code (curl piped to a shell)"),
    (re.compile(r'wget[^|;]*\|\s*(sudo\s+)?(ba)?sh\b', re.IGNORECASE),
     "Downloads and executes remote code (wget piped to a shell)"),
    (re.compile(r'base64\s+(-d|--decode)[^|;]*\|\s*(ba)?sh\b', re.IGNORECASE),
     "Decodes and executes a base64-obfuscated payload"),
    (re.compile(r'\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/var/log|/etc|/boot|/root\b|/home\b|/)', re.IGNORECASE),
     "Attempts to delete critical system or log files"),
    (re.compile(r'\bchmod\s+(-R\s+)?777\b', re.IGNORECASE),
     "Sets world-writable permissions (777)"),
    (re.compile(r'/dev/tcp/\d|\bnc\s+.*-e\s|\bncat\s+.*-e\s|bash\s+-i\s*>&\s*/dev/tcp', re.IGNORECASE),
     "Possible reverse shell"),
    (re.compile(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:'),
     "Fork bomb"),
    (re.compile(r'\biptables\s+(-F|--flush)\b', re.IGNORECASE),
     "Flushes firewall rules"),
    (re.compile(r'\bhistory\s+-c\b|unset\s+HISTFILE|>\s*~?/?\.bash_history', re.IGNORECASE),
     "Clears or disables shell command history (anti-forensics)"),
    (re.compile(r'systemctl\s+(stop|disable)\s+(auditd|rsyslog|wazuh\S*|ufw|apparmor|firewalld|suricata)', re.IGNORECASE),
     "Disables a security or logging service"),
    (re.compile(r'\bdd\s+.*\bif=.*\bof=/dev/(sd|nvme|hd|vd)', re.IGNORECASE),
     "Raw disk write - possible destructive wipe"),
    (re.compile(r'\buserdel\b.*\b(root|admin)\b', re.IGNORECASE),
     "Deletes a privileged account"),
    (re.compile(r'\bvisudo\b|/etc/sudoers\b', re.IGNORECASE),
     "Directly modifies sudoers configuration"),
]


SEVERITY_RANK = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}
SUSPICIOUS_SEVERITY = {
    'possible_break_in': 'high',
    'invalid_user_probe': 'low',
    'new_user_created': 'medium',
    'new_group_created': 'medium',
    'privilege_escalation': 'high',
    'root_login_success': 'medium',
    'brute_force_suspected': 'high',
    'brute_force_rapid': 'critical',
    'failed_su': 'medium',
    'max_auth_attempts_exceeded': 'medium',
    'risky_sudo_command': 'critical',
    'compromised_account_suspected': 'critical',
}

# Defaults (overridable by CLI flags)
BRUTE_FORCE_THRESHOLD = 5          
BRUTE_FORCE_WINDOW_SECONDS = 300    
CORRELATION_MIN_FAILURES = 3        
CORRELATION_WINDOW_SECONDS = 1800   


def parse_timestamp(line):
    m = RE_TIMESTAMP_ISO.match(line)
    if m:
        return m.group('ts')
    m = RE_TIMESTAMP_SYSLOG.match(line)
    if m:
        return m.group('ts')
    return None


def to_datetime(ts_raw, assume_year):
    if not ts_raw:
        return None
    if re.match(r'^\d{4}-\d{2}-\d{2}T', ts_raw):
        try:
            return datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
        except ValueError:
            return None
    try:
        return datetime.strptime(f"{assume_year} {ts_raw.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


class LinuxLogAnalyzer:
    def __init__(self, brute_force_threshold=BRUTE_FORCE_THRESHOLD,
                 brute_force_window_seconds=BRUTE_FORCE_WINDOW_SECONDS,
                 correlation_window_seconds=CORRELATION_WINDOW_SECONDS,
                 allowlist_ips=None, assume_year=None):
        self.total_lines = 0
        self.parsed_lines = 0
        self.failed_logins = []      
        self.successful_logins = []  
        self.sudo_commands = []      
        self.suspicious_events = []  
        self.source_files = []
        self.unparsed_sample = []    

        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_seconds = brute_force_window_seconds
        self.correlation_window_seconds = correlation_window_seconds
        self.assume_year = assume_year or datetime.now().year
        self._used_assumed_year = False  # set True if we have to guess the year

        self._allowlist_nets = []
        for item in (allowlist_ips or []):
            try:
                self._allowlist_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                print(f"[!] Ignoring invalid allowlist entry: {item}", file=sys.stderr)


    def is_allowlisted(self, ip):
        if not ip or not self._allowlist_nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allowlist_nets)


    def analyze_file(self, filepath):
        self.source_files.append(filepath)
        opener = gzip.open if filepath.endswith('.gz') else open
        with opener(filepath, 'rt', errors='replace') as f:
            for raw_line in f:
                line = raw_line.rstrip('\n')
                if not line.strip():
                    continue
                self.total_lines += 1
                self._parse_line(line, filepath)


    def _parse_line(self, line, source_file):
        ts = parse_timestamp(line)
        ts_iso = None
        if ts:
            if not re.match(r'^\d{4}-\d{2}-\d{2}T', ts):
                self._used_assumed_year = True
            dt = to_datetime(ts, self.assume_year)
            if dt:
                ts_iso = dt.isoformat()
        matched_something = False


        rep = RE_MESSAGE_REPEATED.search(line)
        repeat_multiplier = 1
        effective_line = line
        if rep:
            matched_something = True
            repeat_multiplier = max(1, int(rep.group('count')))
            effective_line = rep.group('inner')


        m = RE_FAILED_PASSWORD.search(effective_line)
        if m and m.group('user'):
            matched_something = True
            entry = {
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'user': m.group('user'),
                'ip': m.group('ip'),
                'port': m.group('port'),
                'invalid_user': bool(m.group('invalid')),
                'source_file': source_file,
                'raw': line,
            }
            for _ in range(repeat_multiplier):
                self.failed_logins.append(dict(entry))


        m2 = RE_AUTH_FAILURE.search(effective_line)
        if m2 and not m:
            matched_something = True
            ip = m2.group('ip') or None
            entry = {
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'user': m2.group('user') or 'unknown',
                'ip': ip,
                'port': None,
                'invalid_user': False,
                'source_file': source_file,
                'raw': line,
            }
            for _ in range(repeat_multiplier):
                self.failed_logins.append(dict(entry))


        m3 = RE_PAM_MORE_FAILURES.search(line)
        if m3:
            matched_something = True
            count = int(m3.group('count'))
            ip = m3.group('ip') or None
            entry = {
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'user': m3.group('user') or 'unknown',
                'ip': ip,
                'port': None,
                'invalid_user': False,
                'aggregated': True,
                'source_file': source_file,
                'raw': line,
            }
            for _ in range(count):
                self.failed_logins.append(dict(entry))


        m4 = RE_FAILED_SU.search(line)
        if m4:
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts, 'timestamp_iso': ts_iso, 'type': 'failed_su',
                'detail': f"User '{m4.group('user')}' failed to su to '{m4.group('target')}' on {m4.group('tty')}",
                'ip': None, 'source_file': source_file, 'raw': line,
            })


        m5 = RE_MAX_AUTH_EXCEEDED.search(line)
        if m5:
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts, 'timestamp_iso': ts_iso, 'type': 'max_auth_attempts_exceeded',
                'detail': f"Maximum authentication attempts exceeded for '{m5.group('user')}' from {m5.group('ip')}",
                'ip': m5.group('ip'), 'source_file': source_file, 'raw': line,
            })


        m6 = RE_PRIV_ESCALATION.search(line)
        if m6:
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts,
                 'timestamp_iso': ts_iso,
                  'type': 'privilege_escalation',
                'detail': f"User '{m6.group('user')}' added to privileged group '{m6.group('group')}'",
                'ip': None, 
                'source_file': source_file, 
                'raw': line,
            })


        m = RE_ACCEPTED.search(line)
        if m:
            matched_something = True
            entry = {
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'user': m.group('user'),
                'ip': m.group('ip'),
                'port': m.group('port'),
                'method': m.group('method'),
                'source_file': source_file,
                'raw': line,
            }
            self.successful_logins.append(entry)
            if m.group('user') == 'root':
                self.suspicious_events.append({
                    'timestamp': ts, 'timestamp_iso': ts_iso, 'type': 'root_login_success',
                    'detail': f"Successful root login from {m.group('ip')}",
                    'ip': m.group('ip'), 'source_file': source_file, 'raw': line,
                })


        m = RE_SUDO.search(line)
        if m:
            matched_something = True
            command_text = m.group('command').strip()
            entry = {
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'user': m.group('user'),
                'run_as': m.group('asuser'),
                'tty': m.group('tty'),
                'pwd': m.group('pwd'),
                'command': command_text,
                'source_file': source_file,
                'raw': line,
            }
            self.sudo_commands.append(entry)

            for pattern, reason in RISKY_SUDO_PATTERNS:
                if pattern.search(command_text):
                    self.suspicious_events.append({
                        'timestamp': ts,
                        'timestamp_iso': ts_iso,
                        'type': 'risky_sudo_command',
                        'detail': f"{reason} -- command: {command_text} (run by {m.group('user')} as {m.group('asuser')})",
                        'ip': None, 
                        'source_file': source_file, 
                        'raw': line,
                    })
                    break  


        if RE_BREAKIN.search(line):
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts,
                'timestamp_iso': ts_iso,
                'type': 'possible_break_in',
                'detail': line.strip(),
                'ip': None,
                'source_file': source_file, 
                'raw': line,
            })


        m = RE_INVALID_USER.search(line)
        if m:
            matched_something = True
            ip = m.group('ip')
            if not self.is_allowlisted(ip):
                self.suspicious_events.append({
                    'timestamp': ts, 
                    'timestamp_iso': ts_iso, 
                    'type': 'invalid_user_probe',
                    'detail': f"Login attempt for non-existent user '{m.group('user')}' from {ip}",
                    'ip': ip, 
                    'source_file': source_file,
                    'raw': line,
                })


        m = RE_NEW_USER.search(line)
        if m:
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts,
                'timestamp_iso': ts_iso, 
                'type': 'new_user_created',
                'detail': f"New user account created: {m.group('user')}",
                'ip': None, 
                'source_file': source_file, 
                'raw': line,
            })
        m = RE_NEW_GROUP.search(line)
        if m:
            matched_something = True
            self.suspicious_events.append({
                'timestamp': ts,
                'timestamp_iso': ts_iso, 
                'type': 'new_group_created',
                'detail': f"New group created: {m.group('group')}",
                'ip': None, 
                'source_file': source_file, 
                'raw': line,
            })

        if not matched_something:
            if len(self.unparsed_sample) < 20:
                self.unparsed_sample.append(line)
        else:
            self.parsed_lines += 1


    def _brute_force_events(self):
        by_ip = defaultdict(list)
        for e in self.failed_logins:
            ip = e.get('ip')
            if ip and not self.is_allowlisted(ip):
                by_ip[ip].append(e)

        events = []
        window = timedelta(seconds=self.brute_force_window_seconds)
        for ip, entries in by_ip.items():
            dts = sorted(d for d in (to_datetime(e['timestamp'], self.assume_year) for e in entries) if d)

            flagged = False
            if len(dts) >= self.brute_force_threshold:
                left = 0
                for right in range(len(dts)):
                    while dts[right] - dts[left] > window:
                        left += 1
                    span = right - left + 1
                    if span >= self.brute_force_threshold:
                        events.append({
                            'timestamp': dts[left].strftime('%Y-%m-%d %H:%M:%S'),
                            'timestamp_iso': dts[left].isoformat(),
                            'type': 'brute_force_rapid',
                            'detail': (f"{span} failed login attempts from {ip} within "
                                       f"{self.brute_force_window_seconds}s (rapid brute-force pattern)"),
                            'ip': ip, 'source_file': None, 'raw': None,
                        })
                        flagged = True
                        break

            if not flagged and len(entries) >= self.brute_force_threshold:
                events.append({
                    'timestamp': None, 'timestamp_iso': None,
                    'type': 'brute_force_suspected',
                    'detail': (f"{len(entries)} failed login attempts from {ip} "
                               f"(threshold: {self.brute_force_threshold}; timestamps unavailable "
                               f"or spread out, so this is a volume-only signal)"),
                    'ip': ip, 'source_file': None, 'raw': None,
                })
        return events


    def _correlate_incidents(self):

        import bisect

        probe_dts_by_ip = defaultdict(list)
        for e in self.failed_logins:
            ip = e.get('ip')
            if not ip or not e.get('invalid_user'):
                continue
            dt = to_datetime(e.get('timestamp'), self.assume_year)
            if dt:
                probe_dts_by_ip[ip].append(dt)
        for ip in probe_dts_by_ip:
            probe_dts_by_ip[ip].sort()

        sudo_by_user = defaultdict(list)
        for s in self.sudo_commands:
            sudo_by_user[s['user']].append(s['command'])

        window = timedelta(seconds=self.correlation_window_seconds)
        events = []
        for succ in self.successful_logins:
            ip = succ.get('ip')
            user = succ.get('user')
            if not ip or self.is_allowlisted(ip):
                continue
            succ_dt = to_datetime(succ.get('timestamp'), self.assume_year)
            if not succ_dt:
                continue

            dts = probe_dts_by_ip.get(ip, [])
            lo = bisect.bisect_left(dts, succ_dt - window)
            hi = bisect.bisect_left(dts, succ_dt)
            prior_failures = hi - lo
            if prior_failures < CORRELATION_MIN_FAILURES:
                continue

            detail = (f"Successful login for '{user}' from {ip} followed {prior_failures} "
                      f"invalid-username probe(s) from the same source IP within the preceding "
                      f"{self.correlation_window_seconds}s")
            commands = sudo_by_user.get(user)
            if commands:
                sample = '; '.join(commands[:3])
                detail += f", then ran {len(commands)} sudo command(s) (e.g. {sample})"
            events.append({
                'timestamp': succ.get('timestamp'),
                'timestamp_iso': succ.get('timestamp_iso'),
                'type': 'compromised_account_suspected',
                'detail': detail,
                'ip': ip,
                'source_file': succ.get('source_file'),
                'raw': succ.get('raw'),
            })
        return events

    def _finalize_suspicious_events(self):
        all_events = list(self.suspicious_events) + self._brute_force_events() + self._correlate_incidents()
        for e in all_events:
            e['severity'] = SUSPICIOUS_SEVERITY.get(e['type'], 'low')
        all_events.sort(key=lambda e: (-SEVERITY_RANK.get(e['severity'], 0), e.get('timestamp') or ''))
        return all_events

    def top_source_ips(self, n=15):
        ip_counts = Counter(e['ip'] for e in self.failed_logins if e.get('ip'))
        return ip_counts.most_common(n)

    def failed_logins_by_hour(self):
        buckets = [0] * 24
        any_ts = False
        for e in self.failed_logins:
            dt = to_datetime(e.get('timestamp'), self.assume_year)
            if dt:
                any_ts = True
                buckets[dt.hour] += 1
        return buckets if any_ts else None

    def build_summary(self):
        all_suspicious = self._finalize_suspicious_events()
        hourly = self.failed_logins_by_hour()

        summary = {
            'generated_at': datetime.now().isoformat(timespec='seconds'),
            'source_files': self.source_files,
            'settings': {
                'brute_force_threshold': self.brute_force_threshold,
                'brute_force_window_seconds': self.brute_force_window_seconds,
                'assumed_year': self.assume_year,
                'assumed_year_was_used': self._used_assumed_year,
                'allowlisted_ips': [str(n) for n in self._allowlist_nets],
            },
            'totals': {
                'total_log_entries': self.total_lines,
                'parsed_entries': self.parsed_lines,
                'unparsed_entries': self.total_lines - self.parsed_lines,
                'failed_login_count': len(self.failed_logins),
                'successful_login_count': len(self.successful_logins),
                'sudo_command_count': len(self.sudo_commands),
                'suspicious_event_count': len(all_suspicious),
            },
            'failed_logins': self.failed_logins,
            'successful_logins': self.successful_logins,
            'sudo_commands': self.sudo_commands,
            'suspicious_events': all_suspicious,
            'top_source_ips_failed_logins': [
                {'ip': ip, 'failed_attempts': count} for ip, count in self.top_source_ips()
            ],
            'failed_logins_by_hour': hourly,
            'unparsed_sample': self.unparsed_sample,
        }
        return summary


# HTML report rendering


_TABLE_COUNTER = {'n': 0}


def _next_table_id(prefix):
    _TABLE_COUNTER['n'] += 1
    return f"{prefix}-{_TABLE_COUNTER['n']}"


def _data_table_block(table_id, headers, rows, empty_msg, page_size=25, row_classes=None):
    if not rows:
        return f'<p class="empty">{escape(empty_msg)}</p>', None

    out = [f'<div class="table-toolbar">',
           f'<input type="text" class="table-search" placeholder="Filter rows..." '
           f'oninput="filterTable(\'{table_id}\', this.value)">',
           f'<span class="table-count">{len(rows)} row(s)</span>',
           f'</div>']
    out.append(f'<div class="table-scroll"><table id="{table_id}"><thead><tr>')
    for h in headers:
        out.append(f'<th>{escape(str(h))}</th>')
    out.append('</tr></thead><tbody>')
    for i, row in enumerate(rows):
        cls = f' class="{row_classes[i]}"' if row_classes else ''
        out.append(f'<tr{cls}>')
        for cell in row:
            out.append(f'<td>{escape(str(cell)) if cell is not None else ""}</td>')
        out.append('</tr>')
    out.append('</tbody></table></div>')
    out.append(f'<div class="table-pagination">'
               f'<button onclick="pageTable(\'{table_id}\', -1)">&larr; Prev</button>'
               f'<span id="{table_id}-page-label" class="page-label"></span>'
               f'<button onclick="pageTable(\'{table_id}\', 1)">Next &rarr;</button>'
               f'</div>')
    init_js = f"initTable('{table_id}', {page_size});"
    return ''.join(out), init_js


def _table(headers, rows, empty_msg="No entries found."):
    if not rows:
        return f'<p class="empty">{escape(empty_msg)}</p>'
    out = ['<table>', '<thead><tr>']
    for h in headers:
        out.append(f'<th>{escape(str(h))}</th>')
    out.append('</tr></thead><tbody>')
    for row in rows:
        out.append('<tr>')
        for cell in row:
            out.append(f'<td>{escape(str(cell)) if cell is not None else ""}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')
    return ''.join(out)


def _build_hourly_chart_svg(hourly_counts):
    if not hourly_counts or not any(hourly_counts):
        return ('<p class="empty">No parseable timestamps were found, so an hourly '
                'timeline could not be built.</p>')
    width, height = 720, 180
    pad_left, pad_bottom = 30, 24
    chart_w = width - pad_left - 10
    chart_h = height - pad_bottom - 10
    max_val = max(hourly_counts) or 1
    bar_w = chart_w / 24
    bars = []
    for hour, count in enumerate(hourly_counts):
        bar_h = (count / max_val) * chart_h
        x = pad_left + hour * bar_w
        y = 10 + (chart_h - bar_h)
        color = 'var(--danger)' if count == max_val and count > 0 else 'var(--accent)'
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w * 0.7:.1f}" height="{bar_h:.1f}" '
            f'fill="{color}" rx="2"><title>{hour:02d}:00 - {count} failed attempt(s)</title></rect>'
        )
        if hour % 3 == 0:
            bars.append(f'<text x="{x:.1f}" y="{height - 6}" class="chart-label">{hour:02d}</text>')
    axis = (f'<line x1="{pad_left}" y1="10" x2="{pad_left}" y2="{10 + chart_h}" class="chart-axis"/>'
            f'<line x1="{pad_left}" y1="{10 + chart_h}" x2="{width - 10}" y2="{10 + chart_h}" class="chart-axis"/>')
    return (f'<svg viewBox="0 0 {width} {height}" class="chart-svg">{axis}{"".join(bars)}</svg>'
            f'<p class="chart-caption">Failed login attempts by hour of day (all days combined). '
            f'Hover a bar for the exact count.</p>')


SEVERITY_ORDER_FOR_DISPLAY = ['critical', 'high', 'medium', 'low']


def generate_html_report(summary, output_path):
    _TABLE_COUNTER['n'] = 0
    t = summary['totals']
    settings = summary.get('settings', {})
    init_calls = []

    # Total Log Entries Tab
    total_rows = [
        ('Total log entries', t['total_log_entries']),
        ('Parsed / classified entries', t['parsed_entries']),
        ('Unparsed entries', t['unparsed_entries']),
        ('Failed login attempts', t['failed_login_count']),
        ('Successful logins', t['successful_login_count']),
        ('Sudo commands executed', t['sudo_command_count']),
        ('Suspicious events flagged', t['suspicious_event_count']),
        ('Source file(s)', ', '.join(summary['source_files'])),
        ('Brute-force threshold / window',
         f"{settings.get('brute_force_threshold')} attempts within {settings.get('brute_force_window_seconds')}s"),
        ('Allowlisted IPs/ranges', ', '.join(settings.get('allowlisted_ips') or []) or 'none'),
    ]
    if settings.get('assumed_year_was_used'):
        total_rows.append(('Year assumption',
                            f"Some timestamps had no year; assumed {settings.get('assumed_year')} "
                            f"(pass --year to override)"))
    total_html = _table(['Metric', 'Value'], total_rows)
    chart_html = _build_hourly_chart_svg(summary.get('failed_logins_by_hour'))

    # Failed Logins Tab
    failed_rows = [
        (e.get('timestamp') or '-', e.get('user'), e.get('ip'), e.get('port') or '-',
         'yes' if e.get('invalid_user') else 'no')
        for e in summary['failed_logins']
    ]
    failed_table_id = _next_table_id('failed')
    failed_html, js = _data_table_block(failed_table_id, ['Timestamp', 'User', 'Source IP', 'Port', 'Invalid User'],
                                        failed_rows, "No failed login attempts found.")
    if js:
        init_calls.append(js)

    # Successful Logins Tab
    success_rows = [
        (e.get('timestamp') or '-', e.get('user'), e.get('ip'), e.get('port') or '-', e.get('method') or '-')
        for e in summary['successful_logins']
    ]
    success_table_id = _next_table_id('success')
    success_html, js = _data_table_block(success_table_id, ['Timestamp', 'User', 'Source IP', 'Port', 'Method'],
                                          success_rows, "No successful logins found.")
    if js:
        init_calls.append(js)

    # Sudo Commands Tab
    sudo_rows = [
        (e.get('timestamp') or '-', e.get('user'), e.get('run_as'), e.get('pwd'), e.get('command'))
        for e in summary['sudo_commands']
    ]
    sudo_table_id = _next_table_id('sudo')
    sudo_html, js = _data_table_block(sudo_table_id, ['Timestamp', 'User', 'Run As', 'Working Dir', 'Command'],
                                       sudo_rows, "No sudo command executions found.")
    if js:
        init_calls.append(js)

    # Suspicipus EVents Tab (Severitu colored)
    susp_rows = [
        (e.get('severity', 'low').upper(), e.get('timestamp') or '-', e.get('type'), e.get('ip') or '-', e.get('detail'))
        for e in summary['suspicious_events']
    ]
    susp_row_classes = [f"sev-{e.get('severity', 'low')}" for e in summary['suspicious_events']]
    susp_table_id = _next_table_id('suspicious')
    susp_html, js = _data_table_block(susp_table_id, ['Severity', 'Timestamp', 'Type', 'IP', 'Detail'],
                                       susp_rows, "No suspicious events detected.",
                                       row_classes=susp_row_classes)
    if js:
        init_calls.append(js)

    severity_counts = Counter(e.get('severity', 'low') for e in summary['suspicious_events'])
    severity_summary_html = ''.join(
        f'<span class="sev-pill sev-{sev}">{sev.upper()}: {severity_counts.get(sev, 0)}</span>'
        for sev in SEVERITY_ORDER_FOR_DISPLAY if severity_counts.get(sev)
    )

    # Top Source IPs for Failed Logins
    top_ip_rows = [(row['ip'], row['failed_attempts']) for row in summary['top_source_ips_failed_logins']]
    top_ip_html = _table(['Source IP', 'Failed Attempts'], top_ip_rows, "No failed login source IPs found.")

    tabs = [
        ('total', 'Total Log Entries', total_html + '<h3 class="chart-title">Failed Logins Timeline</h3>' + chart_html),
        ('failed', f"Failed Logins ({t['failed_login_count']})", failed_html),
        ('success', f"Successful Logins ({t['successful_login_count']})", success_html),
        ('sudo', f"Sudo Commands ({t['sudo_command_count']})", sudo_html),
        ('suspicious', f"Suspicious Events ({t['suspicious_event_count']})",
         severity_summary_html + susp_html),
        ('topips', 'Top Source IPs (Failed)', top_ip_html),
    ]

    nav_buttons = '\n'.join(
        f'<button class="tab-btn{" active" if i == 0 else ""}" onclick="showTab(\'{key}\')" id="btn-{key}">{escape(label)}</button>'
        for i, (key, label, _) in enumerate(tabs)
    )
    tab_panels = '\n'.join(
        f'<div class="tab-panel{" active" if i == 0 else ""}" id="tab-{key}">{content}</div>'
        for i, (key, _, content) in enumerate(tabs)
    )

    init_calls_js = '\n'.join(init_calls)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux Log Analysis Report</title>
<style>
  :root {{
    --bg: #0f1419; --panel: #161d27; --border: #24303d; --text: #d8e1e8;
    --muted: #7f92a3; --accent: #4fb0ff; --danger: #ff6b6b; --warn: #ffb74f; --ok: #4fd18b;
    --critical: #ff3b6b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); font-family: 'Segoe UI', Roboto, Arial, sans-serif;
    margin: 0; padding: 0;
  }}
  header {{
    padding: 24px 32px; border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, #131a24, #0f1419);
  }}
  header h1 {{ margin: 0 0 6px 0; font-size: 22px; }}
  header p {{ margin: 0; color: var(--muted); font-size: 13px; }}
  .container {{ padding: 24px 32px; }}
  .tab-nav {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }}
  .tab-btn {{
    background: var(--panel); color: var(--muted); border: 1px solid var(--border);
    padding: 10px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    transition: all 0.15s ease;
  }}
  .tab-btn:hover {{ color: var(--text); border-color: var(--accent); }}
  .tab-btn.active {{ background: var(--accent); color: #04121f; border-color: var(--accent); }}
  .tab-panel {{ display: none; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
  .tab-panel.active {{ display: block; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--accent); text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em;
       position: sticky; top: 0; background: var(--panel); }}
  tr:hover td {{ background: rgba(79, 176, 255, 0.05); }}
  .empty {{ color: var(--muted); font-style: italic; }}
  .summary-badges {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 14px; }}
  .badge {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 16px; min-width: 140px;
  }}
  .badge .num {{ font-size: 22px; font-weight: 700; }}
  .badge .label {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
  .badge.danger .num {{ color: var(--danger); }}
  .badge.ok .num {{ color: var(--ok); }}
  .badge.warn .num {{ color: var(--warn); }}
  .badge.accent .num {{ color: var(--accent); }}
  .table-toolbar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
  .table-search {{
    background: #0d131b; color: var(--text); border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 10px; font-size: 12px; width: 240px;
  }}
  .table-count {{ color: var(--muted); font-size: 12px; }}
  .table-scroll {{ max-height: 480px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; }}
  .table-pagination {{ display: flex; justify-content: center; align-items: center; gap: 14px; margin-top: 10px; }}
  .table-pagination button {{
    background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 12px; font-size: 12px; cursor: pointer;
  }}
  .table-pagination button:hover {{ border-color: var(--accent); }}
  .page-label {{ color: var(--muted); font-size: 12px; }}
  .chart-title {{ font-size: 13px; color: var(--accent); text-transform: uppercase; letter-spacing: 0.04em;
                  margin: 20px 0 8px 0; }}
  .chart-svg {{ width: 100%; height: auto; }}
  .chart-axis {{ stroke: var(--border); stroke-width: 1; }}
  .chart-label {{ fill: var(--muted); font-size: 9px; }}
  .chart-caption {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
  .sev-pill {{
    display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700;
    margin-right: 8px; margin-bottom: 12px;
  }}
  .sev-critical {{ background: rgba(255, 59, 107, 0.18); color: var(--critical); }}
  .sev-high {{ background: rgba(255, 107, 107, 0.18); color: var(--danger); }}
  .sev-medium {{ background: rgba(255, 183, 79, 0.18); color: var(--warn); }}
  .sev-low {{ background: rgba(127, 146, 163, 0.18); color: var(--muted); }}
  tr.sev-critical td:first-child {{ border-left: 3px solid var(--critical); }}
  tr.sev-high td:first-child {{ border-left: 3px solid var(--danger); }}
  tr.sev-medium td:first-child {{ border-left: 3px solid var(--warn); }}
  tr.sev-low td:first-child {{ border-left: 3px solid var(--muted); }}
</style>
</head>
<body>
<header>
  <h1>Linux Log Analysis Report</h1>
  <p>Generated {escape(summary['generated_at'])} &middot; Source: {escape(', '.join(summary['source_files']))}</p>
  <div class="summary-badges">
    <div class="badge accent"><div class="num">{t['total_log_entries']}</div><div class="label">Total Entries</div></div>
    <div class="badge danger"><div class="num">{t['failed_login_count']}</div><div class="label">Failed Logins</div></div>
    <div class="badge ok"><div class="num">{t['successful_login_count']}</div><div class="label">Successful Logins</div></div>
    <div class="badge warn"><div class="num">{t['sudo_command_count']}</div><div class="label">Sudo Commands</div></div>
    <div class="badge danger"><div class="num">{t['suspicious_event_count']}</div><div class="label">Suspicious Events</div></div>
  </div>
</header>
<div class="container">
  <div class="tab-nav">
    {nav_buttons}
  </div>
  {tab_panels}
</div>
<script>
function showTab(key) {{
  document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  document.getElementById('tab-' + key).classList.add('active');
  document.getElementById('btn-' + key).classList.add('active');
}}

var tableState = {{}};

function initTable(id, pageSize) {{
  var table = document.getElementById(id);
  if (!table) return;
  var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
  tableState[id] = {{ rows: rows, page: 0, pageSize: pageSize, filtered: rows }};
  renderTable(id);
}}

function renderTable(id) {{
  var st = tableState[id];
  if (!st) return;
  var totalPages = Math.max(1, Math.ceil(st.filtered.length / st.pageSize));
  if (st.page >= totalPages) st.page = totalPages - 1;
  if (st.page < 0) st.page = 0;
  st.rows.forEach(function(r) {{ r.style.display = 'none'; }});
  st.filtered.slice(st.page * st.pageSize, (st.page + 1) * st.pageSize).forEach(function(r) {{ r.style.display = ''; }});
  var label = document.getElementById(id + '-page-label');
  if (label) label.textContent = 'Page ' + (st.page + 1) + ' of ' + totalPages + ' (' + st.filtered.length + ' matching row(s))';
}}

function filterTable(id, query) {{
  var st = tableState[id];
  if (!st) return;
  query = query.trim().toLowerCase();
  st.filtered = query ? st.rows.filter(function(r) {{ return r.textContent.toLowerCase().indexOf(query) !== -1; }}) : st.rows;
  st.page = 0;
  renderTable(id);
}}

function pageTable(id, delta) {{
  var st = tableState[id];
  if (!st) return;
  st.page += delta;
  renderTable(id);
}}

{init_calls_js}
</script>
</body>
</html>
"""
    with open(output_path, 'w') as f:
        f.write(html)


# CLI

def main():
    parser = argparse.ArgumentParser(description="Linux log analysis tool (auth.log / secure / syslog, plain or .gz).")
    parser.add_argument('-i', '--input', nargs='+', required=True, help="Path(s) to log file(s) to analyze (.log, .txt, or .gz).")
    parser.add_argument('-o', '--outdir', default='.', help="Output directory for the report (default: current dir).")
    parser.add_argument('--html-name', default='log_report.html', help="Filename for the HTML report.")
    parser.add_argument('--json-name', default='log_findings.json', help="Filename for the JSON findings.")
    parser.add_argument('--brute-force-threshold', type=int, default=BRUTE_FORCE_THRESHOLD,
                         help=f"Failed attempts from one IP to flag as brute force (default: {BRUTE_FORCE_THRESHOLD}).")
    parser.add_argument('--brute-force-window', type=int, default=BRUTE_FORCE_WINDOW_SECONDS,
                         help=f"Rolling time window in seconds for rapid brute-force detection (default: {BRUTE_FORCE_WINDOW_SECONDS}).")
    parser.add_argument('--allowlist-ip', nargs='+', default=[],
                         help="IP(s) or CIDR range(s) to exclude from brute-force/invalid-user suspicious flagging (still counted in totals).")
    parser.add_argument('--correlation-window', type=int, default=CORRELATION_WINDOW_SECONDS,
                         help=f"Lookback window in seconds for flagging a success that follows a burst of failures "
                              f"from the same IP (default: {CORRELATION_WINDOW_SECONDS}).")
    parser.add_argument('--year', type=int, default=None,
                         help="Year to assume for syslog timestamps that omit one (default: current year).")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    analyzer = LinuxLogAnalyzer(
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window_seconds=args.brute_force_window,
        correlation_window_seconds=args.correlation_window,
        allowlist_ips=args.allowlist_ip,
        assume_year=args.year,
    )
    for path in args.input:
        if not os.path.isfile(path):
            print(f"[!] File not found, skipping: {path}", file=sys.stderr)
            continue
        print(f"[*] Analyzing {path} ...")
        analyzer.analyze_file(path)

    summary = analyzer.build_summary()

    html_path = os.path.join(args.outdir, args.html_name)
    json_path = os.path.join(args.outdir, args.json_name)

    generate_html_report(summary, html_path)
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)

    t = summary['totals']
    print("\n=== Analysis Summary ===")
    print(f"Total log entries:      {t['total_log_entries']}")
    print(f"Failed login attempts:  {t['failed_login_count']}")
    print(f"Successful logins:      {t['successful_login_count']}")
    print(f"Sudo commands:          {t['sudo_command_count']}")
    print(f"Suspicious events:      {t['suspicious_event_count']}")
    if summary['settings']['assumed_year_was_used']:
        print(f"\n[!] Note: some timestamps had no year; assumed {summary['settings']['assumed_year']} "
              f"(pass --year to override)")
    print(f"\nHTML report saved to:   {html_path}")
    print(f"JSON findings saved to: {json_path}")


if __name__ == '__main__':
    main()
