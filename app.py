#!/usr/bin/env python3
"""
Linux Log Analyzer - Web Dashboard
====================================
A local Flask web app front-end for log_analyzer.py. 

Requires:
    pip install -r requirements.txt
    (log_analyzer.py must be in the same directory)

Usage:
    python3 app.py                  -> http://127.0.0.1:5000 (Runs on port 5000 by default.)
    python3 app.py --port 6793      -> http://127.0.0.1:6793
    python3 app.py --debug          -> Flask debug mode (shows full tracebacks in-browser)
"""

import argparse
import json
import os
import sys
import tempfile
import traceback
import uuid

from flask import Flask, jsonify, render_template, request, send_file

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from log_analyzer import (
    LinuxLogAnalyzer,
    generate_html_report,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    CORRELATION_MIN_FAILURES,
    CORRELATION_WINDOW_SECONDS,
)

def check_required_files():
    problems = []
    template_path = os.path.join(BASE_DIR, 'templates', 'index.html')
    if not os.path.isfile(template_path):
        problems.append(
            f"Missing: {template_path}\n"
            f"  -> app.py expects a 'templates' folder in the SAME directory as itself,\n"
            f"     containing index.html. Right now that folder/file isn't there.\n"
            f"     Fix: mkdir -p \"{os.path.join(BASE_DIR, 'templates')}\" and put index.html "
            f"inside it."
        )
    log_analyzer_path = os.path.join(BASE_DIR, 'log_analyzer.py')
    if not os.path.isfile(log_analyzer_path):
        problems.append(
            f"Missing: {log_analyzer_path}\n"
            f"  -> app.py imports log_analyzer.py directly, so it must be in the SAME "
            f"directory as app.py."
        )
    if problems:
        print("\n" + "=" * 70, file=sys.stderr)
        print("STARTUP CHECK FAILED -- fix the following before running app.py:", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        for p in problems:
            print("\n" + p, file=sys.stderr)
        print("\n" + "=" * 70, file=sys.stderr)
        print(f"Expected layout (relative to app.py's own folder, {BASE_DIR}):", file=sys.stderr)
        print("  app.py", file=sys.stderr)
        print("  log_analyzer.py", file=sys.stderr)
        print("  templates/index.html", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)
        sys.exit(1)


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB upload ceiling

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = os.path.join(tempfile.gettempdir(), 'log_analyzer_web_uploads')
REPORT_ROOT = os.path.join(tempfile.gettempdir(), 'log_analyzer_web_reports')
os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(REPORT_ROOT, exist_ok=True)

ALLOWED_EXTENSIONS = ('.log', '.txt', '.gz')


@app.route('/')
def index():
    try:
        return render_template(
            'index.html',
            default_threshold=BRUTE_FORCE_THRESHOLD,
            default_window=BRUTE_FORCE_WINDOW_SECONDS,
            default_corr_min=CORRELATION_MIN_FAILURES,
            default_corr_window=CORRELATION_WINDOW_SECONDS,
        )
    except Exception:
        tb = traceback.format_exc()
        print(tb, file=sys.stderr)
        return f"<pre>Failed to render the page. Traceback:\n\n{tb}</pre>", 500


@app.errorhandler(500)
def handle_500(e):
    tb = traceback.format_exc()
    print(tb, file=sys.stderr)
    return jsonify({'error': 'Unhandled server error.', 'traceback': tb}), 500


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        files = [f for f in request.files.getlist('logfiles') if f and f.filename]
        if not files:
            return jsonify({'error': 'No files were uploaded.'}), 400

        rejected = [f.filename for f in files if not f.filename.lower().endswith(ALLOWED_EXTENSIONS)]
        files = [f for f in files if f.filename.lower().endswith(ALLOWED_EXTENSIONS)]
        if not files:
            return jsonify({'error': f'None of the uploaded files had a supported extension {ALLOWED_EXTENSIONS}.'}), 400

        def to_int(name, default):
            raw = request.form.get(name, '').strip()
            try:
                return int(raw) if raw else default
            except ValueError:
                return default

        threshold = to_int('threshold', BRUTE_FORCE_THRESHOLD)
        window = to_int('window', BRUTE_FORCE_WINDOW_SECONDS)
        corr_window = to_int('corr_window', CORRELATION_WINDOW_SECONDS)
        year_raw = request.form.get('year', '').strip()
        year = int(year_raw) if year_raw.isdigit() else None

        allowlist_raw = request.form.get('allowlist', '')
        allowlist = [tok.strip() for tok in allowlist_raw.replace('\n', ',').split(',') if tok.strip()]

        run_id = uuid.uuid4().hex[:12]
        run_upload_dir = os.path.join(UPLOAD_ROOT, run_id)
        os.makedirs(run_upload_dir, exist_ok=True)

        saved_paths = []
        for f in files:
            safe_name = os.path.basename(f.filename).replace(os.sep, '_')
            dest = os.path.join(run_upload_dir, safe_name)
            f.save(dest)
            saved_paths.append(dest)

        analyzer = LinuxLogAnalyzer(
            brute_force_threshold=threshold,
            brute_force_window_seconds=window,
            correlation_window_seconds=corr_window,
            allowlist_ips=allowlist,
            assume_year=year,
        )
        file_errors = []
        for path in saved_paths:
            try:
                analyzer.analyze_file(path)
            except Exception as exc:  # keep going even if one file is unreadable
                file_errors.append(f"{os.path.basename(path)}: {exc}")

        summary = analyzer.build_summary()

        run_report_dir = os.path.join(REPORT_ROOT, run_id)
        os.makedirs(run_report_dir, exist_ok=True)
        html_path = os.path.join(run_report_dir, 'log_report.html')
        json_path = os.path.join(run_report_dir, 'log_findings.json')
        generate_html_report(summary, html_path)
        with open(json_path, 'w') as jf:
            json.dump(summary, jf, indent=2)

        summary['run_id'] = run_id
        summary['rejected_files'] = rejected
        summary['file_errors'] = file_errors
        return jsonify(summary)

    except Exception:
        tb = traceback.format_exc()
        print(tb, file=sys.stderr)  # always visible in the terminal running app.py
        return jsonify({
            'error': 'Internal error while analyzing. Full traceback below (also printed in the '
                     'terminal running app.py) -- please share this if you need help debugging it.',
            'traceback': tb,
        }), 500


def _send_file_compat(path, download_name):
    """send_file's filename kwarg was renamed between Flask versions
    (attachment_filename -> download_name in Flask 2.0+); support both
    so this doesn't break on an older Flask install."""
    try:
        return send_file(path, as_attachment=True, download_name=download_name)
    except TypeError:
        return send_file(path, as_attachment=True, attachment_filename=download_name)


@app.route('/download/<run_id>/<kind>')
def download(run_id, kind):
    run_report_dir = os.path.join(REPORT_ROOT, run_id)
    if kind == 'html':
        path = os.path.join(run_report_dir, 'log_report.html')
        name = 'log_report.html'
    elif kind == 'json':
        path = os.path.join(run_report_dir, 'log_findings.json')
        name = 'log_findings.json'
    else:
        return 'Unknown download kind', 404
    if not os.path.isfile(path):
        return 'Report not found -- run an analysis first.', 404
    return _send_file_compat(path, name)


def parse_args():
    parser = argparse.ArgumentParser(description="Linux Log Analyzer web dashboard.")
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 5000)),
                         help="Port to run on (default: 5000, or $PORT if set).")
    parser.add_argument('--host', default='127.0.0.1',
                         help="Host to bind to (default: 127.0.0.1, local machine only).")
    parser.add_argument('--debug', action='store_true',
                         help="Enable Flask debug mode (full in-browser tracebacks + auto-reload).")
    return parser.parse_args()


if __name__ == '__main__':
    check_required_files()
    args = parse_args()
    print("Linux Log Analyzer web dashboard starting...")
    print(f"Open http://{args.host}:{args.port} in your browser.")
    app.run(host=args.host, port=args.port, debug=args.debug)
