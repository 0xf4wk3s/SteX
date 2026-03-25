import os
import re
import hashlib
import shutil
import json
import tempfile
import threading
import time
from dataclasses import asdict
from collections import Counter, defaultdict
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, jsonify, Response
)

from config import Config
from models import ParseResult
from extractors.archive import ArchiveExtractor
from parsers.detector import StealerDetector, get_parser
from highlights import extract_highlights, CATEGORIES
import database as db

app = Flask(__name__)
app.config.from_object(Config)
Config.init()
db.init_db()

_cache_lock = threading.RLock()
parse_cache: dict[str, dict] = {}
_watcher_known: set[str] = set()

_jobs_lock = threading.Lock()
_jobs: dict[str, dict] = {}


def _load_cache_from_db():
    loaded = db.load_all()
    with _cache_lock:
        parse_cache.update(loaded)


_load_cache_from_db()


# ── Helpers ───────────────────────────────────────────────────────────

def _file_key(filepath: str) -> str:
    stat = os.stat(filepath)
    raw = f"{filepath}|{stat.st_size}|{stat.st_mtime}"
    return hashlib.md5(raw.encode()).hexdigest()


def is_victim_dir(directory: str) -> bool:
    if not os.path.isdir(directory):
        return False
    items = {f.lower() for f in os.listdir(directory)}
    stealer_indicators = {
        'passwords.txt', 'password.txt', 'cookies.txt', 'autofill.txt',
        'userinformation.txt', 'system info.txt', 'information.txt',
        'system.txt', 'system_info.txt', 'autofills.txt', 'systeminfo.txt'
    }
    return bool(items & stealer_indicators)


def find_victim_dirs(directory: str) -> list[str]:
    if is_victim_dir(directory):
        return [directory]

    victim_dirs = []
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return []

    for item in entries:
        full_path = os.path.join(directory, item)
        if os.path.isdir(full_path):
            if is_victim_dir(full_path):
                victim_dirs.append(full_path)
            else:
                victim_dirs.extend(find_victim_dirs(full_path))

    return victim_dirs


def parse_logs(directory: str, filename: str) -> ParseResult:
    result = ParseResult(filename=filename)
    victim_dirs = find_victim_dirs(directory)

    if not victim_dirs:
        result.errors.append("No stealer logs found in this archive.")
        return result

    for vdir in victim_dirs:
        try:
            stealer_type = StealerDetector.detect(vdir)
            parser = get_parser(stealer_type, vdir)
            victim = parser.parse()
            result.victims.append(victim)
            result.errors.extend(parser.errors)
        except Exception as e:
            result.errors.append(f"Error parsing {os.path.basename(vdir)}: {e}")

    if result.victims:
        types = [v.stealer_type for v in result.victims]
        result.stealer_type = Counter(types).most_common(1)[0][0]

    result.calculate_totals()
    return result


def _normalize_screenshot_paths(result: ParseResult, base_dir: str):
    for victim in result.victims:
        for ss in victim.screenshots:
            if os.path.isabs(ss.path):
                ss.path = os.path.relpath(ss.path, base_dir).replace('\\', '/')


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1048576:
        return f"{size / 1024:.1f} KB"
    elif size < 1073741824:
        return f"{size / 1048576:.1f} MB"
    return f"{size / 1073741824:.1f} GB"


# ── Job / Background Processing ──────────────────────────────────────

def _get_job(filename: str) -> dict | None:
    with _jobs_lock:
        return _jobs.get(filename, {}).copy() if filename in _jobs else None


def _set_job(filename: str, **kwargs):
    with _jobs_lock:
        if filename not in _jobs:
            _jobs[filename] = {
                'status': 'queued',
                'phase': '',
                'extracted': 0,
                'total': 0,
                'error': '',
            }
        _jobs[filename].update(kwargs)


def _clear_job(filename: str):
    with _jobs_lock:
        _jobs.pop(filename, None)


def _is_processing(filename: str) -> bool:
    with _jobs_lock:
        job = _jobs.get(filename)
        return job is not None and job['status'] in ('queued', 'extracting', 'parsing')


def process_archive_sync(filename: str, password: str = None) -> dict:
    """Synchronous archive processing (used by background threads)."""
    fpath = os.path.join(Config.UPLOAD_FOLDER, filename)
    if not os.path.isfile(fpath):
        return {'error': 'File not found'}

    fkey = _file_key(fpath)
    with _cache_lock:
        if fkey in parse_cache:
            return parse_cache[fkey]

    extract_dir = tempfile.mkdtemp(prefix='stex_extract_')
    try:
        _set_job(filename, status='extracting', phase='Extracting files...')

        def on_progress(extracted, total):
            _set_job(filename, extracted=extracted, total=total)

        ArchiveExtractor.extract(fpath, extract_dir, password=password,
                                 progress_cb=on_progress)

        _set_job(filename, status='parsing', phase='Parsing logs...',
                 extracted=0, total=0)

        result = parse_logs(extract_dir, filename)
        _normalize_screenshot_paths(result, extract_dir)
        hl = extract_highlights(result, filename)

        entry = {
            'result': result,
            'extract_dir': extract_dir,
            'highlights': hl,
        }

        with _cache_lock:
            parse_cache[fkey] = entry

        db.save_archive(fkey, filename, extract_dir, result, hl)

        _set_job(filename, status='done', phase='Complete')
        return entry

    except Exception as e:
        shutil.rmtree(extract_dir, ignore_errors=True)
        _set_job(filename, status='error', phase='Failed', error=str(e))
        return {'error': str(e)}


def process_archive_bg(filename: str, password: str = None):
    """Start archive processing in a background thread."""
    if _is_processing(filename):
        return

    _set_job(filename, status='queued', phase='Queued...',
             extracted=0, total=0, error='')

    def _worker():
        try:
            process_archive_sync(filename, password=password)
        except Exception as e:
            _set_job(filename, status='error', phase='Failed', error=str(e))

    t = threading.Thread(target=_worker, daemon=True, name=f'parse-{filename}')
    t.start()


# ── Scan Uploads ─────────────────────────────────────────────────────

def scan_uploads() -> list[dict]:
    archives = []
    upload_dir = Config.UPLOAD_FOLDER

    if not os.path.isdir(upload_dir):
        return archives

    for fname in sorted(os.listdir(upload_dir)):
        fpath = os.path.join(upload_dir, fname)
        if not os.path.isfile(fpath):
            continue
        if not ArchiveExtractor.is_supported(fname):
            continue

        try:
            size = os.path.getsize(fpath)
        except OSError:
            size = 0

        fkey = _file_key(fpath)

        with _cache_lock:
            cached = parse_cache.get(fkey)

        job = _get_job(fname)

        if cached:
            hl = cached.get('highlights', {})
            archives.append({
                'filename': fname,
                'size': size,
                'key': fkey,
                'stealer_type': cached['result'].stealer_type,
                'victims': len(cached['result'].victims),
                'passwords': cached['result'].total_passwords,
                'cookies': cached['result'].total_cookies,
                'cards': cached['result'].total_cards,
                'wallets': cached['result'].total_wallets,
                'highlights': hl.get('total', 0) if isinstance(hl, dict) else 0,
                'status': 'parsed',
                'error': None,
            })
        elif job and job['status'] in ('queued', 'extracting', 'parsing'):
            archives.append({
                'filename': fname,
                'size': size,
                'key': fkey,
                'stealer_type': '—',
                'victims': 0,
                'passwords': 0,
                'cookies': 0,
                'cards': 0,
                'wallets': 0,
                'highlights': 0,
                'status': 'processing',
                'error': None,
                'phase': job.get('phase', ''),
                'extracted': job.get('extracted', 0),
                'total': job.get('total', 0),
            })
        elif job and job['status'] == 'error':
            archives.append({
                'filename': fname,
                'size': size,
                'key': fkey,
                'stealer_type': '—',
                'victims': 0,
                'passwords': 0,
                'cookies': 0,
                'cards': 0,
                'wallets': 0,
                'highlights': 0,
                'status': 'error',
                'error': job.get('error', 'Unknown error'),
            })
        else:
            try:
                encrypted = ArchiveExtractor.is_encrypted(fpath)
            except Exception:
                encrypted = False

            archives.append({
                'filename': fname,
                'size': size,
                'key': fkey,
                'stealer_type': '—',
                'victims': 0,
                'passwords': 0,
                'cookies': 0,
                'cards': 0,
                'wallets': 0,
                'highlights': 0,
                'status': 'locked' if encrypted else 'pending',
                'error': None,
            })

    return archives


# ── Global Search ─────────────────────────────────────────────────────

def global_search(query: str, max_results: int = 500) -> list[dict]:
    if not query or len(query) < 2:
        return []

    q = query.lower()
    results = []

    with _cache_lock:
        cache_snapshot = dict(parse_cache)

    for fkey, cached in cache_snapshot.items():
        result = cached['result']
        archive = result.filename

        for victim in result.victims:
            for pw in victim.passwords:
                if q in (pw.url or '').lower() or q in (pw.username or '').lower() or q in (pw.password or '').lower():
                    results.append({
                        'type': 'password',
                        'archive': archive,
                        'victim': victim.folder_name,
                        'url': pw.url,
                        'username': pw.username,
                        'password': pw.password,
                        'application': pw.application,
                    })

            for c in victim.cookies:
                if q in (c.host or '').lower() or q in (c.name or '').lower() or q in (c.value or '').lower():
                    results.append({
                        'type': 'cookie',
                        'archive': archive,
                        'victim': victim.folder_name,
                        'host': c.host,
                        'name': c.name,
                        'value': c.value,
                    })

            if victim.system_info:
                si = victim.system_info
                si_text = f"{si.ip} {si.country} {si.city} {si.hwid} {si.os} {si.machine_name} {si.username}".lower()
                if q in si_text:
                    results.append({
                        'type': 'system',
                        'archive': archive,
                        'victim': victim.folder_name,
                        'ip': si.ip,
                        'country': si.country,
                        'os': si.os,
                        'machine_name': si.machine_name,
                        'username': si.username,
                    })

            if len(results) >= max_results:
                return results

    return results


# ── Duplicate Detection ───────────────────────────────────────────────

def find_duplicates() -> dict:
    cred_index: dict[str, list[dict]] = defaultdict(list)

    with _cache_lock:
        cache_snapshot = dict(parse_cache)

    for fkey, cached in cache_snapshot.items():
        result = cached['result']
        archive = result.filename

        for victim in result.victims:
            for pw in victim.passwords:
                url = (pw.url or '').strip().lower()
                user = (pw.username or '').strip().lower()
                passw = (pw.password or '').strip()
                if not user or not passw:
                    continue

                cred_key = f"{url}||{user}||{passw}"
                cred_index[cred_key].append({
                    'archive': archive,
                    'victim': victim.folder_name,
                    'url': pw.url,
                    'username': pw.username,
                    'password': pw.password,
                    'application': pw.application,
                })

    duplicates = []
    for cred_key, entries in cred_index.items():
        archives_involved = {e['archive'] for e in entries}
        if len(archives_involved) >= 2:
            duplicates.append({
                'url': entries[0]['url'],
                'username': entries[0]['username'],
                'password': entries[0]['password'],
                'count': len(entries),
                'archives': sorted(archives_involved),
                'entries': entries,
            })

    duplicates.sort(key=lambda d: d['count'], reverse=True)

    total_creds = sum(
        sum(len(v.passwords) for v in c['result'].victims)
        for c in cache_snapshot.values()
    )

    return {
        'duplicates': duplicates[:500],
        'total_duplicates': len(duplicates),
        'total_credentials': total_creds,
        'archives_count': len(cache_snapshot),
    }


# ── File Watcher ──────────────────────────────────────────────────────

def _watcher_loop():
    while True:
        time.sleep(5)
        try:
            upload_dir = Config.UPLOAD_FOLDER
            if not os.path.isdir(upload_dir):
                continue

            current = set()
            for fname in os.listdir(upload_dir):
                fpath = os.path.join(upload_dir, fname)
                if os.path.isfile(fpath) and ArchiveExtractor.is_supported(fname):
                    current.add(fname)

            new_files = current - _watcher_known
            for fname in new_files:
                fpath = os.path.join(upload_dir, fname)
                try:
                    fkey = _file_key(fpath)
                    with _cache_lock:
                        already = fkey in parse_cache
                    if already or _is_processing(fname):
                        continue
                    if ArchiveExtractor.is_encrypted(fpath):
                        continue
                    process_archive_bg(fname)
                except Exception:
                    pass

            _watcher_known.clear()
            _watcher_known.update(current)
        except Exception:
            pass


def start_watcher():
    upload_dir = Config.UPLOAD_FOLDER
    if os.path.isdir(upload_dir):
        for fname in os.listdir(upload_dir):
            fpath = os.path.join(upload_dir, fname)
            if os.path.isfile(fpath) and ArchiveExtractor.is_supported(fname):
                _watcher_known.add(fname)

    t = threading.Thread(target=_watcher_loop, daemon=True)
    t.start()


# ── Routes ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    archives = scan_uploads()
    return render_template('index.html', archives=archives, format_size=_format_size)


@app.route('/parse/<filename>', methods=['GET', 'POST'])
def parse_single(filename):
    password = None
    if request.method == 'POST':
        password = request.form.get('password', '').strip() or None

    fpath = os.path.join(Config.UPLOAD_FOLDER, filename)
    if not os.path.isfile(fpath):
        flash(f'Archive not found: {filename}', 'error')
        return redirect(url_for('index'))

    fkey = _file_key(fpath)
    with _cache_lock:
        if fkey in parse_cache:
            return redirect(url_for('dashboard', filename=filename))

    if _is_processing(filename):
        flash(f'{filename} is already being processed.', 'info')
        return redirect(url_for('index'))

    process_archive_bg(filename, password=password)
    flash(f'Started processing {filename} in background.', 'success')
    return redirect(url_for('index'))


@app.route('/parse-all')
def parse_all_route():
    upload_dir = Config.UPLOAD_FOLDER
    count = 0
    for fname in os.listdir(upload_dir):
        fpath = os.path.join(upload_dir, fname)
        if os.path.isfile(fpath) and ArchiveExtractor.is_supported(fname):
            fkey = _file_key(fpath)
            with _cache_lock:
                already = fkey in parse_cache
            if not already and not _is_processing(fname):
                if ArchiveExtractor.is_encrypted(fpath):
                    continue
                process_archive_bg(fname)
                count += 1
    flash(f'Started processing {count} archive(s) in background.', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard/<filename>')
def dashboard(filename):
    fpath = os.path.join(Config.UPLOAD_FOLDER, filename)
    if not os.path.isfile(fpath):
        flash('Archive not found.', 'error')
        return redirect(url_for('index'))

    fkey = _file_key(fpath)
    with _cache_lock:
        cached = parse_cache.get(fkey)

    if not cached:
        if _is_processing(filename):
            flash(f'{filename} is still being processed...', 'info')
            return redirect(url_for('index'))
        process_archive_bg(filename)
        flash(f'Started processing {filename} in background.', 'success')
        return redirect(url_for('index'))

    return render_template(
        'dashboard.html',
        result=cached['result'],
        session_id=fkey,
        filename=filename,
        highlights=cached.get('highlights', {}),
        highlight_categories=CATEGORIES,
    )


@app.route('/search')
def search_page():
    query = request.args.get('q', '').strip()
    results = global_search(query) if query else []

    pw_results = [r for r in results if r['type'] == 'password']
    cookie_results = [r for r in results if r['type'] == 'cookie']
    system_results = [r for r in results if r['type'] == 'system']

    with _cache_lock:
        pc = len(parse_cache)

    return render_template(
        'search.html',
        query=query,
        results=results,
        pw_results=pw_results,
        cookie_results=cookie_results,
        system_results=system_results,
        total=len(results),
        parsed_count=pc,
    )


@app.route('/duplicates')
def duplicates_page():
    dup_data = find_duplicates()
    return render_template('duplicates.html', **dup_data)


@app.route('/combo/<session_id>/<fmt>')
def export_combo(session_id, fmt):
    with _cache_lock:
        cached = parse_cache.get(session_id)
    if not cached:
        return "Not found", 404

    result = cached['result']
    lines = []

    for v in result.victims:
        for pw in v.passwords:
            user = pw.username or ''
            passw = pw.password or ''
            if not user and not passw:
                continue
            if fmt == 'user_pass':
                lines.append(f"{user}:{passw}")
            elif fmt == 'url_user_pass':
                lines.append(f"{pw.url or 'N/A'}|{user}|{passw}")
            elif fmt == 'email_pass':
                if '@' in user:
                    lines.append(f"{user}:{passw}")

    seen = set()
    unique = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)

    content = '\n'.join(unique)
    fname = f"stex_combo_{fmt}.txt"

    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={fname}'}
    )


@app.route('/combo-all/<fmt>')
def export_combo_all(fmt):
    with _cache_lock:
        cache_snapshot = dict(parse_cache)

    lines = []
    for fkey, cached in cache_snapshot.items():
        result = cached['result']
        for v in result.victims:
            for pw in v.passwords:
                user = pw.username or ''
                passw = pw.password or ''
                if not user and not passw:
                    continue
                if fmt == 'user_pass':
                    lines.append(f"{user}:{passw}")
                elif fmt == 'url_user_pass':
                    lines.append(f"{pw.url or 'N/A'}|{user}|{passw}")
                elif fmt == 'email_pass':
                    if '@' in user:
                        lines.append(f"{user}:{passw}")

    seen = set()
    unique = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)

    content = '\n'.join(unique)
    fname = f"stex_all_combo_{fmt}.txt"

    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={fname}'}
    )


@app.route('/screenshot/<session_id>/<path:filepath>')
def serve_screenshot(session_id, filepath):
    with _cache_lock:
        cached = parse_cache.get(session_id)
    if not cached:
        return "Not found", 404

    base_dir = cached['extract_dir']
    if not base_dir or not os.path.isdir(base_dir):
        return "Screenshots unavailable (extracted files cleaned up)", 410

    safe_path = os.path.normpath(os.path.join(base_dir, filepath))
    if not safe_path.startswith(os.path.normpath(base_dir)):
        return "Forbidden", 403

    if os.path.isfile(safe_path):
        return send_file(safe_path)
    return "Not found", 404


@app.route('/export/<session_id>/<data_type>/<fmt>')
def export_data(session_id, data_type, fmt):
    with _cache_lock:
        cached = parse_cache.get(session_id)
    if not cached:
        return "Not found", 404

    result = cached['result']
    data = []

    for v in result.victims:
        if data_type == 'passwords':
            data.extend([asdict(p) for p in v.passwords])
        elif data_type == 'cookies':
            data.extend([asdict(c) for c in v.cookies])
        elif data_type == 'autofills':
            data.extend([asdict(a) for a in v.autofills])
        elif data_type == 'cards':
            data.extend([asdict(c) for c in v.credit_cards])
        elif data_type == 'wallets':
            data.extend([asdict(w) for w in v.wallets])

    if fmt == 'json':
        return Response(
            json.dumps(data, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=stex_{data_type}.json'}
        )
    elif fmt == 'csv':
        if not data:
            return "No data", 404

        import csv
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=stex_{data_type}.csv'}
        )

    return "Invalid format", 400


@app.route('/api/archives')
def api_archives():
    return jsonify(scan_uploads())


@app.route('/api/watcher-status')
def api_watcher_status():
    current = set()
    upload_dir = Config.UPLOAD_FOLDER
    if os.path.isdir(upload_dir):
        for fname in os.listdir(upload_dir):
            fpath = os.path.join(upload_dir, fname)
            if os.path.isfile(fpath) and ArchiveExtractor.is_supported(fname):
                current.add(fname)
    with _cache_lock:
        pc = len(parse_cache)

    with _jobs_lock:
        processing = [f for f, j in _jobs.items()
                      if j['status'] in ('queued', 'extracting', 'parsing')]

    return jsonify({
        'archive_count': len(current),
        'parsed_count': pc,
        'processing_count': len(processing),
        'archives': sorted(current),
    })


@app.route('/api/job-status/<filename>')
def api_job_status(filename):
    job = _get_job(filename)
    if not job:
        fpath = os.path.join(Config.UPLOAD_FOLDER, filename)
        if os.path.isfile(fpath):
            fkey = _file_key(fpath)
            with _cache_lock:
                if fkey in parse_cache:
                    return jsonify({'status': 'done', 'phase': 'Complete'})
        return jsonify({'status': 'none'})
    return jsonify(job)


@app.route('/api/jobs')
def api_jobs():
    with _jobs_lock:
        snapshot = {f: j.copy() for f, j in _jobs.items()}
    return jsonify(snapshot)


@app.route('/delete/<filename>')
def delete_archive(filename):
    fpath = os.path.join(Config.UPLOAD_FOLDER, filename)
    if os.path.isfile(fpath):
        fkey = _file_key(fpath)
        with _cache_lock:
            cached = parse_cache.pop(fkey, None)
        if cached and 'extract_dir' in cached:
            shutil.rmtree(cached.get('extract_dir', ''), ignore_errors=True)
        db.delete_archive(fkey)
        _clear_job(filename)
        os.remove(fpath)
        flash(f'Deleted {filename}', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    start_watcher()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
