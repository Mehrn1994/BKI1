"""Shared files (cloud storage) routes."""
import os
import time
from datetime import datetime
from flask import Blueprint, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from app.config import Config
from app.database import log_audit
from app.security import is_api_rate_limited

shared_files_bp = Blueprint('shared_files', __name__)

SHARED_DIR = os.path.join(Config.BASE_DIR, 'data', 'shared_files')
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
# Whitelist of safe file extensions - executables, scripts, and server-side files are blocked
ALLOWED_EXTENSIONS = {
    'pdf', 'xlsx', 'xls', 'csv', 'doc', 'docx', 'txt', 'rtf',
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg',
    'zip', 'rar', '7z', 'tar', 'gz',
    'ppt', 'pptx',
    'mp4', 'mp3', 'wav',
    'json', 'xml', 'yaml', 'yml',
    'log', 'cfg', 'conf',
}
# Blocked dangerous extensions (executables, scripts, server-side code)
BLOCKED_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'ts', 'py', 'rb', 'php',
    'asp', 'aspx', 'jsp', 'jar', 'war', 'ear', 'dll', 'so', 'dylib',
    'msi', 'deb', 'rpm', 'apk', 'ipa', 'dmg', 'iso',
    'html', 'htm', 'htaccess', 'cgi', 'pl',
}


def _get_file_info(filepath):
    stat = os.stat(filepath)
    name = os.path.basename(filepath)
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    return {
        'name': name,
        'size': stat.st_size,
        'ext': ext,
        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        'uploaded': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
    }


@shared_files_bp.route('/api/shared-files', methods=['GET'])
def list_files():
    try:
        os.makedirs(SHARED_DIR, exist_ok=True)
        files = []
        for f in os.listdir(SHARED_DIR):
            fpath = os.path.join(SHARED_DIR, f)
            if os.path.isfile(fpath):
                files.append(_get_file_info(fpath))
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({'status': 'ok', 'files': files})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@shared_files_bp.route('/api/shared-files/upload', methods=['POST'])
def upload_file():
    try:
        if is_api_rate_limited(request.remote_addr, 'shared-upload'):
            return jsonify({'status': 'error', 'error': 'Too many requests'}), 429

        username = request.form.get('username', 'unknown')

        if 'file' not in request.files:
            return jsonify({'status': 'error', 'error': 'No file selected'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'status': 'error', 'error': 'No file selected'}), 400

        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''

        # Block dangerous file types
        if ext in BLOCKED_EXTENSIONS:
            return jsonify({'status': 'error', 'error': f'File type .{ext} is not allowed for security reasons'}), 400
        if ext and ext not in ALLOWED_EXTENSIONS:
            return jsonify({'status': 'error', 'error': f'File type .{ext} is not permitted. Allowed: documents, images, archives'}), 400

        # Check file size
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > MAX_FILE_SIZE:
            return jsonify({'status': 'error', 'error': 'File too large (max 100MB)'}), 400

        os.makedirs(SHARED_DIR, exist_ok=True)
        filename = secure_filename(file.filename)
        if not filename:
            filename = f'file_{int(time.time())}.{ext}'

        # If file exists, add timestamp
        filepath = os.path.join(SHARED_DIR, filename)
        if os.path.exists(filepath):
            name_part = filename.rsplit('.', 1)[0] if '.' in filename else filename
            ext_part = filename.rsplit('.', 1)[1] if '.' in filename else ''
            filename = f"{name_part}_{int(time.time())}.{ext_part}" if ext_part else f"{name_part}_{int(time.time())}"
            filepath = os.path.join(SHARED_DIR, filename)

        file.save(filepath)
        log_audit('shared_upload', filename, username, 'shared_files', ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'message': f'File {filename} uploaded', 'file': _get_file_info(filepath)})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@shared_files_bp.route('/api/shared-files/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        safe_name = secure_filename(filename)
        return send_from_directory(SHARED_DIR, safe_name, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'status': 'error', 'error': 'File not found'}), 404


@shared_files_bp.route('/api/shared-files/delete', methods=['POST'])
def delete_file():
    try:
        data = request.json or {}
        filename = data.get('filename', '')
        username = data.get('username', 'unknown')

        if not filename:
            return jsonify({'status': 'error', 'error': 'No filename'}), 400

        safe_name = secure_filename(filename)
        filepath = os.path.join(SHARED_DIR, safe_name)
        if not os.path.exists(filepath):
            return jsonify({'status': 'error', 'error': 'File not found'}), 404

        os.remove(filepath)
        log_audit('shared_delete', safe_name, username, 'shared_files', ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'message': f'File {safe_name} deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500
