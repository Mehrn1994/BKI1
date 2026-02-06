"""
Remote Connection Module - SSH/Telnet/RDP
WebSocket-based terminal for SSH/Telnet + RDP file generation
"""

import paramiko
import telnetlib
import threading
import uuid
import time
from flask import Blueprint, render_template, request, jsonify, Response

# Temporary session tokens (token -> connection params)
_sessions = {}
SESSION_TTL = 300  # 5 minutes

# Active connections (socket sid -> connection object)
_connections = {}

remote_bp = Blueprint('remote', __name__)


def _cleanup_expired_sessions():
    now = time.time()
    expired = [k for k, v in _sessions.items() if now - v['created'] > SESSION_TTL]
    for k in expired:
        del _sessions[k]


@remote_bp.route('/terminal')
def terminal_page():
    return render_template('terminal.html')


@remote_bp.route('/api/remote/session', methods=['POST'])
def create_session():
    """Create a temporary session token for terminal connection"""
    _cleanup_expired_sessions()

    data = request.json
    if not data or not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400

    token = str(uuid.uuid4())
    _sessions[token] = {
        'host': data['host'].strip(),
        'port': int(data.get('port', 22)),
        'protocol': data.get('protocol', 'ssh'),
        'username': data.get('username', '').strip(),
        'password': data.get('password', ''),
        'created': time.time()
    }

    return jsonify({'token': token})


@remote_bp.route('/api/remote/rdp', methods=['POST'])
def generate_rdp():
    """Generate and return a .rdp file for download"""
    data = request.json
    if not data or not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400

    host = data['host'].strip()
    username = data.get('username', '').strip()
    domain = data.get('domain', '').strip()
    port = int(data.get('port', 3389))

    rdp_lines = [
        "screen mode id:i:2",
        "use multimon:i:0",
        "desktopwidth:i:1920",
        "desktopheight:i:1080",
        "session bpp:i:32",
        "compression:i:1",
        "keyboardhook:i:2",
        "audiocapturemode:i:0",
        "videoplaybackmode:i:1",
        "connection type:i:7",
        "networkautodetect:i:1",
        "bandwidthautodetect:i:1",
        "displayconnectionbar:i:1",
        "disable wallpaper:i:0",
        "allow font smoothing:i:1",
        "allow desktop composition:i:1",
        "disable full window drag:i:0",
        "disable menu anims:i:0",
        "disable themes:i:0",
        "bitmapcachepersistenable:i:1",
        f"full address:s:{host}:{port}",
        "audiomode:i:0",
        "redirectprinters:i:0",
        "redirectclipboard:i:1",
        "autoreconnection enabled:i:1",
        "authentication level:i:2",
        f"prompt for credentials:i:{'0' if username else '1'}",
        "negotiate security layer:i:1",
    ]

    if username:
        rdp_lines.append(f"username:s:{username}")
    if domain:
        rdp_lines.append(f"domain:s:{domain}")

    rdp_content = "\r\n".join(rdp_lines) + "\r\n"

    resp = Response(rdp_content, mimetype='application/x-rdp')
    safe_host = host.replace(':', '_')
    resp.headers['Content-Disposition'] = f'attachment; filename="{safe_host}.rdp"'
    return resp


def register_socketio_handlers(socketio):
    """Register SocketIO event handlers for SSH/Telnet terminals"""

    @socketio.on('connect', namespace='/terminal')
    def on_connect():
        pass

    @socketio.on('start_session', namespace='/terminal')
    def on_start_session(data):
        sid = request.sid
        token = data.get('token', '')

        # Retrieve params from token or use direct data
        if token and token in _sessions:
            params = _sessions.pop(token)
        else:
            params = data

        host = params.get('host', '').strip()
        port = int(params.get('port', 22))
        protocol = params.get('protocol', 'ssh')
        username = params.get('username', '').strip()
        password = params.get('password', '')

        if not host:
            socketio.emit('output',
                          '\r\n\x1b[1;31mError: No host specified\x1b[0m\r\n',
                          namespace='/terminal', to=sid)
            return

        try:
            if protocol == 'ssh':
                _start_ssh(socketio, sid, host, port, username, password)
            elif protocol == 'telnet':
                _start_telnet(socketio, sid, host, port, username, password)
            else:
                socketio.emit('output',
                              f'\r\n\x1b[1;31mUnknown protocol: {protocol}\x1b[0m\r\n',
                              namespace='/terminal', to=sid)
        except Exception as e:
            socketio.emit('output',
                          f'\r\n\x1b[1;31mConnection failed: {e}\x1b[0m\r\n',
                          namespace='/terminal', to=sid)
            socketio.emit('session_end', {}, namespace='/terminal', to=sid)

    @socketio.on('input', namespace='/terminal')
    def on_input(data):
        sid = request.sid
        if sid not in _connections:
            return
        conn = _connections[sid]
        try:
            if conn['protocol'] == 'ssh':
                conn['channel'].send(data)
            elif conn['protocol'] == 'telnet':
                conn['telnet'].write(data.encode('utf-8'))
        except Exception:
            pass

    @socketio.on('resize', namespace='/terminal')
    def on_resize(data):
        sid = request.sid
        if sid in _connections and _connections[sid]['protocol'] == 'ssh':
            try:
                cols = int(data.get('cols', 80))
                rows = int(data.get('rows', 24))
                _connections[sid]['channel'].resize_pty(width=cols, height=rows)
            except Exception:
                pass

    @socketio.on('disconnect', namespace='/terminal')
    def on_disconnect():
        _cleanup_connection(request.sid)


def _start_ssh(socketio, sid, host, port, username, password):
    """Establish an SSH session and start I/O relay"""
    socketio.emit('output',
                  f'\x1b[1;33m>>> Connecting to {host}:{port} via SSH...\x1b[0m\r\n',
                  namespace='/terminal', to=sid)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False
        )
    except paramiko.AuthenticationException:
        socketio.emit('output',
                      '\r\n\x1b[1;31mAuthentication failed. Check username/password.\x1b[0m\r\n',
                      namespace='/terminal', to=sid)
        socketio.emit('session_end', {}, namespace='/terminal', to=sid)
        client.close()
        return
    except Exception as e:
        socketio.emit('output',
                      f'\r\n\x1b[1;31mSSH error: {e}\x1b[0m\r\n',
                      namespace='/terminal', to=sid)
        socketio.emit('session_end', {}, namespace='/terminal', to=sid)
        client.close()
        return

    channel = client.invoke_shell(term='xterm-256color', width=120, height=30)
    channel.settimeout(0.1)

    _connections[sid] = {
        'protocol': 'ssh',
        'client': client,
        'channel': channel,
        'active': True
    }

    socketio.emit('session_start', {'protocol': 'ssh', 'host': host},
                  namespace='/terminal', to=sid)

    def read_loop():
        while sid in _connections and _connections[sid].get('active'):
            try:
                data = channel.recv(4096)
                if not data:
                    break
                socketio.emit('output',
                              data.decode('utf-8', errors='replace'),
                              namespace='/terminal', to=sid)
            except Exception:
                continue
        socketio.emit('session_end', {}, namespace='/terminal', to=sid)
        _cleanup_connection(sid)

    t = threading.Thread(target=read_loop, daemon=True)
    t.start()
    _connections[sid]['thread'] = t


def _start_telnet(socketio, sid, host, port, username, password):
    """Establish a Telnet session and start I/O relay"""
    socketio.emit('output',
                  f'\x1b[1;33m>>> Connecting to {host}:{port} via Telnet...\x1b[0m\r\n',
                  namespace='/terminal', to=sid)

    try:
        tn = telnetlib.Telnet(host, port, timeout=15)
    except Exception as e:
        socketio.emit('output',
                      f'\r\n\x1b[1;31mTelnet error: {e}\x1b[0m\r\n',
                      namespace='/terminal', to=sid)
        socketio.emit('session_end', {}, namespace='/terminal', to=sid)
        return

    _connections[sid] = {
        'protocol': 'telnet',
        'telnet': tn,
        'active': True
    }

    socketio.emit('session_start', {'protocol': 'telnet', 'host': host},
                  namespace='/terminal', to=sid)

    # Auto-login if credentials provided
    if username:
        try:
            tn.read_until(b"ogin:", timeout=5)
            tn.write(username.encode('utf-8') + b'\n')
            if password:
                tn.read_until(b"assword:", timeout=5)
                tn.write(password.encode('utf-8') + b'\n')
        except Exception:
            pass

    def read_loop():
        while sid in _connections and _connections[sid].get('active'):
            try:
                data = tn.read_very_eager()
                if data:
                    socketio.emit('output',
                                  data.decode('utf-8', errors='replace'),
                                  namespace='/terminal', to=sid)
                else:
                    socketio.sleep(0.05)
            except EOFError:
                break
            except Exception:
                socketio.sleep(0.05)
        socketio.emit('session_end', {}, namespace='/terminal', to=sid)
        _cleanup_connection(sid)

    t = threading.Thread(target=read_loop, daemon=True)
    t.start()
    _connections[sid]['thread'] = t


def _cleanup_connection(sid):
    """Close and remove a connection"""
    if sid not in _connections:
        return
    conn = _connections.pop(sid, None)
    if not conn:
        return
    conn['active'] = False
    try:
        if conn['protocol'] == 'ssh':
            conn['channel'].close()
            conn['client'].close()
        elif conn['protocol'] == 'telnet':
            conn['telnet'].close()
    except Exception:
        pass
