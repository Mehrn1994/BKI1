"""
Network Config Portal - Application Factory
Modular Flask application with security, RBAC, audit trail, and more.
"""
import os
from flask import Flask, request, jsonify
from flask_cors import CORS

from app.config import Config


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__,
                template_folder=os.path.join(Config.BASE_DIR, 'templates'),
                static_folder=os.path.join(Config.BASE_DIR, 'static'))

    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # CORS - restricted origins (not wildcard)
    CORS(app, origins=Config.CORS_ORIGINS)

    # Ensure directories exist
    os.makedirs(Config.BACKUP_DIR, exist_ok=True)
    os.makedirs(Config.CHAT_UPLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)

    # Initialize database
    from app.database import init_tables
    init_tables()

    # Register blueprints
    from app.routes.pages import pages_bp
    from app.routes.auth import auth_bp
    from app.routes.stats import stats_bp
    from app.routes.lan import lan_bp
    from app.routes.tunnels import tunnels_bp
    from app.routes.apn import apn_bp
    from app.routes.services import services_bp
    from app.routes.chat import chat_bp
    from app.routes.admin import admin_bp
    from app.routes.export import export_bp
    from app.routes.tools import tools_bp
    from app.routes.shared_files import shared_files_bp
    from app.routes.reports import reports_bp
    from app.routes.network_map import network_map_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(lan_bp)
    app.register_blueprint(tunnels_bp)
    app.register_blueprint(apn_bp)
    app.register_blueprint(services_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(export_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(shared_files_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(network_map_bp)

    # Optional: Remote connection module
    try:
        from flask_socketio import SocketIO
        socketio = SocketIO(app, cors_allowed_origins=Config.CORS_ORIGINS, async_mode='threading')
        from remote_connect import remote_bp, register_socketio_handlers
        app.register_blueprint(remote_bp)
        register_socketio_handlers(socketio)
        app.config['SOCKETIO'] = socketio
        app.config['REMOTE_ENABLED'] = True
        print("Remote Connection module loaded (SSH/Telnet/RDP)")
    except ImportError:
        app.config['REMOTE_ENABLED'] = False

    # Response headers
    @app.after_request
    def add_security_headers(response):
        # Cache headers
        if request.path.endswith(('.html', '.css', '.js', '.png', '.jpg', '.ico')):
            response.headers['Cache-Control'] = 'public, max-age=3600'
        elif request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, max-age=0'

        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        if request.path.startswith('/api/'):
            response.headers['Content-Type'] = response.headers.get('Content-Type', 'application/json')

        return response

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        return "Page not found", 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'error': 'File too large (max 16MB)'}), 413

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({'error': 'Internal server error'}), 500

    # Auto-import PTMP on first run
    _check_ptmp_import()

    return app


def _check_ptmp_import():
    """Auto-import PTMP from router configs if table is empty."""
    try:
        from app.database import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ptmp_connections")
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            print("PTMP table empty, running initial import...")
            from parse_router_configs import import_serial_to_db
            import_serial_to_db()
    except Exception as e:
        print(f"PTMP auto-import check: {e}")
