"""
Network Config Portal - Application Entry Point
Uses modular Flask architecture with blueprints.
"""
import os
import sys

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.tasks import start_background_tasks
from app.config import Config


def main():
    """Start the application."""
    app = create_app()

    # Start background tasks
    start_background_tasks()

    # Run with SocketIO if available, otherwise plain Flask
    if app.config.get('REMOTE_ENABLED'):
        socketio = app.config['SOCKETIO']
        print(f"Starting server with SocketIO on port {Config.PORT}...")
        socketio.run(app, host='0.0.0.0', port=Config.PORT,
                     debug=Config.DEBUG, allow_unsafe_werkzeug=True)
    else:
        print(f"Starting server on port {Config.PORT}...")
        app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG,
                use_reloader=True)


if __name__ == '__main__':
    main()
