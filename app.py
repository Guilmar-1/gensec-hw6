from flask import Flask
from config import Config
from models.db import init_db
from controllers.dashboard_controller import dashboard_bp
from controllers.scan_controller import scan_bp
from controllers.report_controller import report_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize DB tables
    init_db(app)

    # Register Controller Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
