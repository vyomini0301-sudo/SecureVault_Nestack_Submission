from flask import Flask, jsonify, render_template
from config import Config
from database import init_db
from auth import auth_bp
from records import records_bp
from admin import admin_bp
from rate_limit import enforce_rate_limit


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    if overrides:
        app.config.update(overrides)

    init_db(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(records_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def apply_rate_limit():
        return enforce_rate_limit()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"]="default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html")
    @app.get('/health')
    def health():
        return jsonify(status="ok"), 200

    @app.errorhandler(500)
    def err(e):
        return jsonify(error="Internal server error"), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)







