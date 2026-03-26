from flask import Flask, abort, render_template

from config import Config
from secure_app.logging_utils import configure_app_logging
from secure_app.security import apply_security_headers
from secure_app.storage import bootstrap_storage


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    bootstrap_storage(app.config)
    configure_app_logging(app)

    @app.after_request
    def set_headers(response):
        return apply_security_headers(response)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login")
    def login():
        return render_template("login.html")

    @app.route("/register")
    def register():
        return render_template("register.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/upload")
    def upload():
        return render_template("upload.html")

    @app.route("/shared")
    def shared():
        return render_template("shared.html")

    @app.route("/admin")
    def admin():
        return render_template("admin.html")

    @app.route("/forbidden")
    def forbidden():
        abort(403)

    @app.errorhandler(403)
    def handle_forbidden(error):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def handle_not_found(error):
        return render_template("404.html"), 404

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
