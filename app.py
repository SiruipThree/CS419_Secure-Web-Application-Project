from io import BytesIO

from flask import Flask, abort, redirect, render_template, request, send_file

from config import Config
from secure_app.documents import (
    decrypt_document,
    list_recent_documents,
    load_recent_audit_events,
    store_encrypted_document,
)
from secure_app.logging_utils import configure_app_logging
from secure_app.security import apply_security_headers
from secure_app.storage import bootstrap_storage


def _request_is_secure() -> bool:
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.is_secure


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    bootstrap_storage(app.config)
    configure_app_logging(app)

    @app.before_request
    def require_https():
        if not app.config["FORCE_HTTPS"]:
            return None
        if _request_is_secure():
            return None

        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=307)

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
        return render_template(
            "dashboard.html",
            owned_documents=list_recent_documents(app.config, owner="demo-user"),
            recent_audit_events=load_recent_audit_events(app.config),
        )

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        context = {"title_value": ""}
        status_code = 200

        if request.method == "POST":
            context["title_value"] = request.form.get("title", "")
            uploaded_file = request.files.get("document")

            try:
                if uploaded_file is None:
                    raise ValueError("Select a file to upload.")

                uploaded_document = store_encrypted_document(
                    app.config,
                    context["title_value"],
                    uploaded_file,
                )
            except ValueError as exc:
                context["error"] = str(exc)
                status_code = 400
            else:
                context["success"] = (
                    f"Encrypted upload stored successfully as version "
                    f"{uploaded_document['version']}."
                )
                context["uploaded_document"] = uploaded_document

        return render_template("upload.html", **context), status_code

    @app.route("/documents/<document_id>/download")
    def download_document(document_id: str):
        try:
            document, plaintext = decrypt_document(app.config, document_id)
        except FileNotFoundError:
            abort(404)

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=document["filename"],
            mimetype=document["content_type"],
        )

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

    @app.errorhandler(413)
    def handle_request_entity_too_large(error):
        return render_template("413.html"), 413

    return app


app = create_app()


if __name__ == "__main__":
    ssl_context = None
    if app.config["TLS_CERT_FILE"] and app.config["TLS_KEY_FILE"]:
        ssl_context = (
            app.config["TLS_CERT_FILE"],
            app.config["TLS_KEY_FILE"],
        )
    app.run(debug=app.config["DEBUG"], ssl_context=ssl_context)
