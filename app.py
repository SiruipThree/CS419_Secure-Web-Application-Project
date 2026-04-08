from functools import wraps
from io import BytesIO

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from config import Config
from secure_app.access_control import (
    can_access_dashboard,
    can_create_content,
    can_manage_users,
    can_view_all_content,
    normalize_system_role,
)
from secure_app.auth import UserAuth
from secure_app.documents import (
    decrypt_document,
    list_recent_documents,
    list_shared_documents,
    load_recent_audit_events,
    store_encrypted_document,
)
from secure_app.logging_utils import configure_app_logging, security_log
from secure_app.security import apply_security_headers
from secure_app.sessions import create_session, get_session, invalidate_session
from secure_app.storage import bootstrap_storage


def _request_is_secure() -> bool:
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.is_secure


def _anonymous_user() -> dict:
    return {
        "username": None,
        "role": None,
        "is_authenticated": False,
    }


def _set_session_cookie(response, app: Flask, session_token: str):
    response.set_cookie(
        app.config["SESSION_COOKIE_NAME"],
        session_token,
        max_age=app.config["SESSION_TIMEOUT_SECONDS"],
        httponly=app.config["SESSION_COOKIE_HTTPONLY"],
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite=app.config["SESSION_COOKIE_SAMESITE"],
        path="/",
    )
    return response


def _clear_session_cookie(response, app: Flask):
    response.delete_cookie(app.config["SESSION_COOKIE_NAME"], path="/")
    return response


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    bootstrap_storage(app.config)
    configure_app_logging(app)

    def auth_service() -> UserAuth:
        return UserAuth(
            app.config["USERS_FILE"],
            app.config["RATE_LIMITS_FILE"],
        )

    def current_user() -> dict:
        return getattr(g, "current_user", _anonymous_user())

    def require_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_user()["is_authenticated"]:
                return view(*args, **kwargs)
            return redirect(url_for("login"))

        return wrapped

    def require_role(permission_check, capability_name: str):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                user = current_user()
                if not user["is_authenticated"]:
                    return redirect(url_for("login"))
                if permission_check(user["role"]):
                    return view(*args, **kwargs)

                security_log.log_event(
                    "AUTHORIZATION_DENIED",
                    user["username"],
                    {
                        "path": request.path,
                        "capability": capability_name,
                        "system_role": user["role"],
                    },
                    severity="WARNING",
                )
                abort(403)

            return wrapped

        return decorator

    @app.before_request
    def require_https():
        if not app.config["FORCE_HTTPS"]:
            return None
        if _request_is_secure():
            return None

        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=307)

    @app.before_request
    def load_current_user():
        g.current_user = _anonymous_user()
        g.clear_session_cookie = False

        session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not session_token:
            return None

        session_data = get_session(app.config, session_token)
        if session_data is None:
            g.clear_session_cookie = True
            return None

        user = auth_service().get_user(session_data.get("user_id"))
        if user is None:
            invalidate_session(app.config, session_token)
            g.clear_session_cookie = True
            return None

        g.current_user = {
            "username": user["username"],
            "role": normalize_system_role(user.get("role", "user")),
            "is_authenticated": True,
        }
        return None

    @app.context_processor
    def inject_current_user():
        return {"current_user": current_user()}

    @app.after_request
    def set_headers(response):
        if getattr(g, "clear_session_cookie", False):
            _clear_session_cookie(response, app)
        return apply_security_headers(response)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user()["is_authenticated"]:
            destination = (
                url_for("dashboard")
                if can_access_dashboard(current_user()["role"])
                else url_for("shared")
            )
            return redirect(destination)

        context = {"identifier_value": ""}
        status_code = 200

        if request.method == "POST":
            context["identifier_value"] = request.form.get("identifier", "").strip()
            password = request.form.get("password", "")
            result = auth_service().login(
                context["identifier_value"],
                password,
                request.remote_addr,
            )

            if result.get("success"):
                session_token = create_session(
                    app.config,
                    result["user_id"],
                    result["role"],
                )
                destination = (
                    url_for("dashboard")
                    if can_access_dashboard(result["role"])
                    else url_for("shared")
                )
                response = redirect(destination)
                return _set_session_cookie(response, app, session_token)

            context["error"] = result["error"]
            status_code = 400

        return render_template("login.html", **context), status_code

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user()["is_authenticated"]:
            destination = (
                url_for("dashboard")
                if can_access_dashboard(current_user()["role"])
                else url_for("shared")
            )
            return redirect(destination)

        context = {"email_value": "", "username_value": ""}
        status_code = 200

        if request.method == "POST":
            context["username_value"] = request.form.get("username", "").strip()
            context["email_value"] = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            result = auth_service().register(
                context["username_value"],
                context["email_value"],
                password,
                confirm_password,
            )

            if result.get("success"):
                session_token = create_session(
                    app.config,
                    result["user_id"],
                    result["role"],
                )
                response = redirect(url_for("dashboard"))
                return _set_session_cookie(response, app, session_token)

            context["error"] = result["error"]
            status_code = 400

        return render_template("register.html", **context), status_code

    @app.route("/logout", methods=["POST"])
    def logout():
        session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        invalidate_session(app.config, session_token)
        response = redirect(url_for("index"))
        return _clear_session_cookie(response, app)

    @app.route("/dashboard")
    @require_auth
    @require_role(can_access_dashboard, "dashboard_access")
    def dashboard():
        user = current_user()
        documents = (
            list_recent_documents(app.config)
            if can_view_all_content(user["role"])
            else list_recent_documents(app.config, owner=user["username"])
        )
        audit_events = load_recent_audit_events(
            app.config,
            user_id=None if can_view_all_content(user["role"]) else user["username"],
        )
        return render_template(
            "dashboard.html",
            owned_documents=documents,
            recent_audit_events=audit_events,
        )

    @app.route("/upload", methods=["GET", "POST"])
    @require_auth
    @require_role(can_create_content, "document_upload")
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
                    owner=current_user()["username"],
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
    @require_auth
    def download_document(document_id: str):
        user = current_user()

        try:
            document, plaintext = decrypt_document(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=document["filename"],
            mimetype=document["content_type"],
        )

    @app.route("/shared")
    @require_auth
    def shared():
        user = current_user()
        return render_template(
            "shared.html",
            shared_documents=list_shared_documents(
                app.config,
                user_id=user["username"],
                system_role=user["role"],
            ),
        )

    @app.route("/admin")
    @require_auth
    @require_role(can_manage_users, "admin_console")
    def admin():
        return render_template(
            "admin.html",
            users=auth_service().list_users(),
            recent_documents=list_recent_documents(app.config),
            recent_audit_events=load_recent_audit_events(app.config),
        )

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
