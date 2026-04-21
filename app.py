from functools import wraps # wraps login checking and role checking decorators
from io import BytesIO # used for sending file-like objects in responses

from flask import (
    Flask,
    abort, #error response helper
    g, #store current user and other request-scoped data
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from config import Config #get configuration settings
from secure_app.access_control import ( #who can do what based on their role
    can_access_dashboard,
    can_create_content,
    can_delete_document,
    can_download_document,
    can_manage_users,
    can_view_all_content,
    can_view_shared_content,
    normalize_system_role,
)
from secure_app.auth import UserAuth #认证服务类
from secure_app.documents import (#functions for handling documents 
    authorize_document_share_management,
    authorize_document_access,
    authorize_owned_document_edit,
    authorize_document_revision_upload,
    build_document_preview,
    decrypt_document,
    document_supports_inline_editing,
    load_editable_document_content,
    load_document_plaintext,
    log_document_preview,
    list_document_versions,
    list_document_shares,
    list_outbound_document_shares,
    list_owned_documents,
    list_visible_documents,
    list_recent_documents,
    list_shared_documents,
    load_recent_audit_events,
    permanently_delete_document,
    share_document_with_user,
    store_encrypted_document,
    upload_document_revision,
    update_document_content,
)
from secure_app.logging_utils import configure_app_logging, security_log
from secure_app.security import apply_security_headers
from secure_app.sessions import (
    create_session,
    get_session,
    invalidate_session,
    invalidate_user_sessions,
)
from secure_app.storage import bootstrap_storage #initialize storage directories and files if needed


def _request_is_secure() -> bool:# determine if it is secure 
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "") #xforward proto
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.is_secure


def _anonymous_user() -> dict: #represent an unauthenticated user
    return {
        "username": None,
        "role": None,
        "is_authenticated": False,
    }


def _set_session_cookie(response, app: Flask, session_token: str): #config session token
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

#TODO：flask app and internal tools 
def create_app() -> Flask: # create and configure the Flask application
    app = Flask(__name__)
    app.config.from_object(Config)

    bootstrap_storage(app.config)
    configure_app_logging(app)

    def auth_service() -> UserAuth:
        return UserAuth(
            app.config["USERS_FILE"],
            app.config["RATE_LIMITS_FILE"],
            max_login_attempts=app.config["MAX_LOGIN_ATTEMPTS"],
            account_lockout_minutes=app.config["ACCOUNT_LOCKOUT_MINUTES"],
            max_login_attempts_per_ip_per_minute=app.config[
                "MAX_LOGIN_ATTEMPTS_PER_IP_PER_MINUTE"
            ],
        )

    def current_user() -> dict:
        return getattr(g, "current_user", _anonymous_user())

    def document_preview_payload(document: dict, plaintext: bytes) -> dict:
        preview = build_document_preview(document, plaintext)
        if preview.get("kind") == "pdf":
            preview["embed_src"] = url_for(
                "preview_document_content",
                document_id=document["id"],
            )
        return preview

    def require_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_user()["is_authenticated"]:
                return view(*args, **kwargs)
            return redirect(url_for("login"))

        return wrapped

    def require_role(permission_check, capability_name: str): #check the role, and permission
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
#ToDo: auto logic
    # Enforce HTTPS for all requests if configured, by checking the request scheme and redirecting to HTTPS if necessary.
    @app.before_request
    def require_https():
        if app.config["FORCE_HTTPS"] and not _request_is_secure():
            secure_url = request.url.replace("http://", "https://", 1)
            return redirect(secure_url, code=301)
        return None

    @app.before_request
    def load_current_user(): #默认设置成匿名用户，如果有session cookie，尝试加载用户信息到g.current_user，否则保持匿名状态，并在请求结束后根据需要清除cookie
        g.current_user = _anonymous_user()
        g.clear_session_cookie = False # assume we won't need to clear the cookie unless we find an invalid session
        # trying to reconnize the user based on session cookie
        session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not session_token:
            return None

        session_data = get_session(app.config, session_token)
        if session_data is None:
            g.clear_session_cookie = True
            return None #invalid session token, clear cookie on response
    #otherwise, we have session data, try to load the user
        user = auth_service().get_user(session_data.get("user_id"))
        if user is None:
            invalidate_session(app.config, session_token, reason="user_missing")
            g.clear_session_cookie = True
            return None

        g.current_user = {
            "username": user["username"],
            "role": normalize_system_role(user.get("role", "user")),
            "is_authenticated": True,
        }
        return None

    @app.before_request
    def enforce_csrf():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.path == "/login" or request.path == "/register":
            return None

        session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        session_data = get_session(app.config, session_token) if session_token else None
        if session_data is None:
            return None

        expected = session_data.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not expected or not submitted or expected != submitted:
            security_log.log_event(
                "CSRF_VALIDATION_FAILED",
                session_data.get("user_id"),
                {"path": request.path},
                severity="WARNING",
            )
            abort(403)
        return None

    @app.context_processor
    def inject_current_user():
        session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        session_data = get_session(app.config, session_token) if session_token else None
        csrf_token = session_data.get("csrf_token", "") if session_data else ""
        return {"current_user": current_user(), "csrf_token": csrf_token}

    @app.after_request
    def set_headers(response):
        if getattr(g, "clear_session_cookie", False):
            _clear_session_cookie(response, app)
        return apply_security_headers(response)
    #index login, signup, logout. 
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user()["is_authenticated"]:
            destination = (
                url_for("dashboard")
                if can_access_dashboard(current_user()["role"])
                else url_for("documents")
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
                    else url_for("documents")
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
                else url_for("documents")
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
        invalidate_session(app.config, session_token, reason="logout")
        response = redirect(url_for("index"))
        return _clear_session_cookie(response, app)

    @app.route("/change-password", methods=["GET", "POST"])
    @require_auth
    def change_password():
        context = {"error": None, "success": None}
        if request.method == "POST":
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            result = auth_service().change_password(
                current_user()["username"],
                old_password,
                new_password,
                confirm_password,
            )

            if "success" in result:
                session_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
                invalidate_session(app.config, session_token, reason="password_change")
                response = redirect(url_for("login"))
                flash_response = _clear_session_cookie(response, app)
                return flash_response

            context["error"] = result["error"]
            return render_template("change_password.html", **context), 400

        return render_template("change_password.html", **context)

    #dashboard for users with dashboard access, showing recent documents and audit events, with different scopes based on role.
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
        context = {
            "title_value": "",
            "document_type_value": "",
            "document_type_options": [
                {
                    "value": extension,
                    "label": app.config["DOCUMENT_TYPE_LABELS"].get(extension, extension.upper()),
                }
                for extension in sorted(app.config["ALLOWED_EXTENSIONS"])
            ],
        }
        status_code = 200

        if request.method == "POST":
            context["title_value"] = request.form.get("title", "")
            context["document_type_value"] = request.form.get("document_type", "")
            uploaded_file = request.files.get("document")

            try:
                if uploaded_file is None:
                    security_log.log_event(
                        "UPLOAD_VALIDATION_FAILED",
                        current_user()["username"],
                        {
                            "reason": "Select a file to upload.",
                            "title": context["title_value"],
                            "document_type": context["document_type_value"],
                            "filename": "",
                        },
                        severity="WARNING",
                    )
                    raise ValueError("Select a file to upload.")

                uploaded_document = store_encrypted_document(
                    app.config,
                    context["title_value"],
                    context["document_type_value"],
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

#doc operations
    @app.route("/documents/<document_id>/edit", methods=["GET", "POST"])
    @require_auth
    def edit_document(document_id: str):
        user = current_user()

        try:
            editable_document = authorize_owned_document_edit(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        context = {
            "document": editable_document,
            "title_value": editable_document["title"],
            "content_value": "",
            "can_edit_content": False,
        }
        status_code = 200
        plaintext = load_document_plaintext(
            app.config,
            editable_document,
            user_id=user["username"],
        )
        context["can_edit_content"] = document_supports_inline_editing(editable_document)
        context["content_value"] = load_editable_document_content(
            editable_document,
            plaintext,
        )

        if request.method == "POST":
            context["title_value"] = request.form.get("title", "")
            context["content_value"] = request.form.get("content", "")
            try:
                editable_document = update_document_content(
                    app.config,
                    document_id,
                    context["title_value"],
                    context["content_value"],
                    user_id=user["username"],
                    system_role=user["role"],
                )
            except ValueError as exc:
                context["error"] = str(exc)
                status_code = 400
            else:
                context["document"] = editable_document
                context["success"] = "Document details updated successfully."

        return render_template("edit_document.html", **context), status_code

    @app.route("/documents/<document_id>/versions/upload", methods=["GET", "POST"])
    @require_auth
    def upload_document_version_page(document_id: str):
        user = current_user()

        try:
            document = authorize_document_revision_upload(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        context = {
            "document": document,
            "title_value": document["title"],
            "document_type_label": app.config["DOCUMENT_TYPE_LABELS"].get(
                document.get("document_type", ""),
                (document.get("document_type") or "").upper(),
            ),
        }
        status_code = 200

        if request.method == "POST":
            context["title_value"] = request.form.get("title", "")
            uploaded_file = request.files.get("document")

            try:
                document = upload_document_revision(
                    app.config,
                    document_id,
                    context["title_value"],
                    uploaded_file,
                    user_id=user["username"],
                    system_role=user["role"],
                )
            except ValueError as exc:
                context["error"] = str(exc)
                status_code = 400
            else:
                context["document"] = document
                context["title_value"] = document["title"]
                context["success"] = (
                    f"New document version uploaded successfully as version "
                    f"{document['version']}."
                )

        return render_template("upload_document_version.html", **context), status_code

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

    @app.route("/documents/<document_id>/versions/<int:version>/download")
    @require_auth
    def download_document_version(document_id: str, version: int):
        user = current_user()

        try:
            document, plaintext = decrypt_document(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
                version=version,
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

    @app.route("/documents/<document_id>/delete", methods=["POST"])
    @require_auth
    def delete_document(document_id: str):
        user = current_user()

        try:
            permanently_delete_document(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        return redirect(url_for("dashboard"))
#doc operations 2
    @app.route("/documents")
    @require_auth
    @require_role(can_view_shared_content, "document_browse")
    def documents():
        user = current_user()
        if can_view_all_content(user["role"]):
            available_documents = list_visible_documents(
                app.config,
                user_id=user["username"],
                system_role=user["role"],
            )
            shared_with_you = []
        else:
            owned_documents = list_owned_documents(
                app.config,
                owner=user["username"],
                limit=50,
            )
            shared_with_you = list_shared_documents(
                app.config,
                user_id=user["username"],
                system_role=user["role"],
                limit=50,
            )
            available_documents = owned_documents + shared_with_you
        return render_template(
            "documents.html",
            available_documents=available_documents,
            shared_with_you=shared_with_you,
            shared_with_others=list_outbound_document_shares(
                app.config,
                owner=user["username"],
            ),
            page_title="All Documents" if can_view_all_content(user["role"]) else "Documents",
            page_description=(
                "Admin accounts can browse all uploaded documents."
                if can_view_all_content(user["role"])
                else "This page shows the documents you own, the ones shared with you, and the ones you have shared with others."
            ),
        )

    @app.route("/documents/<document_id>/preview")
    @require_auth
    @require_role(can_view_shared_content, "document_preview")
    def preview_document(document_id: str):
        user = current_user()

        try:
            document, document_role = authorize_document_access(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
            plaintext = load_document_plaintext(
                app.config,
                document,
                user_id=user["username"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        log_document_preview(
            app.config, document, user["username"], document_role,
        )

        can_manage_shares = False
        can_return_to_owner = document_role == "editor"
        try:
            authorize_document_share_management(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
        except (FileNotFoundError, PermissionError):
            pass
        else:
            can_manage_shares = True

        return render_template(
            "document_preview.html",
            document=document,
            preview=document_preview_payload(document, plaintext),
            can_download=can_download_document(user["role"], document_role),
            can_delete=can_delete_document(user["role"], document_role),
            can_upload_new_version=document_role in {"owner", "editor"},
            can_edit=document_supports_inline_editing(document)
            and document_role in {"owner", "editor"},
            can_manage_shares=can_manage_shares,
            can_return_to_owner=can_return_to_owner,
            share_target_value="",
            share_role_value="viewer",
            version_history=list_document_versions(document),
            share_entries=list_document_shares(app.config, document_id)
            if can_manage_shares
            else [],
        )

    @app.route("/documents/<document_id>/preview/content")
    @require_auth
    @require_role(can_view_shared_content, "document_preview")
    def preview_document_content(document_id: str):
        user = current_user()

        try:
            document, document_role = authorize_document_access(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
            plaintext = load_document_plaintext(
                app.config,
                document,
                user_id=user["username"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        if (document.get("document_type") or "").lower() != "pdf":
            abort(404)

        log_document_preview(
            app.config, document, user["username"], document_role,
        )

        return send_file(
            BytesIO(plaintext),
            as_attachment=False,
            download_name=document["filename"],
            mimetype=document["content_type"],
        )

    @app.route("/documents/<document_id>/share", methods=["POST"])
    @require_auth
    def share_document(document_id: str):
        user = current_user()
        share_target_value = request.form.get("recipient_username", "")
        share_role_value = request.form.get("access_role", "viewer")

        try:
            document, document_role = authorize_document_access(
                app.config,
                document_id,
                user_id=user["username"],
                system_role=user["role"],
            )
            plaintext = load_document_plaintext(
                app.config,
                document,
                user_id=user["username"],
            )
        except FileNotFoundError:
            abort(404)
        except PermissionError:
            abort(403)

        context = {
            "document": document,
            "preview": document_preview_payload(document, plaintext),
            "can_download": can_download_document(user["role"], document_role),
            "can_delete": can_delete_document(user["role"], document_role),
            "can_upload_new_version": document_role in {"owner", "editor"},
            "can_edit": document_supports_inline_editing(document)
            and document_role in {"owner", "editor"},
            "can_manage_shares": document_role == "owner" or user["role"] == "admin",
            "can_return_to_owner": document_role == "editor",
            "share_target_value": share_target_value,
            "share_role_value": share_role_value,
            "share_entries": list_document_shares(app.config, document_id),
        }

        recipient = auth_service().get_user(share_target_value.strip())
        if recipient is None:
            context["share_error"] = "Recipient username was not found."
            return render_template("document_preview.html", **context), 400

        try:
            share_document_with_user(
                app.config,
                document_id,
                share_target_value,
                share_role_value,
                user_id=user["username"],
                system_role=user["role"],
            )
        except ValueError as exc:
            context["share_error"] = str(exc)
            return render_template("document_preview.html", **context), 400

        if document_role == "editor" and recipient["username"] == document["owner"]:
            context["share_success"] = "Updated document returned to the owner."
            context["can_return_to_owner"] = False
            context["can_edit"] = False
            context["can_upload_new_version"] = False
        else:
            context["share_success"] = (
                f"Document shared with {recipient['username']} as {share_role_value.strip().lower()}."
            )
        context["share_target_value"] = ""
        context["share_role_value"] = "viewer"
        context["share_entries"] = list_document_shares(app.config, document_id)
        context["version_history"] = list_document_versions(document)
        return render_template("document_preview.html", **context)
    #share and admin console
    @app.route("/shared")
    @require_auth
    def shared():
        return redirect(url_for("documents"))

    @app.route("/admin")
    @require_auth
    @require_role(can_manage_users, "admin_console")
    def admin():
        return render_template(
            "admin.html",
            users=auth_service().list_users(),
            recent_documents=list_recent_documents(app.config),
            recent_audit_events=load_recent_audit_events(app.config),
            available_roles=("admin", "user", "guest"),
            status_message=request.args.get("message", ""),
            status_category=request.args.get("status", "info"),
        )

    @app.route("/admin/users/<username>/role", methods=["POST"])
    @require_auth
    @require_role(can_manage_users, "admin_manage_users")
    def admin_update_user_role(username: str):
        user = current_user()
        target_username = username.strip()

        if target_username == user["username"]:
            return redirect(
                url_for(
                    "admin",
                    status="error",
                    message="You cannot change your own role from the admin console.",
                )
            )

        result = auth_service().update_role(
            target_username,
            request.form.get("role", ""),
            actor_username=user["username"],
        )
        if result.get("error"):
            return redirect(url_for("admin", status="error", message=result["error"]))

        updated_role = normalize_system_role(result["user"].get("role", "user"))
        return redirect(
            url_for(
                "admin",
                status="success",
                message=f"Updated {target_username} to role {updated_role}.",
            )
        )

    @app.route("/admin/users/<username>/lock", methods=["POST"])
    @require_auth
    @require_role(can_manage_users, "admin_manage_users")
    def admin_lock_user(username: str):
        user = current_user()
        target_username = username.strip()

        if target_username == user["username"]:
            return redirect(
                url_for(
                    "admin",
                    status="error",
                    message="You cannot lock your own account from the admin console.",
                )
            )

        result = auth_service().lock_user(
            target_username,
            actor_username=user["username"],
        )
        if result.get("error"):
            return redirect(url_for("admin", status="error", message=result["error"]))

        return redirect(
            url_for(
                "admin",
                status="success",
                message=f"Locked {target_username}.",
            )
        )

    @app.route("/admin/users/<username>/unlock", methods=["POST"])
    @require_auth
    @require_role(can_manage_users, "admin_manage_users")
    def admin_unlock_user(username: str):
        user = current_user()
        target_username = username.strip()

        result = auth_service().unlock_user(
            target_username,
            actor_username=user["username"],
        )
        if result.get("error"):
            return redirect(url_for("admin", status="error", message=result["error"]))

        return redirect(
            url_for(
                "admin",
                status="success",
                message=f"Unlocked {target_username}.",
            )
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

    @app.errorhandler(500)
    def handle_internal_server_error(error):
        return render_template("500.html"), 500

    return app

#local development 
app = create_app()


if __name__ == "__main__":
    ssl_context = None
    if app.config["TLS_CERT_FILE"] and app.config["TLS_KEY_FILE"]:
        ssl_context = (
            app.config["TLS_CERT_FILE"],
            app.config["TLS_KEY_FILE"],
        )
    app.run(
        debug=app.config["DEBUG"],
        ssl_context=ssl_context,
        host="0.0.0.0",
        port=5000,
    )
