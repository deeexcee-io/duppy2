import os
from flask import Flask, Response, redirect, render_template, request, send_from_directory

Uploader = Flask('Uploader')
Uploader.secret_key = 'XXX1234'

UPLOAD_FOLDER_DEFAULT = os.path.join(os.getcwd(), 'upload')


def env_truthy(key: str, default: str = "0") -> bool:
    """Return True if the environment variable is set to a truthy value."""
    return str(os.environ.get(key, default)).lower() in {"1", "true", "yes", "on"}


CLIENT_NAME = os.environ.get("DUPPY_CLIENT_NAME", "Client")
ENDPOINT_SLUG = os.environ.get("DUPPY_ENDPOINT", "share").strip("/ ")
ENDPOINT_SLUG = ENDPOINT_SLUG or "share"
DOWNLOAD_PATH = f"/{ENDPOINT_SLUG}"

USERNAME = os.environ.get("DUPPY_USERNAME", "")
PASSWORD = os.environ.get("DUPPY_PASSWORD", "")
REQUIRE_AUTH = env_truthy("DUPPY_REQUIRE_BASIC_AUTH", "1")

SHARE_FOLDER = os.environ.get("DUPPY_PAYLOAD_DIR", UPLOAD_FOLDER_DEFAULT)
os.makedirs(SHARE_FOLDER, exist_ok=True)
Uploader.config["UPLOAD_FOLDER"] = SHARE_FOLDER


def unauthorized() -> Response:
    return Response(
        "Unauthorized",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="duppy"'},
    )


@Uploader.before_request
def enforce_basic_auth():
    if not REQUIRE_AUTH:
        return None

    auth = request.authorization
    if not auth or auth.username != USERNAME or auth.password != PASSWORD:
        return unauthorized()
    return None


@Uploader.route("/", methods=["GET"])
def index():
    return redirect(DOWNLOAD_PATH, code=302)


@Uploader.route(DOWNLOAD_PATH, methods=["GET"])
def file_list():
    files = sorted(os.listdir(SHARE_FOLDER))
    return render_template(
        "file_list.html",
        file_list=files,
        client_name=CLIENT_NAME,
    )


@Uploader.route(f"{DOWNLOAD_PATH}/<path:filename>", methods=["GET"])
def down_file(filename: str):
    return send_from_directory(
        SHARE_FOLDER,
        filename,
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    Uploader.run()
