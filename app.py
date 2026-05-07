from flask import Flask, request, render_template, redirect, url_for, make_response, jsonify
import requests
import jwt
import datetime
import os
import re
from urllib.parse import urlparse
from flask import send_from_directory

app = Flask(__name__)

# ---------------------------------------------------------------
# DevNest v2.0 - CTF 교육용 의도적 취약 애플리케이션
# 취약점: SSRF (userinfo@host + 인코딩 IP 우회) + 내부 API 무인증
# ---------------------------------------------------------------

JWT_SECRET = os.environ.get("JWT_SECRET")
FLAG       = os.environ.get("FLAG")

# 메모리 기반 유저 저장소
USERS = {
    "admin": "superSecretAdminPass!",
    "guest": "guest1234",
}

# 세션 내 스니펫 저장소
SNIPPETS = []

BLACKLIST = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::ffff:",
    "169.254.169.254",
]


# ── 헬퍼 ────────────────────────────────────────────────────────

def detect_lang(url: str, content: str) -> str:
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".sh": "Shell",  ".json": "JSON",      ".html": "HTML",
        ".css": "CSS",   ".java": "Java",       ".go": "Go",
        ".rs": "Rust",   ".c": "C",             ".cpp": "C++",
        ".md": "Markdown", ".yml": "YAML",      ".yaml": "YAML",
    }
    path = urlparse(url).path.lower()
    for ext, lang in ext_map.items():
        if path.endswith(ext):
            return lang
    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "JSON"
    return "Text"

from flask import send_from_directory

@app.route("/robots.txt")
def robots():
    return send_from_directory(app.root_path, "robots.txt")


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    return f"{n/1024:.1f} KB"


def detect_name(url: str, fallback: str) -> str:
    if fallback.strip():
        return fallback.strip()
    path = urlparse(url).path
    name = path.rstrip("/").split("/")[-1]
    return name if name else url[:30]


def is_ssrf_safe(url: str) -> tuple[bool, str]:
    """
    취약한 SSRF 방어 — 문자열 블랙리스트만 체크
    userinfo@host + 인코딩 IP 조합으로 우회 가능
      예) http://foo@0x7f000001:5000/...
          http://foo@2130706433:5000/...
    """
    url_lower = url.lower()
    for bad in BLACKLIST:
        if bad in url_lower:
            return False, f"차단된 주소: {bad}"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "http/https만 허용됩니다."
    if not parsed.netloc:
        return False, "유효하지 않은 URL입니다."
    return True, "ok"


def make_jwt(username: str) -> str:
    payload = {
        "sub":  username,
        "role": "admin" if username == "admin" else "user",
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def get_payload() -> dict | None:
    token = request.cookies.get("token")
    if not token:
        return None
    return verify_jwt(token)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = get_payload()
        if not payload:
            return redirect(url_for("login"))
        return f(*args, payload=payload, **kwargs)
    return decorated


def tmpl_ctx(payload: dict, page: str) -> dict:
    return {
        "username": payload.get("sub", ""),
        "role":     payload.get("role", ""),
        "page":     page,
    }


# ── 내부 Admin API ───────────────────────────────────────────────

@app.route("/api/admin/info")
def api_admin_info():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"status": "error", "message": "내부 전용 API입니다."}), 403
    return jsonify({
        "service":   "DevNest Admin API",
        "version":   "1.0",
        "note":      "내부망 전용 — JWT 검증 없음",
        "endpoints": [
            "GET /api/admin/info",
            "GET /api/admin/change_password?new_password=<pw>"
        ]
    })


@app.route("/api/admin/change_password")
def api_change_password():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"status": "error", "message": "내부 전용 API입니다."}), 403

    new_pw = request.args.get("new_password", "").strip()
    if not new_pw:
        return jsonify({
            "status":  "error",
            "message": "new_password 파라미터가 필요합니다.",
            "example": "/api/admin/change_password?new_password=newpass123"
        }), 400

    USERS["admin"] = new_pw
    return jsonify({
        "status":  "success",
        "message": "admin 비밀번호가 변경되었습니다.",
        "hint":    "/login 에서 admin 계정으로 로그인하세요."
    })


# ── 라우트 ───────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            token = make_jwt(username)
            resp  = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("token", token, httponly=True)
            return resp
        error = "아이디 또는 비밀번호가 올바르지 않습니다."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("token")
    return resp


@app.route("/")
@login_required
def dashboard(payload):
    return render_template("dashboard.html", **tmpl_ctx(payload, "dash"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password(payload):
    msg    = ""
    is_err = False
    if request.method == "POST":
        new_pw = request.form.get("new_password", "").strip()
        if new_pw:
            USERS[payload["sub"]] = new_pw
            msg = f"✓ '{payload['sub']}' 계정의 비밀번호가 변경되었습니다."
        else:
            msg    = "비밀번호를 입력해주세요."
            is_err = True
    return render_template(
        "change_password.html",
        **tmpl_ctx(payload, "pw"),
        msg=msg,
        is_err=is_err,
    )


@app.route("/fetch", methods=["GET", "POST"])
@login_required
def fetch_save(payload):
    result       = None
    is_err       = False
    fetched_url  = ""
    snippet_name = ""

    if request.method == "POST":
        source_url   = request.form.get("source_url", "").strip()
        snippet_name = request.form.get("snippet_name", "").strip()
        fetched_url  = source_url

        if not source_url:
            result = "URL을 입력해주세요."
            is_err = True
        else:
            safe, reason = is_ssrf_safe(source_url)
            if not safe:
                result = f"[보안 차단] {reason}"
                is_err = True
            else:
                try:
                    resp = requests.get(
                        source_url,
                        timeout=5,
                        allow_redirects=False,
                        headers={"User-Agent": "DevNest-Fetcher/2.0"},
                    )
                    result = resp.text[:8000]
                    is_err = False

                    # 스니펫 저장
                    name = detect_name(source_url, snippet_name)
                    lang = detect_lang(source_url, result)
                    SNIPPETS.insert(0, {
                        "name":    name,
                        "url":     source_url,
                        "lang":    lang,
                        "size":    format_size(len(result.encode())),
                        "content": result,
                    })

                except Exception as e:
                    result = f"요청 실패: {str(e)}"
                    is_err = True

    return render_template(
        "fetch.html",
        **tmpl_ctx(payload, "fetch"),
        result=result,
        is_err=is_err,
        fetched_url=fetched_url,
        snippet_name=snippet_name,
        snippets=SNIPPETS,
    )


@app.route("/admin")
@login_required
def admin(payload):
    if payload.get("role") != "admin":
        return render_template("403.html", **tmpl_ctx(payload, "admin")), 403
    return render_template("admin.html", **tmpl_ctx(payload, "admin"))


@app.route("/admin/flag")
@login_required
def admin_flag(payload):
    if payload.get("role") != "admin":
        return redirect(url_for("admin"))
    return render_template(
        "admin_flag.html",
        **tmpl_ctx(payload, "admin"),
        flag=FLAG,
    )


@app.route("/docs")
@login_required
def docs(payload):
    return render_template("docs.html", **tmpl_ctx(payload, "docs"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
