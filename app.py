from __future__ import annotations

import json
import os
import base64
import hmac
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from hashlib import sha256
from http.cookies import SimpleCookie
from importlib.util import find_spec
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(ROOT))).expanduser().resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "testpilot.db"
ARTIFACTS = DATA_DIR / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)
COLLECTIONS = {"projects", "requirements", "test-cases", "scripts", "suites", "scans", "findings", "runs", "bugs", "activities", "baselines"}
LOCK = threading.RLock()
JOBS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def envfile():
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    token_path = DATA_DIR / ".execution-token"
    token = os.environ.get("EXECUTION_TOKEN", "").strip()
    if not token and token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        token = secrets.token_urlsafe(32)
        token_path.write_text(token, encoding="utf-8")
    os.environ["EXECUTION_TOKEN"] = token


def db():
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT NOT NULL, project_id TEXT, data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS records_kind_project ON records(kind,project_id)")
        con.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, created_at TEXT NOT NULL)")


def add_event(label: str):
    with db() as con:
        con.execute("INSERT INTO events(label,created_at) VALUES(?,?)", (label[:200], now()))


def row_obj(row):
    if not row:
        return None
    d = json.loads(row["data"])
    d.update(id=row["id"], type=row["kind"], createdAt=row["created_at"], updatedAt=row["updated_at"])
    return d


def list_records(kind, query=None):
    query = query or {}
    clauses, vals = ["kind=?"], [kind]
    for key in ("projectId", "status", "severity"):
        if query.get(key):
            clauses.append("json_extract(data, '$." + key + "')=?")
            vals.append(query[key])
    with db() as con:
        rows = con.execute("SELECT * FROM records WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC LIMIT 500", vals).fetchall()
    return [row_obj(r) for r in rows]


def get_record(ident):
    with db() as con:
        return row_obj(con.execute("SELECT * FROM records WHERE id=?", (ident,)).fetchone())


def save_record(kind, data, ident=None):
    ident = ident or secrets.token_hex(5).upper()
    stamp = now()
    prev = get_record(ident)
    created = prev["createdAt"] if prev else stamp
    payload = {k: v for k, v in data.items() if k not in ("id", "type", "createdAt", "updatedAt")}
    if kind == "test-cases" and not payload.get("caseKey"):
        payload["caseKey"] = "TC-" + secrets.token_hex(3).upper()
    if kind == "bugs" and not payload.get("bugKey"):
        payload["bugKey"] = "BUG-" + secrets.token_hex(3).upper()
    with db() as con:
        con.execute("INSERT INTO records(id,kind,project_id,data,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,project_id=excluded.project_id,data=excluded.data,updated_at=excluded.updated_at", (ident, kind, payload.get("projectId"), json.dumps(payload), created, stamp))
    return row_obj({"id": ident, "kind": kind, "data": json.dumps(payload), "created_at": created, "updated_at": stamp})


def delete_record(ident):
    with db() as con:
        cur = con.execute("DELETE FROM records WHERE id=?", (ident,))
        return cur.rowcount > 0


def dashboard():
    kinds = {k: list_records(k) for k in ("projects", "requirements", "test-cases", "scripts", "suites", "scans", "findings", "runs", "bugs")}
    runs = kinds["runs"]
    tests = [t for r in runs for t in r.get("results", [])]
    statuses = {s: sum(1 for x in tests if x.get("status") == s) for s in ("passed", "failed", "skipped", "blocked")}
    recent = sorted(runs + kinds["scans"], key=lambda x: x.get("updatedAt", ""), reverse=True)[:8]
    open_bugs = [b for b in kinds["bugs"] if b.get("status", "Open") not in ("Closed", "Fixed")]
    return {"projects": len(kinds["projects"]), "requirements": len(kinds["requirements"]), "testCases": len(kinds["test-cases"]), "automationTests": len(kinds["scripts"]), "scans": len(kinds["scans"]), "pagesScanned": sum(x.get("coverage", {}).get("scanned", 0) for x in kinds["scans"]), "statuses": statuses, "passRate": round(100 * statuses["passed"] / max(1, statuses["passed"] + statuses["failed"]), 1), "bugsBySeverity": {s: sum(1 for b in open_bugs if b.get("severity") == s) for s in ("Critical", "High", "Medium", "Low")}, "latest": recent}


def ai_generate(req):
    key = os.environ.get("AI_API_KEY", "").strip()
    if not key:
        raise RuntimeError("AI provider is not configured. Set AI_API_KEY in the server environment, then restart TestPilot AI.")
    base = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("AI_MODEL", "gpt-4o-mini")
    prompt = "Return only a JSON array of test cases with fields title,description,preconditions,steps (array of strings),testData,expectedResult,priority (Low/Medium/High),testType,automationStatus. Include relevant positive, negative, boundary, validation, accessibility, responsive, security and regression coverage. Never claim execution. Requirement:\n" + str(req.get("description", "")) + "\nAcceptance criteria:\n" + str(req.get("acceptanceCriteria", ""))
    body = json.dumps({"model": model, "temperature": 0.2, "messages": [{"role": "system", "content": "You create practical software QA cases. Output valid JSON only."}, {"role": "user", "content": prompt}]}).encode()
    request = urllib.request.Request(base + "/chat/completions", data=body, headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.loads(response.read())
        content = result["choices"][0]["message"]["content"]
        cases = json.loads(content[content.find("["):content.rfind("]") + 1])
        if not isinstance(cases, list) or not cases:
            raise ValueError("No cases were returned")
        return cases[:30]
    except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("AI generation failed: " + str(exc))


def safe_target(raw):
    from ipaddress import ip_address
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid http or https website URL.")
    host = parsed.hostname.lower().rstrip(".")
    if host in ("localhost", "metadata.google.internal") or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local and internal network targets are blocked by the scanner.")
    try:
        ip = ip_address(host)
        if not ip.is_global:
            raise ValueError("Private, loopback, and link-local IP targets are blocked.")
    except ValueError as e:
        if "blocked" in str(e):
            raise
    return parsed


def run_scan(scan_id, conf):
    scan = get_record(scan_id)
    save_record("scans", {**scan, **conf, "status": "Running", "progress": {"currentUrl": conf["url"], "discovered": 0, "scanned": 0, "errors": []}}, scan_id)
    progress_dir = ARTIFACTS / scan_id
    progress_dir.mkdir(exist_ok=True)
    progress_file = progress_dir / "progress.json"
    stdout_file = progress_dir / "scan-output.json"
    stderr_file = progress_dir / "scan-error.log"
    worker_conf = {**conf, "_progressFile": str(progress_file)}
    try:
        with stdout_file.open("w", encoding="utf-8") as out, stderr_file.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen([sys.executable, str(ROOT / "scanner_worker.py"), json.dumps(worker_conf)], cwd=ROOT, stdout=out, stderr=err, text=True)
            deadline = time.time() + 240
            while proc.poll() is None and time.time() < deadline:
                try:
                    progress = json.loads(progress_file.read_text(encoding="utf-8"))
                    current = get_record(scan_id) or scan
                    coverage = {**current.get("coverage", {}), **progress.get("coverage", {})}
                    save_record("scans", {**current, "status": "Running", "progress": progress, "coverage": coverage}, scan_id)
                except (OSError, json.JSONDecodeError):
                    pass
                time.sleep(.4)
            if proc.poll() is None:
                proc.kill(); proc.wait()
                payload = {**conf, "status": "Timed out", "error": "Scan exceeded its four-minute time limit.", "coverage": {"discovered": 0, "scanned": 0, "failed": 0, "skipped": 0, "blocked": 0, "pages": []}}
            elif proc.returncode != 0:
                payload = {**conf, "status": "Unavailable", "error": stderr_file.read_text(encoding="utf-8")[-3000:] or "The Playwright scan process failed.", "coverage": {"discovered": 0, "scanned": 0, "failed": 0, "skipped": 0, "blocked": 0, "pages": []}}
            else:
                payload = json.loads(stdout_file.read_text(encoding="utf-8"))
            for finding in payload.pop("findings", []):
                finding["projectId"] = conf.get("projectId")
                finding["scanId"] = scan_id
                save_record("findings", finding)
            if payload.get("status") not in ("Timed out", "Unavailable"):
                payload.update(status="Completed", finishedAt=now())
    except Exception as e:
        payload = {**conf, "status": "Unavailable", "error": str(e)[:1000], "coverage": {"discovered": 0, "scanned": 0, "failed": 0, "skipped": 0, "blocked": 0, "pages": []}}
    save_record("scans", payload, scan_id)
    add_event("Website scan " + str(payload.get("status", "finished")).lower())


def run_tests(run_id, conf):
    run = get_record(run_id)
    started = time.time()
    script_ids = conf.get("scriptIds", [])
    scripts = [get_record(x) for x in script_ids]
    scripts = [s for s in scripts if s]
    if not scripts:
        save_record("runs", {**run, "status": "Blocked", "error": "No saved scripts were selected.", "results": [], "counts": {"passed": 0, "failed": 0, "skipped": 0, "blocked": 0}}, run_id)
        return
    try:
        import pytest  # noqa: F401
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception as e:
        save_record("runs", {**run, "status": "Execution service unavailable", "error": "Install execution dependencies with: python -m pip install -r requirements.txt; then install a browser with: python -m playwright install chromium. " + str(e), "results": [], "counts": {"passed": 0, "failed": 0, "skipped": 0, "blocked": len(scripts)}}, run_id)
        return
    dest = ARTIFACTS / run_id
    dest.mkdir(exist_ok=True)
    (dest / "conftest.py").write_text('''import pytest
from pathlib import Path
from playwright.sync_api import sync_playwright

@pytest.fixture
def page():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        current = browser.new_page(viewport={"width": 1366, "height": 768})
        yield current
        browser.close()

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        current = item.funcargs.get("page")
        if current:
            folder = Path(item.config.rootpath) / "screenshots"
            folder.mkdir(exist_ok=True)
            current.screenshot(path=str(folder / (item.name + ".png")), full_page=True)
''', encoding="utf-8")
    results, files = [], []
    for script in scripts:
        name = "test_" + secrets.token_hex(5) + ".py"
        path = dest / name
        source = script.get("code", "")
        path.write_text(source, encoding="utf-8")
        log_path = dest / (name + ".log")
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rA", "--tb=short", "--junitxml=" + str(dest / (name + ".xml")), str(path)], cwd=dest, capture_output=True, text=True, timeout=90, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            log = (proc.stdout + "\n" + proc.stderr)[-10000:]
            status = "passed" if proc.returncode == 0 else "failed"
            reason = "" if proc.returncode == 0 else log[-2000:]
        except subprocess.TimeoutExpired as exc:
            status, reason, log = "blocked", "Test exceeded its 90-second time limit.", str(exc)
        log_path.write_text(log, encoding="utf-8")
        files.append({"name": log_path.name, "url": "/artifacts/" + run_id + "/" + log_path.name})
        files.append({"name": name + ".xml", "url": "/artifacts/" + run_id + "/" + name + ".xml"}) if (dest / (name + ".xml")).exists() else None
        for evidence in (dest / "screenshots").glob("*.png") if (dest / "screenshots").exists() else []:
            files.append({"name": evidence.name, "url": "/artifacts/" + run_id + "/screenshots/" + evidence.name})
        results.append({"scriptId": script["id"], "testCaseId": script.get("testCaseId"), "title": script.get("title", "Automation test"), "status": status, "failureReason": reason, "log": log[-3000:]})
        if script.get("testCaseId"):
            tc = get_record(script["testCaseId"])
            if tc:
                save_record("test-cases", {**tc, "automationStatus": "Executed", "lastExecutionStatus": status, "lastRunId": run_id}, tc["id"])
    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("passed", "failed", "skipped", "blocked")}
    payload = {**run, "status": "Completed", "finishedAt": now(), "durationSeconds": round(time.time() - started, 2), "results": results, "counts": counts, "artifacts": files}
    save_record("runs", payload, run_id)
    add_event("Automation run finished: " + str(counts["passed"]) + " passed, " + str(counts["failed"]) + " failed")


class Handler(BaseHTTPRequestHandler):
    server_version = "TestPilot/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, status=200, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = min(int(self.headers.get("Content-Length", "0")), 1_000_000)
        return json.loads(self.rfile.read(length) or b"{}")

    def same_origin(self):
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc.lower() != self.headers.get("Host", "").lower():
            self.send_json({"error": "Cross-origin requests are not allowed."}, 403)
            return False
        return True

    def authenticated(self):
        secret = os.environ.get("APP_PASSWORD", "")
        if not secret:
            return os.environ.get("DEPLOYMENT_MODE") != "production"
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookies.get("tp_session").value
            issued, signature = token.split(".", 1)
            issued_at = int(issued)
            if issued_at > int(time.time()) + 60 or int(time.time()) - issued_at > 43200:
                return False
            expected = base64.urlsafe_b64encode(hmac.new(secret.encode(), ("testpilot:" + issued).encode(), sha256).digest()).decode().rstrip("=")
            return hmac.compare_digest(signature, expected)
        except Exception:
            return False

    def session_cookie(self, clear=False):
        if clear:
            value = "tp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        else:
            issued = str(int(time.time()))
            signature = base64.urlsafe_b64encode(hmac.new(os.environ["APP_PASSWORD"].encode(), ("testpilot:" + issued).encode(), sha256).digest()).decode().rstrip("=")
            value = "tp_session=" + issued + "." + signature + "; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict"
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            value += "; Secure"
        return value

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_json({"ok": True})
            return
        if path == "/api/auth/status":
            required = bool(os.environ.get("APP_PASSWORD")) or os.environ.get("DEPLOYMENT_MODE") == "production"
            self.send_json({"required": required, "authenticated": self.authenticated() if required else True})
            return
        if path.startswith("/api/") and path != "/api/health" and not self.authenticated():
            self.send_json({"error": "Sign in to continue."}, 401)
            return
        if path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        if path == "/api/health":
            self.send_json({"ok": True, "aiConfigured": bool(os.environ.get("AI_API_KEY")), "executionConfigured": bool(find_spec("playwright") and find_spec("pytest")), "playwrightInstalled": find_spec("playwright") is not None, "pytestInstalled": find_spec("pytest") is not None})
            return
        if path == "/api/dashboard":
            self.send_json(dashboard()); return
        if path == "/api/settings":
            self.send_json({"aiConfigured": bool(os.environ.get("AI_API_KEY")), "aiModel": os.environ.get("AI_MODEL", "gpt-4o-mini"), "aiBaseUrl": os.environ.get("AI_BASE_URL", "https://api.openai.com/v1"), "executionConfigured": bool(find_spec("playwright") and find_spec("pytest")), "playwrightInstalled": find_spec("playwright") is not None, "pytestInstalled": find_spec("pytest") is not None}); return
        if path.startswith("/api/"):
            parts = path.split("/")
            kind = parts[2]
            if kind not in COLLECTIONS:
                self.send_json({"error": "Unknown collection"}, 404); return
            if len(parts) > 3:
                obj = get_record(parts[3])
                if not obj or obj["type"] != kind:
                    self.send_json({"error": "Not found"}, 404)
                else:
                    self.send_json(obj)
                return
            from urllib.parse import parse_qs
            q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            self.send_json(list_records(kind, q)); return
        if path.startswith("/artifacts/"):
            if not self.authenticated():
                self.send_json({"error": "Sign in to continue."}, 401); return
            rel = path[len("/artifacts/"):]
            target = (ARTIFACTS / rel).resolve()
            if ARTIFACTS.resolve() not in target.parents or not target.is_file():
                self.send_json({"error": "Artifact not found"}, 404); return
            content = target.read_bytes()
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content); return
        static_files = {"/": ROOT / "index.html", "/index.html": ROOT / "index.html", "/app.js": ROOT / "app.js", "/styles.css": ROOT / "styles.css"}
        file = static_files.get(path)
        if not file or not file.is_file():
            self.send_json({"error": "Not found"}, 404); return
        content = file.read_bytes()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8" if file.suffix == ".html" else "text/" + ("css" if file.suffix == ".css" else "javascript") + "; charset=utf-8"); self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content)

    def do_POST(self):
        if not self.same_origin():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/api/auth/login":
                ip = self.client_address[0]
                recent = [t for t in LOGIN_ATTEMPTS.get(ip, []) if time.time() - t < 600]
                if len(recent) >= 12:
                    self.send_json({"error": "Too many sign-in attempts. Wait a few minutes and try again."}, 429)
                    return
                recent.append(time.time()); LOGIN_ATTEMPTS[ip] = recent
                secret = os.environ.get("APP_PASSWORD", "")
                if not secret or not hmac.compare_digest(str(data.get("password", "")), secret):
                    self.send_json({"error": "Password is incorrect."}, 401)
                    return
                LOGIN_ATTEMPTS.pop(ip, None)
                self.send_json({"ok": True}, headers={"Set-Cookie": self.session_cookie()})
                return
            if path == "/api/auth/logout":
                self.send_json({"ok": True}, headers={"Set-Cookie": self.session_cookie(clear=True)})
                return
            if path.startswith("/api/") and not self.authenticated():
                self.send_json({"error": "Sign in to continue."}, 401)
                return
            parts = path.split("/")
            if len(parts) == 3 and parts[1] == "api" and parts[2] in COLLECTIONS:
                saved = save_record(parts[2], data)
                add_event("Created " + parts[2] + " record")
                self.send_json(saved, 201)
                return
            if path == "/api/ai/generate":
                req = get_record(data.get("requirementId", "")) if data.get("requirementId") else data
                if not req:
                    self.send_json({"error": "Requirement not found"}, 404); return
                cases = ai_generate(req)
                saved = []
                existing = {" ".join(str(x.get("title", "")).casefold().split()) for x in list_records("test-cases") if x.get("requirementId") == req.get("id", data.get("requirementId"))}
                for case in cases:
                    title_key = " ".join(str(case.get("title", "")).casefold().split())
                    if not title_key or title_key in existing:
                        continue
                    case.update(projectId=req.get("projectId"), requirementId=req.get("id", data.get("requirementId")), automationStatus="Not Run", status="Draft", caseKey="TC-" + secrets.token_hex(3).upper())
                    saved.append(save_record("test-cases", case))
                    existing.add(title_key)
                add_event("AI generated " + str(len(saved)) + " test cases")
                self.send_json({"cases": saved}); return
            if path == "/api/scans/start":
                if data.get("authorized") is not True:
                    self.send_json({"error": "Confirm that you are authorized to scan this website."}, 400); return
                try:
                    parsed = safe_target(data.get("url", ""))
                except ValueError as e:
                    self.send_json({"error": str(e)}, 400); return
                conf = {"url": parsed.geturl(), "projectId": data.get("projectId"), "environment": data.get("environment", "QA"), "maxPages": max(1, min(50, int(data.get("maxPages", 10)))), "maxDepth": max(0, min(4, int(data.get("maxDepth", 2)))), "viewport": data.get("viewport", "desktop"), "options": data.get("options", {}), "includePatterns": data.get("includePatterns", ""), "excludePatterns": data.get("excludePatterns", ""), "authorized": True}
                ident = "SC-" + secrets.token_hex(4).upper()
                scan = save_record("scans", {**conf, "status": "Queued", "coverage": {"discovered": 0, "scanned": 0, "failed": 0, "skipped": 0, "blocked": 0, "pages": []}}, ident)
                threading.Thread(target=run_scan, args=(ident, conf), daemon=True).start()
                self.send_json(scan, 202); return
            if path == "/api/runs/start":
                if data.get("authorized") is not True:
                    self.send_json({"error": "Confirm that you are authorized to run the selected tests against this environment."}, 400); return
                ident = "RUN-" + secrets.token_hex(4).upper()
                run = save_record("runs", {"projectId": data.get("projectId"), "environment": data.get("environment", "QA"), "suiteId": data.get("suiteId"), "status": "Queued", "startedAt": now(), "results": [], "counts": {"passed": 0, "failed": 0, "skipped": 0, "blocked": 0}}, ident)
                threading.Thread(target=run_tests, args=(ident, data), daemon=True).start()
                self.send_json(run, 202); return
            if path == "/api/export/csv":
                kind = data.get("kind", "runs")
                if kind not in COLLECTIONS:
                    self.send_json({"error": "Unknown collection"}, 400); return
                import csv, io
                rows = list_records(kind)
                keys = sorted({k for row in rows for k in row.keys()})
                output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=keys, extrasaction="ignore"); writer.writeheader()
                for row in rows: writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
                content = output.getvalue().encode("utf-8-sig")
                self.send_response(200); self.send_header("Content-Type", "text/csv; charset=utf-8"); self.send_header("Content-Disposition", 'attachment; filename="testpilot-' + kind + '.csv"'); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content); return
            self.send_json({"error": "Unknown action"}, 404)
        except Exception as e:
            self.send_json({"error": str(e)[:1000]}, 500)

    def do_PUT(self):
        if not self.same_origin():
            return
        parts = urlparse(self.path).path.split("/")
        if not self.authenticated():
            self.send_json({"error": "Sign in to continue."}, 401); return
        if len(parts) != 4 or parts[1] != "api" or parts[2] not in COLLECTIONS:
            self.send_json({"error": "Not found"}, 404); return
        try:
            data = self.body()
            self.send_json(save_record(parts[2], data, parts[3]))
        except Exception as e: self.send_json({"error": str(e)}, 400)

    def do_DELETE(self):
        if not self.same_origin():
            return
        parts = urlparse(self.path).path.split("/")
        if not self.authenticated():
            self.send_json({"error": "Sign in to continue."}, 401); return
        if len(parts) != 4 or parts[1] != "api" or parts[2] not in COLLECTIONS:
            self.send_json({"error": "Not found"}, 404); return
        if delete_record(parts[3]):
            add_event("Deleted " + parts[2] + " record")
            self.send_json({"ok": True})
        else: self.send_json({"error": "Not found"}, 404)

if __name__ == "__main__":
    envfile(); init_db()
    port = int(os.environ.get("PORT", "8765"))
    if os.environ.get("DEPLOYMENT_MODE") == "production" and not os.environ.get("APP_PASSWORD", "").strip():
        raise SystemExit("APP_PASSWORD must be set before starting in production mode.")
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"TestPilot AI running at http://{host}:{port}")
    print("AI provider:", "configured" if os.environ.get("AI_API_KEY") else "not configured")
    print("Execution token stored in .execution-token; keep this local file private.")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
