# TestPilot AI

TestPilot AI is a local, database-backed QA workspace. The server uses Python's standard library and SQLite; the UI is served locally from this folder. Website scans and automation runs use the installed Python Playwright and pytest packages. They report unavailable when a required browser or package is missing.

## Start

1. Copy `.env.example` to `.env` and fill in the AI settings if you want AI test-case generation. Keep `.env` private.
2. Install the packages in `requirements.txt` in your Python environment. Install Playwright browser binaries with `python -m playwright install chromium` when needed.
3. Run `python app.py` and open `http://127.0.0.1:8765`.

## Docker hosting

The included `Dockerfile` listens on the host-provided port, stores SQLite data and artifacts under `/data`, installs Chromium, and requires `APP_PASSWORD` in production mode. Use a host that supports a persistent disk mounted at `/data`, HTTPS, and one running app instance (SQLite is single-instance storage). Put `APP_PASSWORD` and `AI_API_KEY` in the host's secret settings; do not commit a `.env` file.

For a local container preview, copy `.env.example` to `.env`, set `APP_PASSWORD` and `DEPLOYMENT_MODE=production`, then run `docker build -t testpilot-ai .` and `docker run --env-file .env -p 10000:10000 -v testpilot-data:/data testpilot-ai`. The app refuses to start in production mode without a password, restricts browser actions to signed-in sessions, and rate-limits password attempts.

AI generation uses an OpenAI-compatible chat completions endpoint. Configure `AI_API_KEY`, `AI_BASE_URL`, and `AI_MODEL` in the server environment. Keys are never sent to the browser. A generated test case is always marked Not Run until a real automation execution updates it.

The app generates a private `.execution-token` for a future remote worker integration. A separate remote worker is not included. Local execution accepts same-origin requests and requires an explicit authorization confirmation in the UI. Runs execute reviewed Python test files with a timeout. Scans require the user to confirm they are authorized to test the target; private, loopback, and link-local destinations are blocked.

## Included modules

Dashboard, projects/environments, requirements, test cases, automation scripts, suites, website scanner, test runs, bugs, reports, and settings. Records are persisted in `testpilot.db`; scans publish the current URL and page counts while running. Pytest runs save JUnit XML and logs, and the built-in `page` fixture captures screenshots for failures.

This is a functional local foundation. Multi-user identity, remote worker isolation, PDF export, mobile emulation, visual baseline comparison, and full axe-core integration are not configured in this starter and are identified in the UI rather than represented as completed checks.
