"""Bounded, read-only Playwright website scanner used by the local app."""
import json
import os
import re
import socket
import sys
import urllib.request
import urllib.error
from pathlib import Path
import xml.etree.ElementTree as ET
from collections import deque
from ipaddress import ip_address
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse


def normalize(raw):
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        return None
    return urlunparse((p.scheme, p.netloc.lower(), p.path or "/", "", p.query, ""))


def is_public(url):
    try:
        host = urlparse(url).hostname
        if not host or host == "localhost" or host.endswith((".local", ".localhost", ".internal")):
            return False
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return bool(answers) and all(ip_address(x[4][0]).is_global for x in answers)
    except Exception:
        return False


def ai_spellcheck(page_texts):
    key = os.environ.get("AI_API_KEY", "").strip()
    if not key:
        return [], "AI provider is not configured"
    base = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("AI_MODEL", "gpt-4o-mini")
    text = "\n\n".join(f"PAGE: {url}\n{text[:1100]}" for url, text in page_texts[:20])[:18000]
    if not text.strip():
        return [], "No English page text was available"
    prompt = "Proofread only the visible page text for clear English spelling mistakes. Ignore proper names, product names, URLs, code, and non-English text. Do not report grammar/style preferences. Return only JSON array; each item has url, wrong, suggested, context. Include only high-confidence actual misspellings, maximum 30. Text:\n" + text
    body = json.dumps({"model": model, "temperature": 0, "messages": [{"role": "system", "content": "You are a conservative spell checker. Output valid JSON only."}, {"role": "user", "content": prompt}]}).encode()
    request = urllib.request.Request(base + "/chat/completions", data=body, headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            result = json.loads(response.read())
        content = result["choices"][0]["message"]["content"]
        items = json.loads(content[content.find("["):content.rfind("]") + 1])
        return (items[:30] if isinstance(items, list) else []), f"Completed · first {min(len(page_texts),20)} English pages"
    except Exception as exc:
        return [], "Spelling review unavailable: " + str(exc)[:180]


def scan(conf):
    from playwright.sync_api import sync_playwright
    start = normalize(conf["url"])
    if not start or not is_public(start):
        raise ValueError("Target could not be confirmed as a public website; private and unresolved hosts are blocked.")
    origin = urlparse(start)
    start_domain = origin.hostname
    limit, max_depth = conf["maxPages"], conf["maxDepth"]
    include = [x.strip() for x in conf.get("includePatterns", "").splitlines() if x.strip()]
    exclude = [x.strip() for x in conf.get("excludePatterns", "").splitlines() if x.strip()]
    w, h = {"mobile": (375, 812), "tablet": (768, 1024), "desktop": (1366, 768), "wide": (1920, 1080)}.get(conf.get("viewport"), (1366, 768))
    opts = conf.get("options", {})
    queue, seen = deque([(start, 0)]), set()
    pages, findings, failed, skipped, blocked, page_texts, evidence_by_url = [], [], 0, 0, 0, [], {}
    def publish(current_url="", current_error=""):
        target = conf.get("_progressFile")
        if not target: return
        snapshot = {"currentUrl": current_url, "discovered": len(seen)+len(queue), "coverage": {"discovered": len(seen)+len(queue), "scanned": sum(1 for x in pages if not x.get("error")), "failed": failed, "skipped": skipped, "blocked": blocked, "pages": pages[:100]}, "errors": ([current_error] if current_error else [])}
        progress_path = Path(target)
        temporary = progress_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(snapshot), encoding="utf-8")
        os.replace(temporary, progress_path)
    publish(start)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": w, "height": h}, ignore_https_errors=False)
        robots_disallow, sitemap_urls = [], []
        try:
            robots = context.request.get(urljoin(start, "/robots.txt"), timeout=5000)
            if robots.status < 400:
                active = False
                for raw_line in robots.text().splitlines():
                    line = raw_line.split("#", 1)[0].strip()
                    if ":" not in line: continue
                    name, value = [x.strip() for x in line.split(":", 1)]
                    if name.lower() == "user-agent": active = value == "*"
                    elif active and name.lower() == "disallow" and value: robots_disallow.append(value)
                    elif name.lower() == "sitemap" and (u := normalize(value)) and urlparse(u).hostname == start_domain: sitemap_urls.append(u)
        except Exception:
            pass
        for sitemap in sitemap_urls[:3]:
            try:
                response = context.request.get(sitemap, timeout=8000)
                if response.status >= 400: continue
                root = ET.fromstring(response.body())
                for node in root.iter():
                    if node.tag.lower().endswith("loc") and node.text:
                        link = normalize(node.text.strip())
                        if link and urlparse(link).hostname == start_domain and link not in seen and len(queue) < 100:
                            queue.append((link, min(1, max_depth)))
            except Exception:
                continue
        page = context.new_page()
        console_errors, request_errors = [], []
        page.on("console", lambda msg: console_errors.append(msg.text[:300]) if msg.type == "error" else None)
        page.on("requestfailed", lambda req: request_errors.append({"url": req.url[:500], "error": (req.failure or "request failed")[:300]}))
        # Every top-level URL and redirect must remain on the user's public domain.
        def guard(route):
            request_url = route.request.url
            request_host = urlparse(request_url).hostname
            is_document = route.request.resource_type == "document"
            if is_public(request_url) and (not is_document or request_host == start_domain):
                route.continue_()
            else:
                route.abort()
        page.route("**/*", guard)
        while queue and len(pages) < limit:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            publish(url)
            if urlparse(url).hostname != start_domain or not is_public(url):
                skipped += 1
                publish(url, "Blocked or skipped unsafe URL")
                continue
            if any(urlparse(url).path.startswith(path) for path in robots_disallow):
                skipped += 1
                publish(url, "Disallowed by robots.txt")
                continue
            if any(re.search(pat, url) for pat in exclude) or (include and not any(re.search(pat, url) for pat in include)):
                skipped += 1
                publish(url, "Excluded by URL pattern")
                continue
            console_errors.clear(); request_errors.clear()
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=18000)
                page.wait_for_timeout(300)
                status = response.status if response else None
                final_url = normalize(page.url) or url
                if urlparse(final_url).hostname != start_domain:
                    skipped += 1
                    continue
                title = page.title()
                data = page.evaluate("""() => {
                  const visible = e => { const r=e.getBoundingClientRect(),s=getComputedStyle(e); return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'; };
                  const links=[...document.querySelectorAll('a[href]')].map(a=>({href:a.href,text:(a.innerText||a.getAttribute('aria-label')||'').trim(),rel:a.rel||''}));
                  const imgs=[...document.images].map(i=>({src:i.currentSrc||i.src,alt:i.getAttribute('alt'),loaded:i.complete&&i.naturalWidth>0}));
                  const controls=[...document.querySelectorAll('button,input,select,textarea,[role=button]')].map(e=>({tag:e.tagName,type:e.type||'',label:(e.getAttribute('aria-label')||e.labels?.[0]?.innerText||e.innerText||e.placeholder||'').trim(),required:e.required||e.getAttribute('aria-required')==='true',visible:visible(e)}));
                  const forms=[...document.forms].map(f=>({action:f.action,method:f.method,fields:f.elements.length}));
                  const size={scrollWidth:document.documentElement.scrollWidth,clientWidth:document.documentElement.clientWidth,scrollHeight:document.documentElement.scrollHeight};
                  return {links,imgs,controls,forms,size,metaDescription:!!document.querySelector('meta[name=description]'),headings:[...document.querySelectorAll('h1,h2,h3')].map(e=>({tag:e.tagName,text:e.innerText.trim().slice(0,120)})),text:document.body?.innerText?.slice(0,2200)||'',lang:document.documentElement.lang||''};
                }""")
                page_entry = {"url": final_url, "status": status, "title": title, "depth": depth}
                pages.append(page_entry)
                if opts.get("spelling", False) and (data.get("lang", "").lower().startswith("en") or not data.get("lang")):
                    page_texts.append((final_url, data.get("text", "")))
                def finding(category, severity, title_, detail, element=""):
                    findings.append({"category": category, "severity": severity, "title": title_, "description": detail, "url": final_url, "element": element, "status": "Suspected", "reproductionSteps": ["Open " + final_url, "Inspect the affected page or element"]})
                if status and status >= 400:
                    finding("Page load", "High" if status >= 500 else "Medium", "Page returned HTTP " + str(status), "The page responded with HTTP " + str(status) + ".")
                if not title.strip(): finding("Metadata", "Low", "Page title is missing", "The document title is empty.")
                if not data["metaDescription"]: finding("Metadata", "Low", "Meta description is missing", "No meta description was found.")
                if data["size"]["scrollWidth"] > data["size"]["clientWidth"] + 2: finding("Responsive", "Medium", "Horizontal overflow detected", "The document is wider than the viewport at the selected scan size.", str(data["size"]))
                if opts.get("responsive", True):
                    original_viewport = {"width": w, "height": h}
                    for viewport_name, vw, vh in (("mobile", 375, 812), ("tablet", 768, 1024), ("desktop", 1366, 768)):
                        try:
                            page.set_viewport_size({"width": vw, "height": vh})
                            page.wait_for_timeout(100)
                            dimensions = page.evaluate("({scrollWidth:document.documentElement.scrollWidth,clientWidth:document.documentElement.clientWidth})")
                            if dimensions["scrollWidth"] > dimensions["clientWidth"] + 2:
                                finding("Responsive", "Medium", "Horizontal overflow at " + viewport_name, f"The page is wider than the {viewport_name} viewport ({vw} px).", str(dimensions))
                        except Exception:
                            pass
                    page.set_viewport_size(original_viewport)
                for image in data["imgs"]:
                    if not image["loaded"]: finding("Images", "Medium", "Image did not load", "The browser reports an image with no natural dimensions.", image["src"])
                    if image["alt"] is None: finding("Accessibility", "Low", "Image has no alt attribute", "Automated check: image is missing its alt attribute.", image["src"])
                for control in data["controls"]:
                    if not control["label"] and control["visible"]: finding("Accessibility", "Medium", "Control has no accessible label", "Automated name check found a visible form control or button without a detectable label.", control["tag"]+":"+control["type"])
                if data["forms"]:
                    finding("Forms", "Info", "Form detected; submission not performed", "The scanner records the form but does not submit it to avoid changing data or contacting third parties.", json.dumps(data["forms"]))
                if opts.get("console", True):
                    for err in console_errors[:10]: finding("Console", "Medium", "Browser console error", err)
                if opts.get("links", True):
                    for link in data["links"]:
                        href = normalize(link["href"])
                        if href and urlparse(href).hostname == start_domain and href not in seen and depth < max_depth and not re.search(r"logout|signout|sign-out|delete|remove|purchase|checkout|payment|submit", link["href"], re.I):
                            queue.append((href, depth+1))
                if opts.get("visual", False) and len(evidence_by_url) < 20:
                    artifact_dir = conf.get("_artifactDir")
                    if artifact_dir:
                        try:
                            os.makedirs(artifact_dir, exist_ok=True)
                            image_name = f"page-{len(pages):03}.png"
                            page.screenshot(path=str(Path(artifact_dir) / image_name), full_page=True, timeout=6000)
                            evidence_url = "/artifacts/" + Path(artifact_dir).name + "/" + image_name
                            evidence_by_url[final_url] = evidence_url
                            for item in findings:
                                if item.get("url") == final_url and not item.get("screenshotUrl"):
                                    item["screenshotUrl"] = evidence_url
                        except Exception:
                            pass
                if depth >= max_depth:
                    pass
                publish(final_url)
            except Exception as exc:
                msg = str(exc)[:300]
                if "ERR_BLOCKED_BY_CLIENT" in msg or "net::ERR_BLOCKED_BY_RESPONSE" in msg:
                    blocked += 1
                else:
                    failed += 1
                pages.append({"url": url, "status": None, "error": msg, "depth": depth})
                publish(url, msg)
        browser.close()
    spelling_status = "Not requested"
    if opts.get("spelling", False):
        spelling_items, spelling_status = ai_spellcheck(page_texts)
        for item in spelling_items:
            page_url = item.get("url") or (page_texts[0][0] if page_texts else start)
            if urlparse(page_url).hostname != start_domain:
                continue
            wrong, suggested, context = str(item.get("wrong", ""))[:80], str(item.get("suggested", ""))[:80], str(item.get("context", ""))[:240]
            if not wrong or not suggested:
                continue
            finding = {"category": "Spelling", "severity": "Low", "title": "Possible spelling issue: " + wrong, "description": f"Possible misspelling '{wrong}' → '{suggested}'. Context: {context}", "url": page_url, "element": context, "status": "Needs review", "reproductionSteps": ["Open " + page_url, "Find the text: " + context]}
            if page_url in evidence_by_url:
                finding["screenshotUrl"] = evidence_by_url[page_url]
            findings.append(finding)
    return {"url": start, "spellingReview": spelling_status, "viewport": conf.get("viewport", "desktop"), "finishedAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="seconds"), "coverage": {"discovered": len(seen)+len(queue), "scanned": sum(1 for x in pages if not x.get("error")), "failed": failed, "skipped": skipped, "blocked": blocked, "notScannedDueToLimit": len(queue), "depth": max((x.get("depth",0) for x in pages), default=0), "pages": pages}, "findings": findings}


if __name__ == "__main__":
    print(json.dumps(scan(json.loads(sys.argv[1]))))
