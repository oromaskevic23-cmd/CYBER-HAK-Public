"""True Chromium smoke of a locally hosted IMPERIAL EYE source atlas.

No external camera links are opened. This is NOT face recognition or live feed
ingestion; the production authentication backend remains intentionally absent.
"""
from __future__ import annotations

from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from playwright.sync_api import sync_playwright


ROOT=Path("security/imperial_eye").resolve()


class SilentHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return


def main():
    handler=partial(SilentHandler,directory=str(ROOT))
    server=ThreadingHTTPServer(("127.0.0.1",0),handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    port=server.server_address[1]
    requests=[]
    try:
        with sync_playwright() as driver:
            browser=driver.chromium.launch(headless=True)
            try:
                context=browser.new_context(accept_downloads=False,service_workers="block")
                try:
                    def block_external(route):
                        if route.request.url.startswith("http://127.0.0.1:"+str(port)+"/"):
                            route.continue_()
                        else:
                            requests.append(route.request.url)
                            route.abort("blockedbyclient")
                    context.route("**/*",block_external)
                    page=context.new_page()
                    try:
                        page.goto(f"http://127.0.0.1:{port}/web/",wait_until="networkidle")
                        page.locator("#count").get_by_text("2",exact=True).wait_for()
                        assert page.locator(".source-card").count()==2
                        assert page.locator("video,iframe,img").count()==0
                        page.fill("#source-filter","Fintraffic")
                        assert page.locator(".source-card").count()==1
                        page.fill("#source-filter","no-matching-agency")
                        assert page.locator(".source-card").count()==0
                        page.fill("#source-filter","")
                        assert page.locator(".source-card").count()==2
                        page.locator("#owner-check").click()
                        assert "Access denied" in page.locator("#passkey-status").inner_text()
                        page.locator("#owner-auth").click()
                        page.locator("#passkey-status").get_by_text("Access denied",exact=False).wait_for()
                        assert page.locator(".source-card a").count()==2
                        assert len(requests)==0
                        screenshot=page.screenshot(full_page=True)
                        assert screenshot.startswith(b"\x89PNG\r\n\x1a\n")
                        print(json.dumps({
                            "status":"CHROMIUM_UI_LOCAL_SMOKE_PASS",
                            "engine":browser.version,
                            "official_portal_entries_rendered":2,
                            "filter_tested":True,
                            "owner_auth_without_backend":"DENIED",
                            "face_templates_collected":0,
                            "third_party_streams_played":0,
                            "external_network_requests":len(requests),
                            "screenshot_sha256":hashlib.sha256(screenshot).hexdigest(),
                            "production_owner_session":False,
                            "face_recognition_implemented":False
                        },sort_keys=True,indent=2))
                    finally:
                        page.close()
                finally:
                    context.close()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__=="__main__":
    main()
