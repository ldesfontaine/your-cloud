#!/usr/bin/env python3
"""Drive the installed Tauri App through the external LAB WebDriver."""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import re
import time
import urllib.error
import urllib.request


def request(base_url: str, method: str, path: str, payload: object | None = None) -> object:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            document = json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"WebDriver {method} {path} failed: {error.code} {detail}") from error
    return document.get("value")


class Driver:
    def __init__(self, base_url: str, application: str):
        self.base_url = base_url.rstrip("/")
        response = request(
            self.base_url,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {"tauri:options": {"application": application}}
                }
            },
        )
        self.session_id = response["sessionId"]

    def close(self) -> None:
        request(self.base_url, "DELETE", f"/session/{self.session_id}")

    def execute(self, script: str) -> object:
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": []},
        )

    def resize(self, width: int, height: int) -> dict[str, int]:
        value = request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/window/rect",
            {"x": 0, "y": 0, "width": width, "height": height},
        )
        time.sleep(0.25)
        return value

    def press_tab(self) -> None:
        request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/actions",
            {
                "actions": [
                    {
                        "type": "key",
                        "id": "keyboard",
                        "actions": [
                            {"type": "keyDown", "value": "\ue004"},
                            {"type": "keyUp", "value": "\ue004"},
                        ],
                    }
                ]
            },
        )

    def screenshot(self, path: pathlib.Path) -> None:
        encoded = request(
            self.base_url,
            "GET",
            f"/session/{self.session_id}/screenshot",
        )
        path.write_bytes(base64.b64decode(encoded, validate=True))


METRICS_SCRIPT = r"""
const root = document.documentElement;
const body = document.body;
const rootStyle = getComputedStyle(root);
const controls = [...document.querySelectorAll('button, input:not([type="checkbox"]), select, textarea')]
  .filter((element) => {
    const rectangle = element.getBoundingClientRect();
    return rectangle.width > 0 && rectangle.height > 0;
  });
return {
  title: document.title,
  href: location.href,
  heading: document.querySelector('h1')?.textContent ?? null,
  inner_width: innerWidth,
  inner_height: innerHeight,
  client_width: root.clientWidth,
  scroll_width: root.scrollWidth,
  body_scroll_width: body.scrollWidth,
  horizontal_overflow: root.scrollWidth > root.clientWidth + 1,
  theme_dark: matchMedia('(prefers-color-scheme: dark)').matches,
  color_canvas: rootStyle.getPropertyValue('--color-canvas').trim(),
  color_text: rootStyle.getPropertyValue('--color-text').trim(),
  body_font: getComputedStyle(body).fontFamily,
  root_font_size: rootStyle.fontSize,
  minimum_control_height: controls.length
    ? Math.min(...controls.map((element) => element.getBoundingClientRect().height))
    : null,
  remote_resources: performance.getEntriesByType('resource')
    .map((entry) => entry.name)
    .filter((name) => /^https?:/u.test(name)),
};
"""


def assert_layout(metrics: dict[str, object], expected_theme: str) -> None:
    assert metrics["title"] == "Your Cloud"
    assert metrics["href"] == "tauri://localhost"
    assert metrics["heading"] == "Accès local"
    assert metrics["horizontal_overflow"] is False
    assert metrics["remote_resources"] == []
    assert "Inter" in metrics["body_font"]
    assert metrics["minimum_control_height"] >= 44
    expected_dark = expected_theme == "dark"
    assert metrics["theme_dark"] is expected_dark
    expected_colors = (
        {"color_canvas": "#0b1120", "color_text": "#f8fafc"}
        if expected_dark
        else {"color_canvas": "#fafaf9", "color_text": "#111827"}
    )
    for key, value in expected_colors.items():
        assert metrics[key] == value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--application", default="/usr/bin/your-cloud-app")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--expected-theme", choices=("light", "dark"), required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]{1,32}", args.label):
        raise SystemExit("label must be a short lowercase identifier")

    args.output.mkdir(parents=True, exist_ok=True)
    driver = Driver(args.base_url, args.application)
    report: dict[str, object] = {
        "schema_version": 1,
        "application": args.application,
        "theme": args.expected_theme,
        "instrumentation": "tauri-driver 2.0.6 with WebKitWebDriver",
    }
    try:
        for _ in range(40):
            heading = driver.execute("return document.querySelector('h1')?.textContent ?? null;")
            if heading == "Accès local":
                break
            time.sleep(0.25)
        else:
            raise AssertionError("the installed App did not render its local access view")

        desktop_rect = driver.resize(1280, 800)
        desktop = driver.execute(METRICS_SCRIPT)
        assert desktop_rect["width"] == 1280 and desktop_rect["height"] == 800
        assert_layout(desktop, args.expected_theme)
        driver.screenshot(args.output / f"{args.label}-1280x800.png")

        driver.press_tab()
        focus = driver.execute(
            "const e=document.activeElement; return {tag:e.tagName, "
            "focus_visible:e.matches(':focus-visible'), text:e.textContent?.trim() ?? ''};"
        )
        assert focus["tag"] in {"BUTTON", "INPUT", "TEXTAREA", "SELECT", "A"}
        assert focus["focus_visible"] is True

        compact_rect = driver.resize(640, 560)
        compact = driver.execute(METRICS_SCRIPT)
        assert compact_rect["width"] == 640 and compact_rect["height"] == 560
        assert_layout(compact, args.expected_theme)
        driver.screenshot(args.output / f"{args.label}-640x560.png")

        driver.execute("document.documentElement.style.fontSize='32px'; return true;")
        zoomed = driver.execute(METRICS_SCRIPT)
        assert zoomed["root_font_size"] == "32px"
        assert zoomed["horizontal_overflow"] is False
        driver.screenshot(args.output / f"{args.label}-640x560-text-200.png")
        driver.execute("document.documentElement.style.fontSize=''; return true;")

        minimum_rect = driver.resize(500, 400)
        assert minimum_rect["width"] >= 640 and minimum_rect["height"] >= 560

        report.update(
            {
                "desktop": desktop,
                "compact": compact,
                "text_zoom_200": zoomed,
                "keyboard_focus": focus,
                "minimum_window_after_500x400_request": minimum_rect,
                "result": "pass",
            }
        )
    finally:
        driver.close()

    report_path = args.output / f"{args.label}-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"ui_proof={args.label} result=pass desktop=1280x800 compact=640x560 "
        "text_zoom=200 keyboard_focus=visible remote_resources=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
