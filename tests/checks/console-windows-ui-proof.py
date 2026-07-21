#!/usr/bin/env python3
"""Prove the installed Windows Console renderer without exposing generated secrets."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import pathlib
import re
import time
import urllib.error
import urllib.request


def request(
    base_url: str,
    method: str,
    path: str,
    payload: object | None = None,
    timeout_seconds: int = 30,
) -> object:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
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
            {"capabilities": {"alwaysMatch": {"tauri:options": {"application": application}}}},
            timeout_seconds=120,
        )
        self.session_id = response["sessionId"]
        time.sleep(0.5)

    def safe_request(self, method: str, path: str, payload: object) -> object:
        for attempt in range(2):
            try:
                return request(self.base_url, method, path, payload)
            except (http.client.RemoteDisconnected, ConnectionResetError):
                if attempt == 1:
                    raise
                time.sleep(0.25)
        raise AssertionError("unreachable WebDriver retry state")

    def close(self) -> None:
        request(self.base_url, "DELETE", f"/session/{self.session_id}")

    def execute(self, script: str, arguments: list[object] | None = None) -> object:
        return self.safe_request(
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": arguments or []},
        )

    def wait(
        self,
        script: str,
        expected: object = True,
        seconds: int = 30,
        arguments: list[object] | None = None,
    ) -> object:
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            last = self.execute(script, arguments)
            if last == expected:
                return last
            time.sleep(0.25)
        raise AssertionError(f"condition not reached; last value was {last!r}")

    def element(self, strategy: str, value: str) -> str:
        result = self.safe_request(
            "POST",
            f"/session/{self.session_id}/element",
            {"using": strategy, "value": value},
        )
        identifier = result.get("element-6066-11e4-a52e-4f735466cecf")
        if not identifier:
            raise AssertionError(f"element not found with {strategy}: {value}")
        return identifier

    def click(self, identifier: str) -> None:
        request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/element/{identifier}/click",
            {},
        )

    def click_button(self, label: str) -> None:
        self.click(
            self.element(
                "xpath",
                f"//button[normalize-space(.)={json.dumps(label, ensure_ascii=False)}]",
            )
        )

    def fill_fields(self, fields: dict[str, str]) -> None:
        result = self.execute(
            "for(const [selector,value] of Object.entries(arguments[0])){"
            "const element=document.querySelector(selector);"
            "if(!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement))"
            "return false;"
            "const prototype=element instanceof HTMLTextAreaElement"
            "?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
            "const previous=element.value;"
            "Object.getOwnPropertyDescriptor(prototype,'value').set.call(element,value);"
            "if(element._valueTracker) element._valueTracker.setValue(previous);"
            "element.dispatchEvent(new Event('input',{bubbles:true}));} return true;",
            [fields],
        )
        assert result is True

    def resize(self, width: int, height: int) -> dict[str, int]:
        value = request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/window/rect",
            {"x": 0, "y": 0, "width": width, "height": height},
        )
        time.sleep(0.25)
        return value

    def screenshot(self, path: pathlib.Path) -> None:
        encoded = request(self.base_url, "GET", f"/session/{self.session_id}/screenshot")
        path.write_bytes(base64.b64decode(encoded, validate=True))

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


METRICS_SCRIPT = r"""
const root = document.documentElement;
const body = document.body;
const controls = [...document.querySelectorAll('button, input:not([type="checkbox"]), select, textarea')]
  .filter((element) => {
    const rectangle = element.getBoundingClientRect();
    return rectangle.width > 0 && rectangle.height > 0;
  });
return {
  title: document.title,
  href: location.href,
  origin: location.origin,
  heading: document.querySelector('h1')?.textContent ?? null,
  inner_width: innerWidth,
  inner_height: innerHeight,
  client_width: root.clientWidth,
  scroll_width: root.scrollWidth,
  horizontal_overflow: root.scrollWidth > root.clientWidth + 1,
  theme_dark: matchMedia('(prefers-color-scheme: dark)').matches,
  body_font: getComputedStyle(body).fontFamily,
  root_font_size: getComputedStyle(root).fontSize,
  minimum_control_height: controls.length
    ? Math.min(...controls.map((element) => element.getBoundingClientRect().height))
    : null,
  remote_resources: performance.getEntriesByType('resource')
    .map((entry) => entry.name)
    .filter((name) => {
      try { return new URL(name).origin !== location.origin; }
      catch { return true; }
    }),
};
"""


def assert_metrics(metrics: dict[str, object], heading: str) -> None:
    assert metrics["title"] == "Your Cloud"
    assert metrics["origin"] == "http://tauri.localhost"
    assert metrics["href"] == "http://tauri.localhost/"
    assert metrics["heading"] == heading
    assert metrics["horizontal_overflow"] is False
    assert metrics["remote_resources"] == []
    assert "Inter" in str(metrics["body_font"])
    assert metrics["minimum_control_height"] is not None
    assert float(metrics["minimum_control_height"]) >= 44


def capture_view(
    driver: Driver,
    output: pathlib.Path,
    slug: str,
    heading: str,
) -> dict[str, object]:
    desktop_rectangle = driver.resize(1280, 800)
    assert desktop_rectangle["width"] == 1280 and desktop_rectangle["height"] == 800
    desktop = driver.execute(METRICS_SCRIPT)
    assert isinstance(desktop, dict)
    assert_metrics(desktop, heading)
    driver.screenshot(output / f"windows-{slug}-1280x800.png")

    driver.execute("document.body.focus(); return true;")
    driver.press_tab()
    focus = driver.execute(
        "const element=document.activeElement; return {tag:element.tagName,"
        "visible:element.matches(':focus-visible')};"
    )
    assert focus["tag"] in {"BUTTON", "INPUT", "TEXTAREA", "SELECT", "A"}
    assert focus["visible"] is True

    compact_rectangle = driver.resize(640, 560)
    assert compact_rectangle["width"] == 640 and compact_rectangle["height"] == 560
    compact = driver.execute(METRICS_SCRIPT)
    assert isinstance(compact, dict)
    assert_metrics(compact, heading)
    driver.screenshot(output / f"windows-{slug}-640x560.png")

    driver.execute("document.documentElement.style.fontSize='32px'; return true;")
    zoomed = driver.execute(METRICS_SCRIPT)
    assert isinstance(zoomed, dict)
    assert zoomed["root_font_size"] == "32px"
    assert zoomed["horizontal_overflow"] is False
    driver.screenshot(output / f"windows-{slug}-640x560-text-200.png")
    driver.execute("document.documentElement.style.fontSize=''; return true;")
    return {
        "desktop": desktop,
        "compact": compact,
        "text_zoom_200": zoomed,
        "keyboard_focus": focus,
    }


def initialize_real_windows_vault(driver: Driver) -> None:
    driver.click_button("Générer les secrets locaux")
    driver.wait("return document.querySelectorAll('.yc-secret').length===2;")
    secrets = driver.execute(
        "return [...document.querySelectorAll('.yc-secret')].map((e)=>e.textContent.trim());"
    )
    assert isinstance(secrets, list) and len(secrets) == 2
    phrase, recovery = secrets
    assert isinstance(phrase, str) and len(phrase.encode("utf-8")) <= 96
    assert len(phrase.split(" ")) == 6
    assert isinstance(recovery, str) and re.fullmatch(r"(?:[A-Z2-7]{6}-){8}[A-Z2-7]{6}", recovery)
    driver.fill_fields(
        {
            "#confirm-unlock-phrase": phrase,
            "#confirm-recovery-code": recovery,
        }
    )
    driver.click(driver.element("css selector", "input[type=checkbox]"))
    driver.wait("return document.querySelector('input[type=checkbox]').checked;")
    driver.click_button("Confirmer et créer le coffre")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures", 60)
    residual = driver.execute(
        "return {secrets:document.querySelectorAll('.yc-secret').length,"
        "local:Object.keys(localStorage),session:Object.keys(sessionStorage),"
        "passwords:[...document.querySelectorAll('input[type=password]')].map((e)=>e.value)};"
    )
    assert residual == {"secrets": 0, "local": [], "session": [], "passwords": []}


def install_visual_fixture(driver: Driver) -> tuple[str, str]:
    controller_id = "11111111-1111-4111-8111-111111111111"
    infrastructure_id = "22222222-2222-4222-8222-222222222222"
    association = {
        "controller_id": controller_id,
        "infrastructure_id": infrastructure_id,
        "infrastructure_label": "Infrastructure Windows CI",
        "origin": "https://10.42.0.10:9443",
        "device_status": "active",
        "certificate_expires_at": "2027-01-01T00:00:00Z",
    }
    infrastructure = {
        "schema_version": 1,
        "controller_id": controller_id,
        "infrastructure_id": infrastructure_id,
        "initialized": True,
        "label": "Infrastructure Windows CI",
        "inventory_revision": 7,
    }
    machines = {
        "schema_version": 1,
        "controller_id": controller_id,
        "infrastructure_id": infrastructure_id,
        "inventory_revision": 7,
        "relay_status": "available",
        "relay_snapshot_at": "2026-07-21T00:00:00Z",
        "machines": [
            {
                "machine_id": "machine-windows-ci-1",
                "label": "Machine principale",
                "enrollment_status": "active",
                "observation_status": "recent",
                "observation": {
                    "profile": "host-health.v1",
                    "sequence": 42,
                    "observed_at": "2026-07-21T00:00:00Z",
                    "received_at": "2026-07-21T00:00:01Z",
                    "observed_time_warning": False,
                    "continuity": "complete",
                    "gap_summary": None,
                    "health": {
                        "uptime": {"status": "ok", "uptime_seconds": 3600, "error": None},
                        "memory": {
                            "status": "ok",
                            "total_bytes": 8589934592,
                            "available_bytes": 4294967296,
                            "error": None,
                        },
                        "rootfs": {
                            "status": "ok",
                            "total_bytes": 137438953472,
                            "available_bytes": 68719476736,
                            "error": None,
                        },
                    },
                },
            },
            {
                "machine_id": "machine-windows-ci-2",
                "label": "<img src=x onerror=window.__ycHostileExecuted=true>",
                "enrollment_status": "active",
                "observation_status": "old",
                "observation": {
                    "profile": "host-health.v1",
                    "sequence": 41,
                    "observed_at": "2026-07-20T20:00:00Z",
                    "received_at": "2026-07-20T20:00:01Z",
                    "observed_time_warning": True,
                    "continuity": "gapped",
                    "gap_summary": {
                        "range_count": 1,
                        "dropped_count": 3,
                        "first_sequence": 38,
                        "last_sequence": 40,
                    },
                    "health": {
                        "uptime": {"status": "error", "uptime_seconds": None, "error": "source_unavailable"},
                        "memory": {"status": "error", "total_bytes": None, "available_bytes": None, "error": "source_invalid"},
                        "rootfs": {"status": "error", "total_bytes": None, "available_bytes": None, "error": "source_unavailable"},
                    },
                },
            },
        ],
    }
    installed = driver.execute(
        "const internals=window.__TAURI_INTERNALS__;"
        "if(!internals || typeof internals.invoke!=='function') return false;"
        "const original=internals.invoke.bind(internals);"
        "const fixture=arguments[0];"
        "window.__ycHostileExecuted=false;"
        "internals.invoke=async(command,args,options)=>{"
        "if(command==='pair_controller') return fixture.association;"
        "if(command==='read_infrastructure') return fixture.infrastructure;"
        "if(command==='read_machines') return fixture.machines;"
        "return original(command,args,options);};"
        "return true;",
        [{"association": association, "infrastructure": infrastructure, "machines": machines}],
    )
    assert installed is True
    return controller_id, infrastructure_id


def pair_visual_fixture(driver: Driver) -> None:
    driver.fill_fields(
        {
            "#pair-origin": "https://10.42.0.10:9443",
            "#pair-temporary-origin": "https://10.42.0.10:9444",
            "#pair-controller-id": "11111111-1111-4111-8111-111111111111",
            "#pair-infrastructure-id": "22222222-2222-4222-8222-222222222222",
            "#pair-spki": "a" * 64,
            "#pair-ca": "-----BEGIN CERTIFICATE-----\nWINDOWS-CI-VISUAL-FIXTURE\n-----END CERTIFICATE-----",
            "#pair-window-id": "33333333-3333-4333-8333-333333333333",
            "#pair-window-code": "visual-fixture-only",
            "#pair-recovery-code": "visual-fixture-only",
        }
    )
    driver.click_button("Vérifier et associer")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Synthèse", 60)
    driver.wait(
        "const refresh=[...document.querySelectorAll('button')]"
        ".find((e)=>e.textContent.trim()==='Actualiser');"
        "return refresh?.getAttribute('aria-busy')==='false';",
        True,
        60,
    )


def navigate(driver: Driver, label: str, heading: str) -> None:
    driver.click_button(label)
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", heading)
    if heading in {"Synthèse", "Parc", "Observations"}:
        driver.wait(
            "const refresh=[...document.querySelectorAll('button')]"
            ".find((e)=>e.textContent.trim()==='Actualiser');"
            "return refresh?.getAttribute('aria-busy')==='false';",
            True,
            60,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--application", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    driver = Driver(args.base_url, args.application)
    report: dict[str, object] = {
        "schema_version": 1,
        "application": args.application,
        "platform": "windows",
        "instrumentation": "tauri-driver 2.0.6 with Microsoft Edge WebDriver and WebView2",
        "fixture_scope": "renderer-only IPC responses after real Windows vault initialization",
        "views": {},
    }
    try:
        driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Accès local", 60)
        views = report["views"]
        assert isinstance(views, dict)
        views["local-access"] = capture_view(driver, args.output, "local-access", "Accès local")

        initialize_real_windows_vault(driver)
        views["infrastructures"] = capture_view(
            driver, args.output, "infrastructures", "Infrastructures"
        )
        driver.click_button("Associer")
        driver.wait(
            "return document.querySelector('h1')?.textContent ?? null;",
            "Association ou récupération",
        )
        views["association"] = capture_view(
            driver,
            args.output,
            "association",
            "Association ou récupération",
        )

        controller_id, infrastructure_id = install_visual_fixture(driver)
        pair_visual_fixture(driver)
        views["summary"] = capture_view(driver, args.output, "summary", "Synthèse")
        navigate(driver, "Parc", "Parc")
        views["fleet"] = capture_view(driver, args.output, "fleet", "Parc")
        hostile = driver.execute(
            "return {executed:window.__ycHostileExecuted===true,"
            "element:document.querySelector('img[src=x]')!==null,"
            "text:document.body.textContent.includes('<img src=x onerror=window.__ycHostileExecuted=true>')};"
        )
        assert hostile == {"executed": False, "element": False, "text": True}
        navigate(driver, "Observations", "Observations")
        views["observations"] = capture_view(
            driver, args.output, "observations", "Observations"
        )
        navigate(driver, "Profil et sessions", "Profil et sessions")
        views["profile"] = capture_view(
            driver, args.output, "profile", "Profil et sessions"
        )

        minimum_rectangle = driver.resize(500, 400)
        assert minimum_rectangle["width"] >= 640 and minimum_rectangle["height"] >= 560
        report.update(
            {
                "controller_id": controller_id,
                "infrastructure_id": infrastructure_id,
                "hostile_label_rendered_as_text": True,
                "minimum_window_after_500x400_request": minimum_rectangle,
                "result": "pass",
            }
        )
    finally:
        driver.close()

    (args.output / "windows-ui-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "PASS: Windows WebView2 rendered seven views at 1280x800 and 640x560, "
        "kept 200% text responsive, exposed no remote resource and escaped hostile content"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
