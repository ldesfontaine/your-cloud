#!/usr/bin/env python3
"""Smoke-test the installed Windows Console renderer without exposing generated secrets."""

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
    def __init__(self, base_url: str, debugger_address: str):
        self.base_url = base_url.rstrip("/")
        response = request(
            self.base_url,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "webview2",
                        "ms:edgeChromium": True,
                        "ms:edgeOptions": {"debuggerAddress": debugger_address},
                    }
                }
            },
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

    def execute_async(
        self,
        script: str,
        arguments: list[object] | None = None,
        timeout_seconds: int = 45,
    ) -> object:
        request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/timeouts",
            {"script": timeout_seconds * 1000},
        )
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/async",
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
      try {
        const resource = new URL(name);
        if (!['http:', 'https:'].includes(resource.protocol)) return false;
        return !new Set([location.origin, 'http://ipc.localhost']).has(resource.origin);
      }
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
    assert metrics["remote_resources"] == [], metrics["remote_resources"]
    assert "Inter" in str(metrics["body_font"])
    assert metrics["minimum_control_height"] is not None
    assert float(metrics["minimum_control_height"]) >= 44


def css_pixels(value: object) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)px", str(value))
    if match is None:
        raise AssertionError(f"expected a CSS pixel value, got {value!r}")
    return float(match.group(1))


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

    compact_root_font_size = css_pixels(compact["root_font_size"])
    zoomed_root_font_size = compact_root_font_size * 2
    try:
        driver.execute(
            "document.documentElement.style.setProperty("
            "'font-size',`${arguments[0]}px`,'important'); return true;",
            [zoomed_root_font_size],
        )
        driver.wait(
            "return Math.abs(parseFloat(getComputedStyle(document.documentElement).fontSize)"
            "-arguments[0])<0.01;",
            arguments=[zoomed_root_font_size],
        )
        zoomed = driver.execute(METRICS_SCRIPT)
        assert isinstance(zoomed, dict)
        actual_zoomed_root_font_size = css_pixels(zoomed["root_font_size"])
        assert abs(actual_zoomed_root_font_size - zoomed_root_font_size) < 0.01, {
            "expected": zoomed_root_font_size,
            "actual": actual_zoomed_root_font_size,
        }
        assert zoomed["horizontal_overflow"] is False
        driver.screenshot(output / f"windows-{slug}-640x560-text-200.png")
    finally:
        driver.execute(
            "document.documentElement.style.removeProperty('font-size'); return true;"
        )
        driver.wait(
            "return Math.abs(parseFloat(getComputedStyle(document.documentElement).fontSize)"
            "-arguments[0])<0.01;",
            arguments=[compact_root_font_size],
        )
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


BOOTSTRAP_IPC_PROOF_SCRIPT = r"""
const done = arguments[arguments.length - 1];
(async () => {
  const internals = window.__TAURI_INTERNALS__;
  if (!internals || typeof internals.invoke !== 'function') {
    throw new Error('tauri-invoke-unavailable');
  }
  const invoke = internals.invoke.bind(internals);
  const hostKey = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const target = Object.freeze({
    host: 'controller.example.test',
    port: 22,
    username: 'infra_admin',
    host_key_sha256: hostKey,
    access_kind: 'administrator',
  });
  const expectedSessionKeys = [
    'actions',
    'expires_in_seconds',
    'lifecycle',
    'mode',
    'request_id',
    'schema_version',
    'step',
    'target',
  ];
  const expectedTargetKeys = [
    'access_kind',
    'host',
    'host_key_sha256',
    'port',
    'username',
  ];
  const fail = (label) => { throw new Error(label); };
  const settled = (promise) => Promise.resolve(promise).then(
    (value) => ({ status: 'fulfilled', value }),
    (reason) => ({ status: 'rejected', reason }),
  );
  const assertCodeOnly = (result, expectedCode, label, forbiddenValue = null) => {
    if (result.status !== 'rejected') fail(`${label}-was-not-rejected`);
    const error = result.reason;
    if (!error || typeof error !== 'object' || Array.isArray(error)) {
      fail(`${label}-error-is-not-an-object`);
    }
    const keys = Object.keys(error).sort();
    if (keys.length !== 1 || keys[0] !== 'code' || error.code !== expectedCode) {
      fail(`${label}-error-is-not-code-only`);
    }
    if (forbiddenValue !== null && JSON.stringify(error).includes(forbiddenValue)) {
      fail(`${label}-echoed-sensitive-input`);
    }
    return error.code;
  };
  const assertSession = (session, mode, label) => {
    if (!session || typeof session !== 'object' || Array.isArray(session)) {
      fail(`${label}-session-is-not-an-object`);
    }
    if (JSON.stringify(Object.keys(session).sort()) !== JSON.stringify(expectedSessionKeys)) {
      fail(`${label}-session-fields-drifted`);
    }
    if (session.schema_version !== 1 || session.mode !== mode ||
        session.step !== 'personal_access' ||
        session.lifecycle !== 'awaiting_native_assistant' ||
        !Number.isInteger(session.expires_in_seconds) ||
        session.expires_in_seconds < 1 || session.expires_in_seconds > 300 ||
        !Array.isArray(session.actions) || session.actions.length !== 1 ||
        session.actions[0] !== 'audit_target_read_only' ||
        typeof session.request_id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(session.request_id)) {
      fail(`${label}-session-contract-refused`);
    }
    if (!session.target || typeof session.target !== 'object' ||
        JSON.stringify(Object.keys(session.target).sort()) !== JSON.stringify(expectedTargetKeys) ||
        JSON.stringify(session.target) !== JSON.stringify(target)) {
      fail(`${label}-target-drifted`);
    }
    return session.request_id;
  };
  const start = (mode, extra = {}) => invoke('start_bootstrap', {
    input: { mode, target, ...extra },
  });
  const status = (requestId) => invoke('bootstrap_status', { requestId });
  const cancel = (requestId) => invoke('cancel_bootstrap', { requestId });

  const unknownCanary = 'unknown-field-must-not-be-reflected';
  const unknown = await settled(start('create', { unexpected: unknownCanary }));
  const unknownCode = assertCodeOnly(unknown, 'invalid_input', 'unknown-field', unknownCanary);

  const sensitiveCanary = 'sensitive-value-must-not-be-reflected';
  const sensitive = await settled(start('create', { password: sensitiveCanary }));
  const sensitiveCode = assertCodeOnly(
    sensitive,
    'invalid_input',
    'sensitive-field',
    sensitiveCanary,
  );

  const concurrent = await Promise.all([
    settled(start('create')),
    settled(start('create')),
  ]);
  const winners = concurrent.filter((result) => result.status === 'fulfilled');
  const busy = concurrent.filter((result) => result.status === 'rejected');
  if (winners.length !== 1 || busy.length !== 1) fail('concurrent-create-cardinality-drifted');
  const busyCode = assertCodeOnly(busy[0], 'bootstrap_busy', 'concurrent-create');
  const createRequestId = assertSession(winners[0].value, 'create', 'create');

  const forged = await settled(status('ffeeddccbbaa99887766554433221100'));
  const forgedCode = assertCodeOnly(forged, 'bootstrap_request_refused', 'forged-id');

  const cancelled = await settled(cancel(createRequestId));
  if (cancelled.status !== 'fulfilled' || cancelled.value !== null) {
    fail('active-create-cancellation-failed');
  }
  const cancellationReplay = await settled(cancel(createRequestId));
  const cancellationReplayCode = assertCodeOnly(
    cancellationReplay,
    'bootstrap_request_refused',
    'cancel-replay',
  );

  const replaceStart = await settled(start('replace'));
  if (replaceStart.status !== 'fulfilled') fail('replace-start-was-rejected');
  const replaceRequestId = assertSession(replaceStart.value, 'replace', 'replace');

  let replacePolls = 0;
  let terminalCode = null;
  const terminalDeadline = performance.now() + 15000;
  while (performance.now() < terminalDeadline) {
    replacePolls += 1;
    const polled = await settled(status(replaceRequestId));
    if (polled.status === 'fulfilled') {
      assertSession(polled.value, 'replace', 'replace-poll');
      await new Promise((resolve) => setTimeout(resolve, 25));
      continue;
    }
    terminalCode = assertCodeOnly(
      polled,
      'native_assistant_unavailable',
      'replace-terminal',
    );
    break;
  }
  if (terminalCode === null) fail('replace-helper-did-not-fail-closed');

  const terminalReplay = await settled(status(replaceRequestId));
  const terminalReplayCode = assertCodeOnly(
    terminalReplay,
    'bootstrap_request_refused',
    'terminal-replay',
  );

  return {
    invoke_surface: 'window.__TAURI_INTERNALS__.invoke',
    commands: ['start_bootstrap', 'bootstrap_status', 'cancel_bootstrap'],
    modes: ['create', 'replace'],
    session_schema_version: 1,
    lifecycle_observed: 'awaiting_native_assistant',
    create_terminal: 'cancelled_by_test',
    replace_terminal: terminalCode,
    replace_poll_count: replacePolls,
    concurrency: 'one_active_one_bootstrap_busy',
    request_ids_included_in_proof_artifact: false,
    target_included_in_public_error_or_proof_artifact: false,
    sensitive_input_included_in_public_error_or_proof_artifact: false,
    error_shape: 'code-only',
    rejected_codes: {
      unknown_field: unknownCode,
      sensitive_field: sensitiveCode,
      concurrent_start: busyCode,
      forged_id: forgedCode,
      cancellation_replay: cancellationReplayCode,
      terminal_replay: terminalReplayCode,
    },
    success_claimed: false,
  };
})().then(
  (proof) => done({ ok: true, proof }),
  (error) => done({
    ok: false,
    failure: error instanceof Error ? error.message : 'unknown-bootstrap-proof-failure',
  }),
);
"""


def exercise_live_bootstrap_ipc(driver: Driver) -> dict[str, object]:
    outcome = driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT)
    assert isinstance(outcome, dict)
    assert outcome.get("ok") is True, outcome.get("failure", "bootstrap IPC proof failed")
    proof = outcome.get("proof")
    assert isinstance(proof, dict)
    assert proof.get("success_claimed") is False
    assert proof.get("request_ids_included_in_proof_artifact") is False
    assert proof.get("target_included_in_public_error_or_proof_artifact") is False
    assert proof.get("sensitive_input_included_in_public_error_or_proof_artifact") is False
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--application", required=True)
    parser.add_argument("--debugger-address", required=True)
    parser.add_argument("--session-ready-marker", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    driver = Driver(args.base_url, args.debugger_address)
    args.session_ready_marker.touch(exist_ok=False)
    report: dict[str, object] = {
        "schema_version": 1,
        "application": args.application,
        "platform": "windows",
        "instrumentation": (
            "tauri-driver 2.0.6 proxying matching Microsoft Edge WebDriver "
            "attached to the installed WebView2"
        ),
        "debugger_transport": "ephemeral loopback TCP, removed before normal launch",
        "proof_scope": "installed-native-smoke",
        "controller_exercised": False,
        "native_minimum_window_enforcement": "not_exercised_by_webview_webdriver",
        "post_association_views": "not_executed_without_real_controller",
        "views": {},
    }
    try:
        driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Accès local", 60)
        views = report["views"]
        assert isinstance(views, dict)
        views["local-access"] = capture_view(driver, args.output, "local-access", "Accès local")

        initialize_real_windows_vault(driver)
        report["bootstrap_tauri_ipc"] = exercise_live_bootstrap_ipc(driver)
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

        report.update(
            {
                "real_windows_vault_initialized": True,
                "bootstrap_business_result": "not_implemented_fail_closed",
                "result": "pass",
            }
        )
    finally:
        driver.close()

    (args.output / "windows-webview2-smoke.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "PASS: installed Windows WebView2 rendered three pre-association views at "
        "1280x800 and 640x560, initialized the real Windows vault, kept 200% text "
        "responsive, exercised bounded Tauri bootstrap IPC without claiming business "
        "success and exposed no remote resource"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
