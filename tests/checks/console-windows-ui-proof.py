#!/usr/bin/env python3
"""Smoke-test an installed Console renderer without exposing generated secrets."""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import ctypes
import http.client
import json
import pathlib
import re
import struct
import subprocess
import time
import urllib.error
import urllib.request
import zlib


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_SCREENSHOT_ATTEMPTS = 5
SCREENSHOT_RETRY_DELAY_SECONDS = 0.5
MIN_SCREENSHOT_DISTINCT_RGB = 256
MAX_SCREENSHOT_DOMINANT_RGB_RATIO = 0.995
MAX_SCREENSHOT_EXACT_BLACK_RATIO = 0.10


class ScreenshotRasterError(AssertionError):
    """Reject a screenshot whose encoded raster cannot support visual proof."""


def paeth_predictor(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def inspect_png_raster(
    payload: bytes,
    expected_width: int,
    expected_height: int,
) -> dict[str, object]:
    if not payload.startswith(PNG_SIGNATURE):
        raise ScreenshotRasterError("capture is not a PNG")

    cursor = len(PNG_SIGNATURE)
    header: tuple[int, int, int, int, int, int, int] | None = None
    compressed = bytearray()
    saw_image_data = False
    saw_end = False
    while cursor < len(payload):
        if len(payload) - cursor < 12:
            raise ScreenshotRasterError("capture PNG chunk is truncated")
        chunk_length = struct.unpack_from(">I", payload, cursor)[0]
        chunk_end = cursor + 12 + chunk_length
        if chunk_end > len(payload):
            raise ScreenshotRasterError("capture PNG chunk exceeds the payload")
        chunk_type = payload[cursor + 4 : cursor + 8]
        chunk_payload = payload[cursor + 8 : cursor + 8 + chunk_length]
        expected_crc = struct.unpack_from(">I", payload, cursor + 8 + chunk_length)[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_payload, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ScreenshotRasterError("capture PNG chunk CRC is invalid")

        if header is None and chunk_type != b"IHDR":
            raise ScreenshotRasterError("capture PNG does not start with IHDR")
        if chunk_type == b"IHDR":
            if header is not None or chunk_length != 13:
                raise ScreenshotRasterError("capture PNG IHDR is duplicated or invalid")
            header = struct.unpack(">IIBBBBB", chunk_payload)
        elif chunk_type == b"IDAT":
            if header is None or saw_end:
                raise ScreenshotRasterError("capture PNG IDAT order is invalid")
            saw_image_data = True
            compressed.extend(chunk_payload)
        elif chunk_type == b"IEND":
            if chunk_length != 0 or not saw_image_data:
                raise ScreenshotRasterError("capture PNG IEND is invalid")
            saw_end = True
            cursor = chunk_end
            break
        elif chunk_type[0] & 0x20 == 0:
            raise ScreenshotRasterError("capture PNG contains an unsupported critical chunk")
        cursor = chunk_end

    if header is None or not saw_end or cursor != len(payload):
        raise ScreenshotRasterError("capture PNG is incomplete or has trailing data")
    width, height, bit_depth, color_type, compression, filtering, interlace = header
    if width != expected_width or height != expected_height:
        raise ScreenshotRasterError("capture PNG dimensions differ from the requested view")
    if (
        bit_depth != 8
        or color_type not in {2, 6}
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        raise ScreenshotRasterError("capture PNG encoding is outside the RGB8 contract")

    bytes_per_pixel = 3 if color_type == 2 else 4
    row_length = width * bytes_per_pixel
    expected_length = (row_length + 1) * height
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(bytes(compressed), expected_length + 1)
    except zlib.error as error:
        raise ScreenshotRasterError("capture PNG image data is invalid") from error
    if (
        len(raw) != expected_length
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
    ):
        raise ScreenshotRasterError("capture PNG decompressed length is invalid")

    previous = bytearray(row_length)
    colors: collections.Counter[tuple[int, int, int]] = collections.Counter()
    exact_black_pixels = 0
    raw_cursor = 0
    for _ in range(height):
        filter_type = raw[raw_cursor]
        raw_cursor += 1
        filtered = raw[raw_cursor : raw_cursor + row_length]
        raw_cursor += row_length
        reconstructed = bytearray(row_length)
        for index, encoded in enumerate(filtered):
            left = reconstructed[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            above = previous[index]
            upper_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = paeth_predictor(left, above, upper_left)
            else:
                raise ScreenshotRasterError("capture PNG uses an unknown row filter")
            reconstructed[index] = (encoded + predictor) & 0xFF

        for index in range(0, row_length, bytes_per_pixel):
            red, green, blue = reconstructed[index : index + 3]
            if bytes_per_pixel == 4 and reconstructed[index + 3] != 255:
                raise ScreenshotRasterError("capture PNG contains a transparent pixel")
            color = (red, green, blue)
            colors[color] += 1
            if color == (0, 0, 0):
                exact_black_pixels += 1
        previous = reconstructed

    total_pixels = width * height
    distinct_rgb = len(colors)
    dominant_rgb_ratio = max(colors.values()) / total_pixels
    exact_black_ratio = exact_black_pixels / total_pixels
    if distinct_rgb < MIN_SCREENSHOT_DISTINCT_RGB:
        raise ScreenshotRasterError("capture raster has too few distinct RGB colors")
    if dominant_rgb_ratio > MAX_SCREENSHOT_DOMINANT_RGB_RATIO:
        raise ScreenshotRasterError("capture raster is dominated by one RGB color")
    if exact_black_ratio > MAX_SCREENSHOT_EXACT_BLACK_RATIO:
        raise ScreenshotRasterError("capture raster contains too much exact black")
    return {
        "width": width,
        "height": height,
        "distinct_rgb": distinct_rgb,
        "dominant_rgb_ratio": round(dominant_rgb_ratio, 6),
        "exact_black_ratio": round(exact_black_ratio, 6),
    }


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
    def __init__(
        self,
        base_url: str,
        application: str,
        debugger_address: str | None,
    ):
        self.base_url = base_url.rstrip("/")
        if debugger_address is None:
            always_match = {
                "tauri:options": {"application": application, "args": []},
            }
        else:
            always_match = {
                "browserName": "webview2",
                "ms:edgeChromium": True,
                "ms:edgeOptions": {"debuggerAddress": debugger_address},
            }
        response = request(
            self.base_url,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": always_match,
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

    def set_script_timeout(self, timeout_seconds: int) -> None:
        self.safe_request(
            "POST",
            f"/session/{self.session_id}/timeouts",
            {"script": timeout_seconds * 1000},
        )

    def execute_async(
        self,
        script: str,
        arguments: list[object] | None = None,
        timeout_seconds: int = 45,
    ) -> object:
        self.set_script_timeout(timeout_seconds)
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

    def resize(self, width: int, height: int) -> dict[str, int]:
        value = request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/window/rect",
            {"x": 0, "y": 0, "width": width, "height": height},
        )
        self.wait(
            "return innerWidth===arguments[0] && innerHeight===arguments[1];",
            arguments=[width, height],
        )
        return value

    def wait_for_paint(self) -> None:
        painted = self.execute_async(
            """
const done = arguments[arguments.length - 1];
const afterFonts = () => requestAnimationFrame(
  () => requestAnimationFrame(() => done(true)),
);
Promise.resolve(document.fonts?.ready).then(afterFonts, afterFonts);
""",
            timeout_seconds=5,
        )
        if painted is not True:
            raise AssertionError("renderer did not cross the bounded paint barrier")

    def screenshot(
        self,
        path: pathlib.Path,
        expected_width: int,
        expected_height: int,
    ) -> dict[str, object]:
        last_raster_error: ScreenshotRasterError | None = None
        for attempt in range(1, MAX_SCREENSHOT_ATTEMPTS + 1):
            self.wait_for_paint()
            encoded = request(self.base_url, "GET", f"/session/{self.session_id}/screenshot")
            try:
                if not isinstance(encoded, str):
                    raise ScreenshotRasterError("WebDriver screenshot is not base64 text")
                payload = base64.b64decode(encoded, validate=True)
                raster = inspect_png_raster(payload, expected_width, expected_height)
            except (binascii.Error, ValueError) as error:
                last_raster_error = ScreenshotRasterError(
                    "WebDriver screenshot base64 is invalid"
                )
                last_raster_error.__cause__ = error
            except ScreenshotRasterError as error:
                last_raster_error = error
            else:
                path.write_bytes(payload)
                return {**raster, "capture_attempts": attempt}
            if attempt < MAX_SCREENSHOT_ATTEMPTS:
                time.sleep(SCREENSHOT_RETRY_DELAY_SECONDS)
        raise AssertionError(
            f"screenshot raster remained invalid after {MAX_SCREENSHOT_ATTEMPTS} attempts: "
            f"{last_raster_error}"
        ) from last_raster_error

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


def assert_metrics(metrics: dict[str, object], heading: str, platform: str) -> None:
    assert metrics["title"] == "Your Cloud"
    if platform == "windows":
        assert metrics["origin"] == "http://tauri.localhost"
        assert metrics["href"] == "http://tauri.localhost/"
    else:
        assert metrics["href"] == "tauri://localhost"
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
    platform: str,
    slug: str,
    heading: str,
) -> dict[str, object]:
    desktop_rectangle = driver.resize(1280, 800)
    assert desktop_rectangle["width"] == 1280 and desktop_rectangle["height"] == 800
    desktop = driver.execute(METRICS_SCRIPT)
    assert isinstance(desktop, dict)
    assert_metrics(desktop, heading, platform)
    desktop["raster"] = driver.screenshot(
        output / f"{platform}-{slug}-1280x800.png",
        1280,
        800,
    )

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
    assert_metrics(compact, heading, platform)
    compact["raster"] = driver.screenshot(
        output / f"{platform}-{slug}-640x560.png",
        640,
        560,
    )

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
        zoomed["raster"] = driver.screenshot(
            output / f"{platform}-{slug}-640x560-text-200.png",
            640,
            560,
        )
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


NATIVE_VAULT_INITIALIZATION_SCRIPT = r"""
const done = arguments[arguments.length - 1];
let phase = 'vault-initialization-started';
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const fail = (failurePhase) => {
  phase = failurePhase;
  throw new Error('expurgated-vault-initialization-failure');
};
const waitFor = async (predicate, timeoutMilliseconds, failurePhase) => {
  const deadline = performance.now() + timeoutMilliseconds;
  while (performance.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await sleep(50);
  }
  fail(failurePhase);
};
const exactEnabledButton = (label) => [...document.querySelectorAll('button')].find(
  (button) => button.textContent?.trim() === label && !button.disabled,
);
const setInputValue = (selector, value) => {
  const input = document.querySelector(selector);
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (!(input instanceof HTMLInputElement) || typeof descriptor?.set !== 'function') {
    fail('vault-confirmation-input-unavailable');
  }
  const previous = input.value;
  descriptor.set.call(input, value);
  if (input._valueTracker) input._valueTracker.setValue(previous);
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
};

(async () => {
  const generateButton = exactEnabledButton('Générer les secrets locaux');
  if (!generateButton) fail('vault-generation-action-unavailable');
  generateButton.click();

  const secrets = await waitFor(() => {
    const candidates = [...document.querySelectorAll('.yc-secret')];
    if (candidates.length !== 2) return null;
    return candidates.map((element) => element.textContent?.trim() ?? '');
  }, 30000, 'vault-generated-secret-count-invalid');
  let phrase = secrets[0];
  let recovery = secrets[1];
  const phraseShapeValid = (
    /^[^ ]+(?: [^ ]+){5}$/u.test(phrase)
    && new TextEncoder().encode(phrase).length <= 96
  );
  const recoveryShapeValid = /^(?:[A-Z2-7]{6}-){8}[A-Z2-7]{6}$/u.test(recovery);
  if (!phraseShapeValid || !recoveryShapeValid) fail('vault-generated-secret-shape-invalid');

  setInputValue('#confirm-unlock-phrase', phrase);
  setInputValue('#confirm-recovery-code', recovery);
  await waitFor(() => {
    const phraseInput = document.querySelector('#confirm-unlock-phrase');
    const recoveryInput = document.querySelector('#confirm-recovery-code');
    return phraseInput instanceof HTMLInputElement
      && recoveryInput instanceof HTMLInputElement
      && phraseInput.value === phrase
      && recoveryInput.value === recovery;
  }, 5000, 'vault-confirmation-values-not-accepted');

  const checkbox = document.querySelector('input[type=checkbox]');
  if (!(checkbox instanceof HTMLInputElement)) fail('vault-confirmation-checkbox-unavailable');
  checkbox.click();
  await waitFor(
    () => document.querySelector('input[type=checkbox]')?.checked === true,
    5000,
    'vault-confirmation-checkbox-not-checked',
  );
  const confirmButton = await waitFor(
    () => exactEnabledButton('Confirmer et créer le coffre'),
    5000,
    'vault-confirmation-action-unavailable',
  );

  secrets.fill('');
  phrase = '';
  recovery = '';
  confirmButton.click();
  await waitFor(
    () => document.querySelector('h1')?.textContent?.trim() === 'Infrastructures',
    60000,
    'vault-confirmation-did-not-complete',
  );

  const facts = {
    generated_secret_shapes_valid: phraseShapeValid && recoveryShapeValid,
    confirmation_completed_inside_webview: true,
    generated_secrets_absent_from_dom: document.querySelectorAll('.yc-secret').length === 0,
    local_storage_empty: Object.keys(localStorage).length === 0,
    session_storage_empty: Object.keys(sessionStorage).length === 0,
    password_fields_empty: [...document.querySelectorAll('input[type=password]')]
      .every((input) => input.value === ''),
  };
  if (!Object.values(facts).every((value) => value === true)) {
    fail('vault-residual-state-not-empty');
  }
  done({ ok: true, facts });
})().catch(() => done({ ok: false, failure: phase }));
"""


def initialize_real_native_vault(driver: Driver) -> None:
    outcome = driver.execute_async(NATIVE_VAULT_INITIALIZATION_SCRIPT, timeout_seconds=90)
    assert isinstance(outcome, dict)
    assert outcome.get("ok") is True, outcome.get(
        "failure", "native vault initialization failed"
    )
    assert outcome.get("facts") == {
        "generated_secret_shapes_valid": True,
        "confirmation_completed_inside_webview": True,
        "generated_secrets_absent_from_dom": True,
        "local_storage_empty": True,
        "session_storage_empty": True,
        "password_fields_empty": True,
    }
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures", 60)


BOOTSTRAP_IPC_PROOF_SCRIPT = r"""
const done = arguments[arguments.length - 1];
const phase = arguments[0];
const opaqueRequestId = phase === 'finish' ? arguments[1] : null;
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

  if (phase === 'start') {
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

    const authorityRejections = {};
    for (const [label, extra] of [
      ['consent', { consent: 'frontend-consent-must-not-be-accepted' }],
      ['prompt', { prompt: 'confirm_root_access' }],
      ['step', { step: 'root_access' }],
      ['actions', { actions: ['install_controller'] }],
      ['expiration', { remaining_millis: 300000 }],
    ]) {
      const rawCanary = Object.values(extra)[0];
      const canary = Array.isArray(rawCanary) ? rawCanary[0] : String(rawCanary);
      const rejected = await settled(start('create', extra));
      authorityRejections[label] = assertCodeOnly(
        rejected,
        'invalid_input',
        `${label}-field`,
        canary,
      );
    }

    const concurrent = await Promise.all([
      settled(start('create')),
      settled(start('create')),
    ]);
    const winners = concurrent.filter((result) => result.status === 'fulfilled');
    const busy = concurrent.filter((result) => result.status === 'rejected');
    if (winners.length !== 1 || busy.length !== 1) {
      fail('concurrent-create-cardinality-drifted');
    }
    const busyCode = assertCodeOnly(busy[0], 'bootstrap_busy', 'concurrent-create');
    const createRequestId = assertSession(winners[0].value, 'create', 'create');

    const forged = await settled(status('ffeeddccbbaa99887766554433221100'));
    const forgedCode = assertCodeOnly(forged, 'bootstrap_request_refused', 'forged-id');

    return {
      phase: 'capture_ready',
      request_id: createRequestId,
      proof: {
        invoke_surface: 'window.__TAURI_INTERNALS__.invoke',
        commands: ['start_bootstrap', 'bootstrap_status', 'cancel_bootstrap'],
        modes: ['create', 'replace'],
        session_schema_version: 1,
        lifecycle_observed: 'awaiting_native_assistant',
        concurrency: 'one_active_one_bootstrap_busy',
        error_shape: 'code-only',
        rejected_codes: {
          unknown_field: unknownCode,
          sensitive_field: sensitiveCode,
          authority_fields: authorityRejections,
          concurrent_start: busyCode,
          forged_id: forgedCode,
        },
      },
    };
  }

  if (phase !== 'finish' || typeof opaqueRequestId !== 'string' ||
      !/^[0-9a-f]{32}$/.test(opaqueRequestId)) {
    fail('bootstrap-proof-phase-refused');
  }

  const createRunning = await settled(status(opaqueRequestId));
  if (createRunning.status !== 'fulfilled') fail('create-helper-did-not-remain-running');
  assertSession(createRunning.value, 'create', 'create-running');

  const mutatedHost = 'mutated-controller.example.test';
  const targetMutation = await settled(start('create', {
    target: { ...target, host: mutatedHost },
  }));
  const targetMutationCode = assertCodeOnly(
    targetMutation,
    'bootstrap_busy',
    'active-target-mutation',
    mutatedHost,
  );

  const cancelled = await settled(cancel(opaqueRequestId));
  if (cancelled.status !== 'fulfilled' || cancelled.value !== null) {
    fail('active-create-cancellation-failed');
  }
  const cancellationReplay = await settled(cancel(opaqueRequestId));
  const cancellationReplayCode = assertCodeOnly(
    cancellationReplay,
    'bootstrap_request_refused',
    'cancel-replay',
  );

  const replaceStart = await settled(start('replace'));
  if (replaceStart.status !== 'fulfilled') fail('replace-start-was-rejected');
  const replaceRequestId = assertSession(replaceStart.value, 'replace', 'replace');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  const replaceRunning = await settled(status(replaceRequestId));
  if (replaceRunning.status !== 'fulfilled') fail('replace-helper-did-not-remain-running');
  assertSession(replaceRunning.value, 'replace', 'replace-running');

  const replaceCancelled = await settled(cancel(replaceRequestId));
  if (replaceCancelled.status !== 'fulfilled' || replaceCancelled.value !== null) {
    fail('active-replace-cancellation-failed');
  }

  const terminalReplay = await settled(status(replaceRequestId));
  const terminalReplayCode = assertCodeOnly(
    terminalReplay,
    'bootstrap_request_refused',
    'terminal-replay',
  );

  return {
    phase: 'finished',
    proof: {
      create_helper_running_after_native_capture: true,
      replace_helper_running_after_millis: 1000,
      create_terminal: 'cancelled_by_test',
      replace_terminal: 'cancelled_by_test',
      request_ids_included_in_proof_artifact: false,
      target_included_in_public_error: false,
      sensitive_input_included_in_public_error_or_proof_artifact: false,
      rejected_codes: {
        active_target_mutation: targetMutationCode,
        cancellation_replay: cancellationReplayCode,
        terminal_replay: terminalReplayCode,
      },
      success_claimed: false,
    },
  };
})().then(
  (result) => done({ ok: true, result }),
  (error) => done({
    ok: false,
    failure: error instanceof Error ? error.message : 'unknown-bootstrap-proof-failure',
  }),
);
"""


def capture_linux_native_prompt(output: pathlib.Path) -> dict[str, object]:
    title = "Your Cloud — autoriser l’accès personnel"
    deadline = time.monotonic() + 10
    window_id: str | None = None
    while time.monotonic() < deadline:
        found = subprocess.run(
            ["/usr/bin/xdotool", "search", "--onlyvisible", "--name", f"^{re.escape(title)}$"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        candidates = [line.strip() for line in found.stdout.splitlines() if line.strip()]
        if found.returncode == 0 and candidates:
            window_id = candidates[-1]
            break
        time.sleep(0.05)
    if window_id is None or not window_id.isdecimal():
        raise AssertionError("native GTK consent window was not observed")
    observed_title = subprocess.run(
        ["/usr/bin/xdotool", "getwindowname", window_id],
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    ).stdout.strip()
    if observed_title != title:
        raise AssertionError("native GTK consent title drifted")
    time.sleep(0.1)
    capture = output / "linux-native-personal-consent.png"
    rendered = subprocess.run(
        ["/usr/bin/import", "-window", window_id, str(capture)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    if rendered.returncode != 0 or not capture.is_file():
        raise AssertionError("native GTK consent capture failed")
    if not capture.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError("native GTK consent capture is not a PNG")
    return {
        "title_exact": True,
        "png_signature_valid": True,
        "public_scope_machine_inspected": False,
        "secret_control_machine_inspected": False,
    }


def capture_windows_native_prompt(output: pathlib.Path) -> dict[str, object]:
    from ctypes import wintypes

    title = "Your Cloud — autoriser l’accès personnel"
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.GetDlgItem.restype = wintypes.HWND
    user32.SendMessageTimeoutW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    user32.SendMessageTimeoutW.restype = wintypes.LPARAM
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL

    def window_text(window: int) -> str:
        length = user32.GetWindowTextLengthW(window)
        if length < 0:
            raise AssertionError("native Win32 text length failed")
        buffer = ctypes.create_unicode_buffer(length + 1)
        copied = user32.GetWindowTextW(window, buffer, len(buffer))
        if copied != length:
            raise AssertionError("native Win32 text read failed")
        return buffer.value

    def control_text(window: int) -> str:
        wm_gettext = 0x000D
        wm_gettextlength = 0x000E
        smto_block_abort_if_hung = 0x0001 | 0x0002
        length_result = ctypes.c_size_t()
        if not user32.SendMessageTimeoutW(
            window,
            wm_gettextlength,
            0,
            0,
            smto_block_abort_if_hung,
            1000,
            ctypes.byref(length_result),
        ):
            raise AssertionError("native Win32 control text length timed out")
        length = length_result.value
        if length > 4096:
            raise AssertionError("native Win32 control text exceeded its public bound")
        buffer = ctypes.create_unicode_buffer(length + 1)
        copied_result = ctypes.c_size_t()
        if not user32.SendMessageTimeoutW(
            window,
            wm_gettext,
            len(buffer),
            ctypes.addressof(buffer),
            smto_block_abort_if_hung,
            1000,
            ctypes.byref(copied_result),
        ):
            raise AssertionError("native Win32 control text read timed out")
        if copied_result.value != length:
            raise AssertionError("native Win32 control text length drifted")
        return buffer.value

    deadline = time.monotonic() + 10
    dialog: int | None = None
    while time.monotonic() < deadline and dialog is None:
        matches: list[int] = []

        @callback_type
        def collect(window: int, _parameter: int) -> bool:
            if user32.IsWindowVisible(window) and window_text(window) == title:
                matches.append(window)
            return True

        if not user32.EnumWindows(collect, 0):
            raise AssertionError("native Win32 window enumeration failed")
        if matches:
            dialog = matches[-1]
            break
        time.sleep(0.05)
    if dialog is None:
        raise AssertionError("native Win32 consent window was not observed")

    scope_control = user32.GetDlgItem(dialog, 1001)
    countdown_control = user32.GetDlgItem(dialog, 1002)
    secret_control = user32.GetDlgItem(dialog, 1004)
    refuse_control = user32.GetDlgItem(dialog, 1005)
    accept_control = user32.GetDlgItem(dialog, 1)
    if not all((scope_control, countdown_control, refuse_control, accept_control)) or secret_control:
        raise AssertionError("native Win32 consent controls drifted")
    expected_scope = [
        "Parcours : création",
        "Cible : infra_admin@controller.example.test:22",
        "Route d’accès : administrateur",
        "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Étape : accès personnel",
        "Action : audit de la cible en lecture seule",
    ]
    observed_scope = control_text(scope_control).splitlines()
    if observed_scope != expected_scope:
        raise AssertionError("native Win32 public scope drifted")
    if re.fullmatch(r"Expiration : [1-9][0-9]* s", control_text(countdown_control)) is None:
        raise AssertionError("native Win32 expiration label drifted")
    if control_text(refuse_control) != "&Refuser" or control_text(accept_control) != "&Autoriser l’audit":
        raise AssertionError("native Win32 actions drifted")

    rectangle = wintypes.RECT()
    if not user32.GetWindowRect(dialog, ctypes.byref(rectangle)):
        raise AssertionError("native Win32 bounds read failed")
    width = rectangle.right - rectangle.left
    height = rectangle.bottom - rectangle.top
    if width <= 0 or height <= 0:
        raise AssertionError("native Win32 bounds are empty")
    user32.SetForegroundWindow(dialog)
    time.sleep(0.1)
    capture = output / "windows-native-personal-consent.png"
    escaped_capture = str(capture).replace("'", "''")
    script = (
        "Add-Type -AssemblyName System.Drawing;"
        f"$bitmap=New-Object System.Drawing.Bitmap({width},{height});"
        "$graphics=[System.Drawing.Graphics]::FromImage($bitmap);"
        f"$graphics.CopyFromScreen({rectangle.left},{rectangle.top},0,0,$bitmap.Size);"
        f"$bitmap.Save('{escaped_capture}',[System.Drawing.Imaging.ImageFormat]::Png);"
        "$graphics.Dispose();$bitmap.Dispose()"
    )
    rendered = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if rendered.returncode != 0 or not capture.is_file():
        raise AssertionError("native Win32 consent capture failed")
    if not capture.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError("native Win32 consent capture is not a PNG")
    return {
        "title_exact": True,
        "png_signature_valid": True,
        "public_scope_machine_inspected": True,
        "synthetic_target_present": True,
        "secret_control_machine_inspected": True,
        "secret_control_present": False,
    }


def exercise_live_bootstrap_ipc(
    driver: Driver,
    platform: str,
    output: pathlib.Path,
) -> dict[str, object]:
    start_outcome = driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT, ["start"])
    assert isinstance(start_outcome, dict)
    assert start_outcome.get("ok") is True, start_outcome.get(
        "failure", "bootstrap IPC start handshake failed"
    )
    start_result = start_outcome.get("result")
    assert isinstance(start_result, dict)
    assert start_result.get("phase") == "capture_ready"
    create_request_id = start_result.get("request_id")
    assert isinstance(create_request_id, str)
    assert re.fullmatch(r"[0-9a-f]{32}", create_request_id)
    preflight_proof = start_result.get("proof")
    assert isinstance(preflight_proof, dict)

    capture_facts = (
        capture_windows_native_prompt(output)
        if platform == "windows"
        else capture_linux_native_prompt(output)
    )

    finish_outcome = driver.execute_async(
        BOOTSTRAP_IPC_PROOF_SCRIPT,
        ["finish", create_request_id],
    )
    assert isinstance(finish_outcome, dict)
    assert finish_outcome.get("ok") is True, finish_outcome.get(
        "failure", "bootstrap IPC finish handshake failed"
    )
    finish_result = finish_outcome.get("result")
    assert isinstance(finish_result, dict)
    assert finish_result.get("phase") == "finished"
    finish_proof = finish_result.get("proof")
    assert isinstance(finish_proof, dict)

    preflight_rejections = preflight_proof.get("rejected_codes")
    finish_rejections = finish_proof.get("rejected_codes")
    assert isinstance(preflight_rejections, dict)
    assert isinstance(finish_rejections, dict)
    overlapping_keys = (preflight_proof.keys() & finish_proof.keys()) - {"rejected_codes"}
    if overlapping_keys:
        raise AssertionError("bootstrap proof phases contain overlapping facts")
    overlapping_rejections = preflight_rejections.keys() & finish_rejections.keys()
    if overlapping_rejections:
        raise AssertionError("bootstrap proof phases contain overlapping rejection facts")
    proof = {
        **{
            key: value
            for key, value in preflight_proof.items()
            if key != "rejected_codes"
        },
        **{
            key: value
            for key, value in finish_proof.items()
            if key != "rejected_codes"
        },
        "rejected_codes": {**preflight_rejections, **finish_rejections},
        "native_capture": capture_facts,
    }
    assert proof.get("success_claimed") is False
    assert proof.get("request_ids_included_in_proof_artifact") is False
    assert proof.get("target_included_in_public_error") is False
    assert proof.get("sensitive_input_included_in_public_error_or_proof_artifact") is False
    serialized_proof = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    if create_request_id in serialized_proof:
        raise AssertionError("bootstrap request identifier entered the proof artifact")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--platform", choices=("linux", "windows"), default="windows")
    parser.add_argument("--application", required=True)
    parser.add_argument("--debugger-address")
    parser.add_argument("--session-ready-marker", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.platform == "windows" and args.debugger_address is None:
        parser.error("--debugger-address is required on Windows")
    if args.platform == "linux" and args.debugger_address is not None:
        parser.error("--debugger-address is not accepted on Linux")
    args.output.mkdir(parents=True, exist_ok=False)

    driver = Driver(args.base_url, args.application, args.debugger_address)
    is_windows = args.platform == "windows"
    args.session_ready_marker.touch(exist_ok=False)
    report: dict[str, object] = {
        "schema_version": 1,
        "application": args.application,
        "platform": args.platform,
        "instrumentation": (
            "tauri-driver 2.0.6 proxying matching Microsoft Edge WebDriver "
            "attached to the installed WebView2"
            if is_windows
            else "tauri-driver 2.0.6 proxying the native WebKitWebDriver"
        ),
        "debugger_transport": (
            "ephemeral loopback TCP, removed before normal launch"
            if is_windows
            else "tauri-driver loopback WebDriver, removed after the proof"
        ),
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
        views["local-access"] = capture_view(
            driver, args.output, args.platform, "local-access", "Accès local"
        )

        initialize_real_native_vault(driver)
        report["bootstrap_tauri_ipc"] = exercise_live_bootstrap_ipc(
            driver, args.platform, args.output
        )
        report["native_personal_consent_capture"] = (
            f"{args.platform}-native-personal-consent.png"
        )
        views["infrastructures"] = capture_view(
            driver, args.output, args.platform, "infrastructures", "Infrastructures"
        )
        driver.click_button("Associer")
        driver.wait(
            "return document.querySelector('h1')?.textContent ?? null;",
            "Association ou récupération",
        )
        views["association"] = capture_view(
            driver,
            args.output,
            args.platform,
            "association",
            "Association ou récupération",
        )

        report.update(
            {
                "real_native_vault_initialized": True,
                "bootstrap_business_result": "not_implemented_fail_closed",
                "result": "pass",
            }
        )
    finally:
        driver.close()

    report_name = (
        "windows-webview2-smoke.json"
        if is_windows
        else "linux-webkitgtk-smoke.json"
    )
    (args.output / report_name).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"PASS: installed {args.platform} Console rendered three pre-association views at "
        "1280x800 and 640x560, initialized the real native vault, kept 200% text "
        "responsive, exercised bounded Tauri bootstrap IPC without claiming business "
        "success and exposed no remote resource"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
