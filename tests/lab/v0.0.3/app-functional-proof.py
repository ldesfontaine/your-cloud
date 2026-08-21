#!/usr/bin/env python3
"""Drive secret-bearing App flows without printing or capturing secrets."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
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
            {"capabilities": {"alwaysMatch": {"tauri:options": {"application": application}}}},
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

    def click_button_idempotent(self, label: str) -> None:
        clicked = self.execute(
            "const button=[...document.querySelectorAll('button')]"
            ".find((e)=>e.textContent.trim()===arguments[0]);"
            "if(!button) return false; button.click(); return true;",
            [label],
        )
        assert clicked is True

    def fill(self, selector: str, value: str) -> None:
        self.fill_fields({selector: value})

    def fill_multiline(self, selector: str, value: str) -> None:
        result = self.execute(
            "const element=document.querySelector(arguments[0]);"
            "if(!(element instanceof HTMLTextAreaElement)) return false;"
            "const previous=element.value;"
            "Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')"
            ".set.call(element,arguments[1]);"
            "if(element._valueTracker) element._valueTracker.setValue(previous);"
            "element.dispatchEvent(new Event('input',{bubbles:true})); return true;",
            [selector, value],
        )
        assert result is True

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
        encoded = request(
            self.base_url,
            "GET",
            f"/session/{self.session_id}/screenshot",
        )
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


def read_secrets(path: pathlib.Path) -> dict[str, str]:
    metadata = path.stat()
    if not path.is_file() or metadata.st_mode & 0o777 != 0o600 or metadata.st_size > 4_096:
        raise AssertionError("the LAB-only secret file has unsafe metadata")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"unlock_phrase", "recovery_code"}:
        raise AssertionError("the LAB-only secret file has an unexpected schema")
    return document


def write_secrets(path: pathlib.Path, document: dict[str, str], *, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
        if len(payload) > 4_096:
            raise AssertionError("secret payload exceeds its bound")
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unlock(driver: Driver, phrase: str) -> None:
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Accès local")
    driver.fill("#unlock-phrase", phrase)
    driver.click_button("Déverrouiller")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")


def wait_view_ready(driver: Driver, heading: str) -> None:
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", heading)
    state = driver.wait(
        "const refresh=[...document.querySelectorAll('button')]"
        ".find((e)=>e.textContent.trim()==='Actualiser');"
        "const refused=document.body.textContent.includes('Opération refusée');"
        "return refused?'refused':(refresh?.getAttribute('aria-busy')==='false'?'ready':'loading');",
        "ready",
        60,
    )
    assert state == "ready"


def initialize(driver: Driver, secret_path: pathlib.Path) -> None:
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Accès local")
    driver.click_button("Générer les secrets locaux")
    driver.wait("return document.querySelectorAll('.yc-secret').length===2;")
    secrets = driver.execute(
        "return [...document.querySelectorAll('.yc-secret')].map((e)=>e.textContent.trim());"
    )
    phrase, recovery = secrets
    assert len(phrase.encode("utf-8")) <= 96 and len(phrase.split(" ")) == 6
    assert re.fullmatch(r"(?:[A-Z2-7]{6}-){8}[A-Z2-7]{6}", recovery)
    driver.fill("#confirm-unlock-phrase", phrase)
    driver.fill("#confirm-recovery-code", recovery)
    driver.click(driver.element("css selector", "input[type=checkbox]"))
    driver.wait("return document.querySelector('input[type=checkbox]').checked;")
    driver.wait(
        "return ![...document.querySelectorAll('button')].find((e)=>"
        "e.textContent.trim()==='Confirmer et créer le coffre').disabled;"
    )
    driver.click_button("Confirmer et créer le coffre")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")
    residual = driver.execute(
        "return {secrets:document.querySelectorAll('.yc-secret').length,"
        "local:Object.keys(localStorage),session:Object.keys(sessionStorage),"
        "inputs:[...document.querySelectorAll('input[type=password]')].map((e)=>e.value)};"
    )
    assert residual == {"secrets": 0, "local": [], "session": [], "inputs": []}
    write_secrets(secret_path, {"unlock_phrase": phrase, "recovery_code": recovery}, exclusive=True)


def change_phrase(driver: Driver, secret_path: pathlib.Path) -> None:
    secrets = read_secrets(secret_path)
    unlock(driver, secrets["unlock_phrase"])
    driver.click_button("Profil et sessions")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Profil et sessions")
    driver.click_button("Générer une nouvelle phrase")
    driver.wait("return document.querySelectorAll('.yc-secret').length===1;")
    replacement = driver.execute("return document.querySelector('.yc-secret').textContent.trim();")
    assert replacement != secrets["unlock_phrase"] and len(replacement.split(" ")) == 6
    driver.fill("#current-unlock-phrase", secrets["unlock_phrase"])
    driver.fill("#confirm-new-unlock-phrase", replacement)
    driver.click_button("Remplacer la phrase")
    driver.wait(
        "return [...document.querySelectorAll('[role=status]')].some((e)=>"
        "e.textContent.includes('Phrase remplacée'));"
    )
    assert driver.execute("return document.querySelectorAll('.yc-secret').length;") == 0
    driver.click_button("Verrouiller")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Accès local")
    driver.fill("#unlock-phrase", secrets["unlock_phrase"])
    driver.click_button("Déverrouiller")
    driver.wait(
        "return [...document.querySelectorAll('[role=alert]')].some((e)=>"
        "e.textContent.includes('Accès refusé'));"
    )
    driver.fill("#unlock-phrase", replacement)
    driver.click_button("Déverrouiller")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")
    write_secrets(
        secret_path,
        {"unlock_phrase": replacement, "recovery_code": secrets["recovery_code"]},
        exclusive=False,
    )


def pair(driver: Driver, secret_path: pathlib.Path, sheet_path: pathlib.Path) -> None:
    secrets = read_secrets(secret_path)
    metadata = sheet_path.stat()
    if not sheet_path.is_file() or metadata.st_mode & 0o777 != 0o600 or metadata.st_size > 8_192:
        raise AssertionError("the pairing sheet has unsafe metadata")
    sheet = json.loads(sheet_path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "mode",
        "origin",
        "temporary_origin",
        "controller_id",
        "infrastructure_id",
        "server_ca_pem",
        "server_spki_sha256",
        "window_id",
        "window_code",
        "expires_at",
    }
    if set(sheet) != expected or sheet["schema_version"] != 1 or sheet["mode"] != "enrollment":
        raise AssertionError("the pairing sheet has an unexpected schema")

    unlock(driver, secrets["unlock_phrase"])
    driver.click_button("Associer")
    driver.wait(
        "return document.querySelector('h1')?.textContent ?? null;",
        "Association ou récupération",
    )
    fields = {
        "#pair-origin": sheet["origin"],
        "#pair-temporary-origin": sheet["temporary_origin"],
        "#pair-controller-id": sheet["controller_id"],
        "#pair-infrastructure-id": sheet["infrastructure_id"],
        "#pair-spki": sheet["server_spki_sha256"],
        "#pair-ca": sheet["server_ca_pem"],
        "#pair-window-id": sheet["window_id"],
        "#pair-window-code": sheet["window_code"],
        "#pair-recovery-code": secrets["recovery_code"],
    }
    driver.fill_fields(fields)
    rendered = driver.execute(
        "return Object.fromEntries(arguments[0].map((selector)=>"
        "[selector,document.querySelector(selector)?.value ?? null]));",
        [list(fields)],
    )
    for selector, expected_value in fields.items():
        actual_value = rendered.get(selector)
        if actual_value != expected_value:
            actual_length = len(actual_value) if isinstance(actual_value, str) else -1
            raise AssertionError(
                f"WebDriver field mismatch for {selector}: expected length "
                f"{len(expected_value)}, actual length {actual_length}"
            )
    driver.click_button("Vérifier et associer")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        outcome = driver.execute(
            "const heading=document.querySelector('h1')?.textContent ?? null;"
            "const refused=[...document.querySelectorAll('[role=alert]')]"
            ".find((e)=>e.textContent.includes('Association refusée'));"
            "return {heading,failure:refused?.textContent.trim() ?? null};"
        )
        if outcome["heading"] == "Synthèse":
            break
        if outcome["failure"]:
            raise AssertionError(f"pairing rejected by the App: {outcome['failure']}")
        time.sleep(0.25)
    else:
        raise AssertionError("pairing did not complete within 60 seconds")
    visible = driver.execute("return document.body.textContent;")
    assert sheet["controller_id"] in visible and sheet["infrastructure_id"] in visible
    assert driver.execute("return document.querySelectorAll('input[type=password]').length;") == 0


def configure(
    driver: Driver,
    secret_path: pathlib.Path,
    infrastructure_label: str,
    machine_arguments: list[str],
) -> None:
    if not infrastructure_label or len(infrastructure_label) > 256:
        raise AssertionError("the infrastructure label is outside its contract bound")
    machines: list[tuple[str, str]] = []
    for argument in machine_arguments:
        machine_id, separator, label = argument.partition("=")
        if (
            not separator
            or not machine_id
            or len(machine_id) > 63
            or not label
            or len(label) > 256
        ):
            raise AssertionError("a machine argument is outside its contract bound")
        machines.append((machine_id, label))
    if not machines:
        raise AssertionError("at least one LAB machine is required")

    secrets = read_secrets(secret_path)
    unlock(driver, secrets["unlock_phrase"])
    driver.click_button("Ouvrir")
    wait_view_ready(driver, "Synthèse")
    if driver.execute("return document.querySelector('#infrastructure-label') !== null;"):
        driver.fill_fields({"#infrastructure-label": infrastructure_label})
        driver.click_button("Initialiser")
        driver.wait(
            "return document.body.textContent.includes(arguments[0]) && "
            "document.querySelector('#infrastructure-label') === null;",
            True,
            60,
            [infrastructure_label],
        )
    else:
        assert infrastructure_label in driver.execute("return document.body.textContent;")

    driver.click_button_idempotent("Parc")
    wait_view_ready(driver, "Parc")
    for machine_id, label in machines:
        already_present = driver.execute(
            "return document.body.textContent.includes(arguments[0]) && "
            "document.body.textContent.includes(arguments[1]);",
            [machine_id, label],
        )
        if already_present:
            continue
        driver.wait("return document.querySelector('#machine-id')?.value === '';")
        driver.fill_fields({"#machine-id": machine_id, "#machine-label": label})
        driver.click_button("Confirmer")
        driver.wait(
            "return document.body.textContent.includes(arguments[0]) && "
            "document.body.textContent.includes(arguments[1]) && "
            "document.querySelector('#machine-id')?.value === '';",
            True,
            60,
            [machine_id, label],
        )

    fleet_text = driver.execute("return document.body.textContent;")
    for machine_id, label in machines:
        assert machine_id in fleet_text and label in fleet_text
    assert "Opération refusée" not in fleet_text

    driver.click_button_idempotent("Observations")
    wait_view_ready(driver, "Observations")
    driver.wait(
        "return !document.body.textContent.includes('Aucun instantané validé') && "
        "arguments[0].every((value)=>document.body.textContent.includes(value));",
        True,
        60,
        [[label for _, label in machines]],
    )
    observations_text = driver.execute("return document.body.textContent;")
    for _, label in machines:
        assert label in observations_text
    assert "Opération refusée" not in observations_text

    driver.click_button_idempotent("Profil et sessions")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Profil et sessions")
    profile_text = driver.execute("return document.body.textContent;")
    assert "AppareilActif" in "".join(profile_text.split())
    assert "Échéance indisponible" not in profile_text
    residual = driver.execute(
        "return {secrets:document.querySelectorAll('.yc-secret').length,"
        "local:Object.keys(localStorage),session:Object.keys(sessionStorage),"
        "passwords:[...document.querySelectorAll('input[type=password]')].map((e)=>e.value)};"
    )
    assert residual["secrets"] == 0 and residual["local"] == [] and residual["session"] == []
    assert all(value == "" for value in residual["passwords"])


def open_association(driver: Driver, infrastructure_id: str) -> None:
    card = driver.element(
        "xpath",
        "//section[contains(concat(' ',normalize-space(@class),' '),' yc-infrastructure-card ') "
        f"and contains(.,{json.dumps(infrastructure_id)})]//button[normalize-space(.)='Ouvrir']",
    )
    driver.click(card)
    wait_view_ready(driver, "Synthèse")


def prove_multi_controller(
    driver: Driver,
    secret_path: pathlib.Path,
    controller_a: str,
    infrastructure_a: str,
    controller_b: str,
    infrastructure_b: str,
    machine_ids: list[str],
) -> None:
    identifiers = (controller_a, infrastructure_a, controller_b, infrastructure_b)
    if len(set(identifiers)) != 4 or any(not re.fullmatch(r"[0-9a-f-]{36}", value) for value in identifiers):
        raise AssertionError("multi-Controller identifiers are invalid or not separated")
    if not machine_ids or any(not value or len(value) > 63 for value in machine_ids):
        raise AssertionError("the A machine list is outside its contract bound")

    secrets = read_secrets(secret_path)
    unlock(driver, secrets["unlock_phrase"])
    driver.wait("return document.querySelectorAll('.yc-infrastructure-card').length;", 2)
    infrastructure_text = driver.execute("return document.body.textContent;")
    assert infrastructure_a in infrastructure_text and infrastructure_b in infrastructure_text

    open_association(driver, infrastructure_b)
    if driver.execute("return document.querySelector('#infrastructure-label') !== null;"):
        driver.fill_fields({"#infrastructure-label": "LAB B v0.0.3"})
        driver.click_button("Initialiser")
        wait_view_ready(driver, "Synthèse")
    summary_b = driver.execute("return document.body.textContent;")
    assert controller_b in summary_b and controller_a not in summary_b
    assert "Relay indisponible" in summary_b
    metrics_b = driver.execute(
        "return Object.fromEntries([...document.querySelectorAll('.yc-metric')].map((e)=>"
        "[e.querySelector('.yc-badge')?.textContent.trim(),e.querySelector('.yc-metric__value')?.textContent.trim()]));"
    )
    assert metrics_b.get("Machines attendues") == "0"

    driver.click_button_idempotent("Infrastructures")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")
    open_association(driver, infrastructure_a)
    summary_a = driver.execute("return document.body.textContent;")
    assert controller_a in summary_a and controller_b not in summary_a
    assert "Relay indisponible" not in summary_a
    metrics_a = driver.execute(
        "return Object.fromEntries([...document.querySelectorAll('.yc-metric')].map((e)=>"
        "[e.querySelector('.yc-badge')?.textContent.trim(),e.querySelector('.yc-metric__value')?.textContent.trim()]));"
    )
    assert metrics_a.get("Machines attendues") == str(len(machine_ids))
    driver.click_button_idempotent("Parc")
    wait_view_ready(driver, "Parc")
    fleet_a = driver.execute("return document.body.textContent;")
    assert all(machine_id in fleet_a for machine_id in machine_ids)

    driver.click_button_idempotent("Infrastructures")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")
    open_association(driver, infrastructure_b)
    driver.click_button_idempotent("Parc")
    wait_view_ready(driver, "Parc")
    fleet_b = driver.execute("return document.body.textContent;")
    assert "Parc vide" in fleet_b and all(machine_id not in fleet_b for machine_id in machine_ids)


def prove_relay_state(
    driver: Driver,
    secret_path: pathlib.Path,
    infrastructure_id: str,
    controller_id: str,
    expected_relay: str,
    machine_arguments: list[str],
    gap_machine: str | None,
) -> None:
    if expected_relay not in {"available", "unavailable"}:
        raise AssertionError("the expected Relay state is invalid")
    machines: list[tuple[str, str | None]] = []
    for argument in machine_arguments:
        machine_id, separator, expected_badge = argument.partition("=")
        if not machine_id or len(machine_id) > 63:
            raise AssertionError("a state machine identifier is outside its bound")
        if separator and expected_badge not in {"Récente", "Ancienne", "Absente", "Non actualisable"}:
            raise AssertionError("an expected observation badge is invalid")
        machines.append((machine_id, expected_badge if separator else None))
    if not machines:
        raise AssertionError("the Relay state proof requires expected machines")

    unlock(driver, read_secrets(secret_path)["unlock_phrase"])
    open_association(driver, infrastructure_id)
    summary = driver.execute("return document.body.textContent;")
    assert controller_id in summary
    if expected_relay == "unavailable":
        assert "Relay indisponible" in summary
    else:
        assert "Relay indisponible" not in summary
    metrics = driver.execute(
        "return Object.fromEntries([...document.querySelectorAll('.yc-metric')].map((e)=>"
        "[e.querySelector('.yc-badge')?.textContent.trim(),e.querySelector('.yc-metric__value')?.textContent.trim()]));"
    )
    assert metrics.get("Machines attendues") == str(len(machines))

    driver.click_button_idempotent("Parc")
    wait_view_ready(driver, "Parc")
    fleet = driver.execute("return document.body.textContent;")
    for machine_id, expected_badge in machines:
        assert machine_id in fleet
        if expected_badge is not None:
            badge = driver.execute(
                "const button=[...document.querySelectorAll('.yc-machine-button')]"
                ".find((e)=>e.textContent.includes(arguments[0]));"
                "return button?.querySelector('.yc-badge')?.textContent.trim() ?? null;",
                [machine_id],
            )
            assert badge == expected_badge
    if gap_machine is not None:
        if gap_machine not in {machine_id for machine_id, _ in machines}:
            raise AssertionError("the expected gap machine is not in the selected infrastructure")
        selected = driver.execute(
            "const button=[...document.querySelectorAll('.yc-machine-button')]"
            ".find((e)=>e.textContent.includes(arguments[0]));"
            "if(!button) return false; button.click(); return true;",
            [gap_machine],
        )
        assert selected is True
        driver.wait(
            "const detail=document.querySelector('.yc-dashboard > .yc-card');"
            "return detail?.textContent.includes('observation manquante') ?? false;"
        )


VISUAL_METRICS_SCRIPT = r"""
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
  horizontal_overflow: root.scrollWidth > root.clientWidth + 1,
  theme_dark: matchMedia('(prefers-color-scheme: dark)').matches,
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


def assert_visual_metrics(
    metrics: dict[str, object],
    expected_heading: str,
    expected_theme: str,
) -> None:
    assert metrics["title"] == "Your Cloud"
    assert metrics["href"] == "tauri://localhost"
    assert metrics["heading"] == expected_heading
    assert metrics["horizontal_overflow"] is False
    assert metrics["remote_resources"] == []
    assert "Inter" in str(metrics["body_font"])
    assert metrics["minimum_control_height"] is not None
    assert float(metrics["minimum_control_height"]) >= 44
    assert metrics["theme_dark"] is (expected_theme == "dark")


def capture_authenticated_view(
    driver: Driver,
    output: pathlib.Path,
    label: str,
    slug: str,
    expected_heading: str,
    expected_theme: str,
) -> dict[str, object]:
    desktop_rectangle = driver.resize(1280, 800)
    assert desktop_rectangle["width"] == 1280 and desktop_rectangle["height"] == 800
    desktop = driver.execute(VISUAL_METRICS_SCRIPT)
    assert isinstance(desktop, dict)
    assert_visual_metrics(desktop, expected_heading, expected_theme)
    driver.screenshot(output / f"{label}-{slug}-1280x800.png")

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
    compact = driver.execute(VISUAL_METRICS_SCRIPT)
    assert isinstance(compact, dict)
    assert_visual_metrics(compact, expected_heading, expected_theme)
    driver.screenshot(output / f"{label}-{slug}-640x560.png")

    driver.execute("document.documentElement.style.fontSize='32px'; return true;")
    zoomed = driver.execute(VISUAL_METRICS_SCRIPT)
    assert isinstance(zoomed, dict)
    assert zoomed["root_font_size"] == "32px"
    assert zoomed["horizontal_overflow"] is False
    driver.execute("document.documentElement.style.fontSize=''; return true;")
    return {
        "desktop": desktop,
        "compact": compact,
        "text_zoom_200": zoomed,
        "keyboard_focus": focus,
    }


def prove_authenticated_views(
    driver: Driver,
    secret_path: pathlib.Path,
    infrastructure_id: str,
    output: pathlib.Path,
    label: str,
    expected_theme: str,
) -> None:
    if not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        raise AssertionError("the visual proof label is invalid")
    if expected_theme not in {"light", "dark"}:
        raise AssertionError("the expected visual theme is invalid")
    output.mkdir(parents=True, exist_ok=True)
    unlock(driver, read_secrets(secret_path)["unlock_phrase"])

    report: dict[str, object] = {
        "schema_version": 1,
        "application": "/usr/bin/your-cloud-app",
        "theme": expected_theme,
        "instrumentation": "tauri-driver 2.0.6 with WebKitWebDriver",
        "views": {},
    }
    views = report["views"]
    assert isinstance(views, dict)

    views["infrastructures"] = capture_authenticated_view(
        driver, output, label, "infrastructures", "Infrastructures", expected_theme
    )
    driver.click_button_idempotent("Associer")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Association ou récupération")
    views["association"] = capture_authenticated_view(
        driver,
        output,
        label,
        "association",
        "Association ou récupération",
        expected_theme,
    )
    driver.click_button_idempotent("Annuler")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Infrastructures")

    open_association(driver, infrastructure_id)
    views["summary"] = capture_authenticated_view(
        driver, output, label, "summary", "Synthèse", expected_theme
    )
    driver.click_button_idempotent("Parc")
    wait_view_ready(driver, "Parc")
    views["fleet"] = capture_authenticated_view(
        driver, output, label, "fleet", "Parc", expected_theme
    )
    driver.click_button_idempotent("Observations")
    wait_view_ready(driver, "Observations")
    views["observations"] = capture_authenticated_view(
        driver, output, label, "observations", "Observations", expected_theme
    )
    driver.click_button_idempotent("Profil et sessions")
    driver.wait("return document.querySelector('h1')?.textContent ?? null;", "Profil et sessions")
    views["profile"] = capture_authenticated_view(
        driver,
        output,
        label,
        "profile",
        "Profil et sessions",
        expected_theme,
    )

    minimum_rectangle = driver.resize(500, 400)
    assert minimum_rectangle["width"] >= 640 and minimum_rectangle["height"] >= 560
    report["minimum_window_after_500x400_request"] = minimum_rectangle
    report["result"] = "pass"
    (output / f"{label}-authenticated-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation",
        choices=(
            "initialize",
            "change-phrase",
            "pair",
            "configure",
            "multi-controller",
            "relay-state",
            "visual-views",
        ),
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--application", default="/usr/bin/your-cloud-app")
    parser.add_argument("--secrets", required=True, type=pathlib.Path)
    parser.add_argument("--sheet", type=pathlib.Path)
    parser.add_argument("--infrastructure-label", default="LAB v0.0.3")
    parser.add_argument("--machine", action="append", default=[])
    parser.add_argument("--controller-a")
    parser.add_argument("--infrastructure-a")
    parser.add_argument("--controller-b")
    parser.add_argument("--infrastructure-b")
    parser.add_argument("--expected-relay")
    parser.add_argument("--gap-machine")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--label")
    parser.add_argument("--expected-theme", choices=("light", "dark"))
    args = parser.parse_args()

    driver = Driver(args.base_url, args.application)
    try:
        if args.operation == "initialize":
            initialize(driver, args.secrets)
        elif args.operation == "change-phrase":
            change_phrase(driver, args.secrets)
        elif args.operation == "pair":
            if args.sheet is None:
                raise SystemExit("--sheet is required for pair")
            pair(driver, args.secrets, args.sheet)
        elif args.operation == "configure":
            configure(
                driver,
                args.secrets,
                args.infrastructure_label,
                args.machine,
            )
        elif args.operation == "multi-controller":
            required = (
                args.controller_a,
                args.infrastructure_a,
                args.controller_b,
                args.infrastructure_b,
            )
            if any(value is None for value in required):
                raise SystemExit("all Controller A/B identifiers are required")
            prove_multi_controller(
                driver,
                args.secrets,
                args.controller_a,
                args.infrastructure_a,
                args.controller_b,
                args.infrastructure_b,
                args.machine,
            )
        elif args.operation == "relay-state":
            if args.controller_a is None or args.infrastructure_a is None or args.expected_relay is None:
                raise SystemExit("Controller A identifiers and --expected-relay are required")
            prove_relay_state(
                driver,
                args.secrets,
                args.infrastructure_a,
                args.controller_a,
                args.expected_relay,
                args.machine,
                args.gap_machine,
            )
        else:
            if (
                args.infrastructure_a is None
                or args.output is None
                or args.label is None
                or args.expected_theme is None
            ):
                raise SystemExit(
                    "--infrastructure-a, --output, --label and --expected-theme are required"
                )
            prove_authenticated_views(
                driver,
                args.secrets,
                args.infrastructure_a,
                args.output,
                args.label,
                args.expected_theme,
            )
    finally:
        driver.close()
    print(f"app_functional={args.operation} result=pass secret_output=redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
