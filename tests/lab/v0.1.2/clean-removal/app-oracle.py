#!/usr/bin/env python3
"""Mène l'App installée jusqu'au formulaire d'association, et pas plus loin.

Ce que cet oracle existe pour produire n'est pas une assertion sur un écran :
c'est de **vraies traces d'usage** sur la machine. Une désinstallation mesurée
sur une machine où le produit n'a jamais tourné ne mesurerait que l'inverse de
`dpkg --install` ; ce qu'il faut savoir est ce que reste un coffre créé, une
configuration écrite et un moteur de rendu qui a mis ses caches en place.

Le trajet s'arrête donc au formulaire d'association, et volontairement : le
coffre, ses clés et la configuration existent dès l'écran précédent, tandis
qu'aller au-delà exigerait un Controller vivant — c'est-à-dire un tout autre
périmètre que celui de cette preuve.

Le pilote est le produit installé, `/usr/bin/your-cloud-app`, conduit par
`tauri-driver` devant le WebKitWebDriver avec lequel l'App Linux peint.
Rien n'est remplacé, rien n'est semé : un coffre semé serait un coffre que cette
preuve n'a pas fait naître, et donc des traces dont elle ne saurait pas dire
qui les a écrites. Le client WebDriver est celui du patron d'oracle du trajet de
commande, réduit à ce que ce trajet-ci demande.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.parse

REQUEST_TIMEOUT = 120


def request(base_url: str, method: str, path: str, body: object = None) -> object:
    parsed = urllib.parse.urlparse(base_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=REQUEST_TIMEOUT)
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    try:
        connection.request(method, path, payload, headers)
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    if not raw:
        return None
    answer = json.loads(raw)
    value = answer.get("value")
    if isinstance(value, dict) and "error" in value:
        raise RuntimeError(f"{value.get('error')}: {value.get('message', '').strip()}")
    return value


class Driver:
    """Une session contre le candidat installé."""

    def __init__(self, base_url: str, application: str) -> None:
        self.base_url = base_url
        capabilities = {"tauri:options": {"application": application, "args": []}}
        response = request(
            base_url, "POST", "/session", {"capabilities": {"alwaysMatch": capabilities}}
        )
        session = response if isinstance(response, dict) else {}
        self.session_id = session.get("sessionId")
        if not self.session_id:
            raise RuntimeError(f"le pilote n'a ouvert aucune session : {response!r}")

    def close(self) -> None:
        try:
            request(self.base_url, "DELETE", f"/session/{self.session_id}")
        except Exception:  # noqa: BLE001 — une session perdue ne cache pas le verdict
            pass

    def execute(self, script: str, *arguments: object) -> object:
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": list(arguments)},
        )


# React tient la valeur d'un champ contrôlé : affecter `.value` met le nœud à
# jour et laisse l'état du composant derrière. Le setter natif suivi d'un
# événement `input` qui remonte est ce qui atteint réellement le composant.
REACT_FILL = """
const setters = {
  INPUT: Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set,
  TEXTAREA: Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set,
};
for (const [selector, value] of Object.entries(arguments[0])) {
  const element = document.querySelector(selector);
  if (!element) return selector;
  const setter = setters[element.tagName];
  if (!setter) return selector;
  setter.call(element, value);
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
}
return true;
"""

CLICK_BY_LABEL = """
const wanted = arguments[0];
const button = [...document.querySelectorAll('button')]
  .find((element) => element.textContent.trim() === wanted && !element.disabled);
if (!button) return false;
button.click();
return true;
"""

HEADING = "const h = document.querySelector('h1'); return h ? h.textContent.trim() : null;"


def wait_until(
    driver: Driver, script: str, expected: object = True, seconds: int = 60, label: str = ""
) -> None:
    deadline = time.monotonic() + seconds
    last: object = None
    while time.monotonic() < deadline:
        try:
            last = driver.execute(script)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            last = "<transport coupé>"
        if last == expected:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{label or 'condition'} : jamais tenue ; dernière valeur {last!r}")


def click(driver: Driver, label: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if driver.execute(CLICK_BY_LABEL, label) is True:
            return
        time.sleep(0.25)
    raise RuntimeError(f"aucun bouton actif ne lit « {label} »")


def click_then_wait(
    driver: Driver,
    label: str,
    effect: str,
    expected: object = True,
    seconds: int = 60,
    description: str = "",
) -> None:
    for attempt in (1, 2):
        try:
            click(driver, label)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        try:
            wait_until(driver, effect, expected, seconds=seconds, label=description or label)
            return
        except RuntimeError:
            if attempt == 2:
                raise


def fill(driver: Driver, values: dict[str, str]) -> None:
    answer = driver.execute(REACT_FILL, values)
    if answer is not True:
        raise RuntimeError(f"le champ {answer!r} est absent de cet écran")


def reach_vault(driver: Driver, report: dict) -> None:
    """D'une App froide au coffre créé, par le chemin du produit.

    Rien n'est semé : les deux secrets sont ceux que l'App a générés, relus
    sur l'écran qui les a affichés, et rendus à l'App qui les redemande.
    C'est ce geste-là qui écrit le coffre sur le disque.
    """
    wait_until(driver, HEADING, "Accès local", seconds=180, label="la vue d'accès local")
    click_then_wait(
        driver,
        "Générer les secrets locaux",
        "return document.querySelectorAll('.yc-secret').length === 2;",
        description="les secrets générés",
    )
    secrets = driver.execute(
        "return [...document.querySelectorAll('.yc-secret')].map((e) => e.textContent.trim());"
    )
    if not isinstance(secrets, list) or len(secrets) != 2:
        raise RuntimeError(f"l'App a rendu {secrets!r} plutôt que deux secrets")
    phrase, recovery = secrets
    fill(driver, {"#confirm-unlock-phrase": phrase, "#confirm-recovery-code": recovery})
    driver.execute(
        "const box = document.querySelector('input[type=checkbox]');"
        "if (box && !box.checked) box.click(); return true;"
    )
    wait_until(
        driver,
        "return document.querySelector('input[type=checkbox]').checked;",
        label="la case de confirmation",
    )
    # Le coffre dérive sa clé sur deux vCPU : l'attente est celle de la KDF.
    click_then_wait(
        driver,
        "Confirmer et créer le coffre",
        HEADING,
        "Infrastructures",
        seconds=300,
        description="la création du coffre",
    )
    report["vault"] = "créé par l'App elle-même, sur la machine de cette passe"
    report["secret_lengths"] = [len(phrase), len(recovery)]


def reach_association_form(driver: Driver, report: dict) -> None:
    """Jusqu'au formulaire, et pas au-delà.

    Le franchir demanderait un Controller vivant et sa feuille d'enrôlement à
    usage unique — un autre périmètre. Ce qui est mesuré ici est que l'App
    a bien tenu son état jusque-là, donc qu'elle l'a écrit.
    """
    click_then_wait(
        driver,
        "Associer",
        HEADING,
        "Association ou récupération",
        description="la vue d'association",
    )
    fields = driver.execute(
        "return [...document.querySelectorAll('input, textarea')]"
        ".map((e) => e.id).filter((id) => id.startsWith('pair-'));"
    )
    if not isinstance(fields, list) or "pair-origin" not in fields:
        raise RuntimeError(f"le formulaire d'association ne porte pas ses champs : {fields!r}")
    report["association_form"] = {"reached": True, "fields": sorted(fields)}


def capture_screen(driver: Driver) -> dict[str, object]:
    try:
        return {
            "heading": driver.execute(HEADING),
            "buttons": driver.execute(
                "return [...document.querySelectorAll('button')].map((e) => ({"
                "  text: e.textContent.trim().slice(0, 60), disabled: e.disabled }));"
            ),
            "alerts": driver.execute(
                "return [...document.querySelectorAll("
                "'[role=alert], .yc-error, .yc-alert, .yc-refusal, .yc-prose')]"
                ".map((e) => e.textContent.trim()).filter((t) => t.length).slice(0, 24);"
            ),
        }
    except Exception as failure:  # noqa: BLE001 — la capture ne masque pas le verdict
        return {"illisible": f"{type(failure).__name__}: {failure}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()

    report: dict[str, object] = {"schema_version": 1}
    driver: Driver | None = None
    status = 0
    try:
        driver = Driver(arguments.base_url, arguments.application)
        reach_vault(driver, report)
        reach_association_form(driver, report)
        report["verdict"] = "PASS"
    except Exception as failure:  # noqa: BLE001 — un rouge doit nommer sa raison
        report["verdict"] = "FAILED"
        report["failure"] = f"{type(failure).__name__}: {failure}"
        if driver is not None:
            report["screen"] = capture_screen(driver)
        status = 1
    finally:
        if driver is not None:
            driver.close()

    with open(arguments.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
