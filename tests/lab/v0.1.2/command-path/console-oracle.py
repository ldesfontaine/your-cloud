#!/usr/bin/env python3
"""Drive the real Console along the whole command path, and judge what it shows.

This oracle pilots the **installed** product: the `.deb` built from this run's
sources, its own WebView process, its own native helper, its own vault. Nothing
of the Console is replaced — no bundle served beside it, no IPC bridge stood in
for, no signature performed on its behalf. What it talks to is `tauri-driver`
proxying WebKitWebDriver, exactly as the reflow proof's `installed` pilot does.

Two mechanisms drive two surfaces, and the report names what each attests:

  * the **WebView** is driven through WebDriver. It attests what the automation
    engine can reach: the DOM the product painted, the values its own fields
    hold, the sentences its own views render. It does not attest that a human
    eye saw them;
  * the **native window** is outside that surface by construction — it is a
    separate GTK process, which is the property link 2 exists for. It is driven
    through X11 by `xdotool`, the most honest mechanism available here: the
    same synthetic key and button events the X server delivers to any client,
    against the real window the real helper mapped. It does not attest that a
    human read the sentences; it attests that the window really opened, that
    its title and its buttons are the product's, and that the answer the core
    received is the one the window's own control produced.

The WebDriver client below is deliberately this proof's own rather than shared
with the reflow oracle: a change made to measure reflow must never silently
change what the command path proves.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import subprocess
import sys
import time
import urllib.parse

# ---------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 120


def request(base_url: str, method: str, path: str, body: object = None) -> dict:
    """One bounded WebDriver call, with the driver's own error text kept.

    A WebDriver error carries the reason the product refused in its `message`;
    swallowing it would turn every refusal into the same opaque red.
    """
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
        return {}
    answer = json.loads(raw)
    value = answer.get("value")
    if isinstance(value, dict) and "error" in value:
        raise RuntimeError(f"{value.get('error')}: {value.get('message', '').strip()}")
    return value if isinstance(value, dict) else {"value": value}


class Driver:
    """One session against the installed candidate."""

    def __init__(self, base_url: str, application: str) -> None:
        self.base_url = base_url
        capabilities = {"tauri:options": {"application": application, "args": []}}
        response = request(
            base_url,
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": capabilities}},
        )
        self.session_id = response.get("sessionId") or response.get("value", {}).get("sessionId")
        if not self.session_id:
            raise RuntimeError(f"the driver opened no session: {response!r}")

    def close(self) -> None:
        try:
            request(self.base_url, "DELETE", f"/session/{self.session_id}")
        except Exception:  # noqa: BLE001 — a lost session must not hide the verdict
            pass

    def execute(self, script: str, *arguments: object) -> object:
        answer = request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": list(arguments)},
        )
        return answer.get("value")

    def screenshot(self) -> str:
        answer = request(self.base_url, "GET", f"/session/{self.session_id}/screenshot")
        return str(answer.get("value", ""))


# ---------------------------------------------------------------------------
# The gestures
# ---------------------------------------------------------------------------

# React owns the value of a controlled input: assigning `.value` updates the
# node and leaves the component's state behind, so the next render puts the old
# value back. The native setter followed by a bubbling `input` event is what
# actually reaches the component — this is the same script the reflow proof
# uses, for the same reason.
REACT_FILL = """
const setters = {
  INPUT: Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set,
  TEXTAREA: Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set,
  SELECT: Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value').set,
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
    driver: Driver,
    script: str,
    expected: object = True,
    seconds: int = 60,
    label: str = "",
    argument: object = None,
) -> None:
    deadline = time.monotonic() + seconds
    last: object = None
    arguments = () if argument is None else (argument,)
    while time.monotonic() < deadline:
        try:
            last = driver.execute(script, *arguments)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            last = "<transport cut>"
        if last == expected:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{label or 'condition'}: never held; last value was {last!r}")


def click(driver: Driver, label: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if driver.execute(CLICK_BY_LABEL, label) is True:
            return
        time.sleep(0.25)
    raise RuntimeError(f"no enabled button reads « {label} »")


def click_then_wait(
    driver: Driver,
    label: str,
    effect: str,
    expected: object = True,
    seconds: int = 60,
    description: str = "",
    argument: object = None,
) -> None:
    """Click, then hold the click to its observable effect.

    A click is never replayed blindly: the effect arriving proves the click
    happened, and only its absence after the full wait allows one more attempt.
    """
    for attempt in (1, 2):
        try:
            click(driver, label)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        try:
            wait_until(driver, effect, expected, seconds=seconds,
                       label=description or label, argument=argument)
            return
        except RuntimeError:
            if attempt == 2:
                raise


def fill(driver: Driver, values: dict[str, str]) -> None:
    answer = driver.execute(REACT_FILL, values)
    if answer is not True:
        raise RuntimeError(f"the field {answer!r} was not found on this screen")


# ---------------------------------------------------------------------------
# The native window, driven through X11
# ---------------------------------------------------------------------------

WINDOW_TITLE = "Approuver cette opération"

# The container path the synthetic application writes its start marker into.
# It is named here because two documents must agree on it: the `tmpfs` line of
# the definition and the environment line the image reads.
SCRATCH_DIRECTORY = "/var/scratch"


def xdotool(*arguments: str) -> str | None:
    """One bounded `xdotool` query, or nothing when it matched nothing.

    A failing query is never a failing proof by itself: the caller polls until
    its own deadline, exactly as the helper's own contract suite does.
    """
    finished = subprocess.run(
        ["xdotool", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return finished.stdout if finished.returncode == 0 else None


def await_native_window(seconds: int = 90) -> str:
    """The window identifier of the real approval window, once it is mapped.

    It is searched by the product's own title rather than by process: the title
    is what a human would read, and a window that carried another one would be
    a defect this proof must see rather than work around.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        listing = xdotool("search", "--onlyvisible", "--name", WINDOW_TITLE)
        if listing:
            for line in listing.splitlines():
                window = line.strip()
                if window.isdigit():
                    return window
        time.sleep(0.25)
    raise RuntimeError(f"no native window titled « {WINDOW_TITLE} » ever appeared")


def native_window_facts(window: str) -> dict[str, object]:
    """What the window really is, read from the X server rather than assumed."""
    name = xdotool("getwindowname", window) or ""
    pid = xdotool("getwindowpid", window) or ""
    geometry = xdotool("getwindowgeometry", window) or ""
    return {
        "title": name.strip(),
        "pid": pid.strip(),
        "geometry": " ".join(geometry.split()),
    }


def answer_native_window(window: str, response: str) -> None:
    """Give the window the answer a human would give it, through X11.

    The two buttons the product builds carry GTK mnemonics — `_Approuver et
    signer` and `_Refuser` — so `alt+a` and `alt+r` activate exactly the
    control a human would click, and never a default this harness chose.

    The keystroke is delivered by **XTEST**, not by `key --window`. A
    `--window` keystroke is an `XSendEvent` synthetic event, and GTK ignores
    those by design — this harness watched the window stay open under one. XTEST
    events enter through the server's own input path, indistinguishable from a
    keyboard's, which is both the mechanism that works and the honest one to
    claim. There is no window manager on this screen, so focus is set
    explicitly rather than by activation.
    """
    keys = {"approve": "alt+a", "refuse": "alt+r"}
    if response not in keys:
        raise RuntimeError(f"a window is answered approve or refuse, never {response!r}")
    xdotool("windowraise", window)
    xdotool("windowfocus", "--sync", window)
    # The pointer is put over the window too: with no window manager, some GTK
    # builds route key events by pointer position rather than by input focus.
    xdotool("mousemove", "--window", window, "50", "50")
    time.sleep(0.5)
    xdotool("key", "--clearmodifiers", keys[response])


def native_window_gone(window: str, seconds: int = 60) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if xdotool("getwindowname", window) is None:
            return True
        time.sleep(0.25)
    return False


# ---------------------------------------------------------------------------
# The journey
# ---------------------------------------------------------------------------


def reach_vault(driver: Driver, report: dict) -> list[str]:
    """From a cold Console to the Infrastructures view, by the product's path.

    Nothing here is command path: it is the local access the human already has
    to cross before any of it exists. It is driven rather than seeded because a
    seeded vault would be a Console this proof did not stand up.
    """
    wait_until(driver, HEADING, "Accès local", seconds=180, label="the local access view")
    click_then_wait(
        driver,
        "Générer les secrets locaux",
        "return document.querySelectorAll('.yc-secret').length === 2;",
        description="the generated secrets",
    )
    secrets = driver.execute(
        "return [...document.querySelectorAll('.yc-secret')].map((e) => e.textContent.trim());"
    )
    if not isinstance(secrets, list) or len(secrets) != 2:
        raise RuntimeError(f"the Console generated {secrets!r} rather than two secrets")
    phrase, recovery = secrets
    fill(driver, {"#confirm-unlock-phrase": phrase, "#confirm-recovery-code": recovery})
    driver.execute(
        "const box = document.querySelector('input[type=checkbox]');"
        "if (box && !box.checked) box.click(); return true;"
    )
    wait_until(
        driver,
        "return document.querySelector('input[type=checkbox]').checked;",
        label="the confirmation checkbox",
    )
    # The vault derives its key on two virtual CPUs: the wait is the KDF's.
    click_then_wait(
        driver,
        "Confirmer et créer le coffre",
        HEADING,
        "Infrastructures",
        seconds=300,
        description="the vault creation",
    )
    report["vault"] = "created by the Console itself, on this run's own machine"
    return [phrase, recovery]


def associate(driver: Driver, sheet: dict, recovery_code: str, report: dict) -> None:
    """Associate the real Console with the real Controller, from the sheet.

    The values come from the one-time enrolment sheet the Controller wrote
    itself. The harness carries that sheet the way a human carries it — it is
    the Controller's own output, never a value this proof invented.

    The global recovery code is the Console's own, generated one screen earlier
    and read back off the screen that displayed it. The core validates it on
    both paths — enrolment as well as recovery — so an association driven
    without it is refused before any byte reaches the Controller.
    """
    click_then_wait(
        driver,
        "Associer",
        HEADING,
        "Association ou récupération",
        description="the association view",
    )
    fill(
        driver,
        {
            "#pair-origin": sheet["origin"],
            "#pair-temporary-origin": sheet["temporary_origin"],
            "#pair-controller-id": sheet["controller_id"],
            "#pair-infrastructure-id": sheet["infrastructure_id"],
            "#pair-spki": sheet["server_spki_sha256"],
            "#pair-ca": sheet["server_ca_pem"],
            "#pair-window-id": sheet["window_id"],
            "#pair-window-code": sheet["window_code"],
            "#pair-recovery-code": recovery_code,
        },
    )
    # The effect is the association view being left behind, not one particular
    # heading: which view the Console lands on afterwards is its decision, and
    # a proof that demanded a name would be pinning a choice it does not own.
    click_then_wait(
        driver,
        "Vérifier et associer",
        "const h = document.querySelector('h1');"
        "return h ? h.textContent.trim() !== 'Association ou récupération' : false;",
        seconds=180,
        description="the association completing",
    )
    report["association"] = {
        "controller_id": sheet["controller_id"],
        "infrastructure_id": sheet["infrastructure_id"],
        "reached": "the Console crossed to its post-association views against a live Controller",
    }


def unlock(driver: Driver, phrase: str, report: dict) -> None:
    """Open a Console that already holds this run's vault and association.

    Stages after the first do not re-create anything: an association is a
    one-shot exchange with a Controller that will not open a second window, so
    what a later stage does is exactly what a human does — type the phrase.
    """
    wait_until(driver, HEADING, "Accès local", seconds=180, label="the local access view")
    fill(driver, {"#unlock-phrase": phrase})
    click_then_wait(
        driver,
        "Déverrouiller",
        "const h = document.querySelector('h1');"
        "return h ? h.textContent.trim() !== 'Accès local' : false;",
        seconds=180,
        description="the vault unlocking",
    )
    report["vault"] = "unlocked; this run's own, created by the Console at the association stage"


def select_infrastructure(driver: Driver) -> None:
    """Enter the one infrastructure this Console is associated with."""
    heading = driver.execute(HEADING)
    if heading == "Infrastructures":
        click_then_wait(
            driver,
            "Ouvrir",
            "const h = document.querySelector('h1');"
            "return h ? h.textContent.trim() !== 'Infrastructures' : false;",
            description="entering the infrastructure",
        )


def attach_machine(driver: Driver, machine_id: str, report: dict) -> None:
    """Attach the machine to the Controller's inventory, from the Parc view.

    This is the gate link 4 goes through: the Controller reads its Relay
    snapshot and refuses a machine it cannot see reported `active`, and an
    approval naming a machine outside the inventory is refused
    `machine_not_active`. It is done from the Console because that is where a
    human does it, and because the projection the Console must read to sign —
    the machine's own reported position — is on this very screen.
    """
    click_then_wait(driver, "Parc", HEADING, "Parc", description="the Parc view")
    report["fleet_before"] = capture_screen(driver)
    fill(driver, {"#machine-id": machine_id, "#machine-label": machine_id})
    # The effect is the machine appearing in the Parc's own list, not a
    # response this pilot inspected: what the Console shows is the claim.
    click_then_wait(
        driver,
        "Confirmer",
        "return document.querySelectorAll('.yc-machine-button').length >= 1;",
        seconds=120,
        description="the machine appearing in the inventory",
    )
    report["attached"] = {
        "machine_id": machine_id,
        "read_back": "the machine is listed by the Console's own Parc view",
    }
    report["fleet_after"] = capture_screen(driver)


def freeze_definition(driver: Driver, slug: str, repository: str, port: int, report: dict) -> None:
    """Write a definition in the Console and freeze it.

    Nothing is pasted and nothing is assembled: the fields are the product's
    own, and freezing is the product's own gesture. The definition declares
    **no origin**, which is a configuration the product supports and enforces —
    a plan carrying an origin for a definition that consumes none is refused.
    That is what lets this proof stand up a real user service without an
    entrypoint, and it is a decision rather than a shortcut.
    """
    click_then_wait(driver, "Services", HEADING, "Services", description="the Services view")
    fill(
        driver,
        {
            "#definition-slug": slug,
            "#definition-repository": repository,
            "#definition-port": str(port),
            # The scratch the image demands under a read-only filesystem. The
            # application refuses to serve without it rather than degrading
            # quietly, so this line is what makes « the service answers » a
            # constat rather than a hope.
            "#definition-tmpfs": SCRATCH_DIRECTORY,
            "#definition-environment": "\n".join(
                [
                    f"YC_LAB_SLUG={slug}",
                    f"YC_LAB_LISTEN_PORT={port}",
                    f"YC_LAB_SCRATCH_DIR={SCRATCH_DIRECTORY}",
                ]
            ),
        },
    )
    # The consequences panel is the **only** door to freezing, and that is the
    # product's decision rather than a step this pilot could skip: the panel is
    # where the sentences a frozen revision commits to are read, and the freeze
    # button exists nowhere else. The button enables only once the core has
    # reviewed the draft, so the wait is on the button, not on a delay.
    wait_until(
        driver,
        "return [...document.querySelectorAll('button')].some("
        "(e) => e.textContent.trim() === 'Voir ce que la machine recevra' && !e.disabled);",
        seconds=120,
        label="the draft becoming reviewable",
    )
    click_then_wait(
        driver,
        "Voir ce que la machine recevra",
        "return document.querySelectorAll('.yc-sentence-list li').length > 0;",
        seconds=120,
        description="the consequences panel",
    )
    report["consequences"] = driver.execute(
        "return [...document.querySelectorAll('.yc-sentence-list li')]"
        ".map((e) => e.textContent.trim());"
    )
    # The effect names **this** definition. An earlier version waited for any
    # « Déployer cette révision » button to exist, and the second journey of a
    # run passed that wait instantly against the card the first journey had
    # frozen — a condition satisfied by the previous step is not a condition.
    click_then_wait(
        driver,
        "Geler cette révision",
        "return [...document.querySelectorAll('.yc-definition__slug')]"
        ".some((e) => e.textContent.trim() === arguments[0]);",
        seconds=180,
        description=f"the revision of « {slug} » freezing",
        argument=slug,
    )
    report["frozen"] = {"slug": slug, "by": "the Console's own freeze gesture"}


# The deploy button of **one** definition, found through the card that names it.
# A run freezes more than one definition, and every card carries a button with
# the same words: clicking « the first one that reads Déployer » deployed the
# wrong revision until this was scoped.
DEPLOY_THE_DEFINITION = """
const wanted = arguments[0];
const heading = [...document.querySelectorAll('.yc-definition__slug')]
  .find((element) => element.textContent.trim() === wanted);
if (!heading) return 'no definition named ' + wanted;
let node = heading;
for (let depth = 0; depth < 8 && node; depth += 1) {
  const button = [...node.querySelectorAll('button')]
    .find((candidate) => candidate.textContent.trim() === 'Déployer cette révision'
      && !candidate.disabled);
  if (button) { button.click(); return true; }
  node = node.parentElement;
}
return 'no deploy button beside ' + wanted;
"""


def deploy_gesture(driver: Driver, slug: str, report: dict) -> None:
    """« Déployer » — the one gesture that carries a slug and nothing else.

    No document is pasted, no digest is typed, no field is copied across: this
    is constat 2 of the contract, and it is exercised rather than asserted.
    """
    deadline = time.monotonic() + 60
    answer: object = None
    while time.monotonic() < deadline:
        answer = driver.execute(DEPLOY_THE_DEFINITION, slug)
        if answer is True:
            break
        time.sleep(0.25)
    if answer is not True:
        raise RuntimeError(f"the deploy gesture of « {slug} » was unreachable: {answer}")
    wait_until(
        driver,
        HEADING,
        "Plans",
        seconds=120,
        label="the Plans view reached by the deploy gesture",
    )
    carried = driver.execute(
        "const e = document.querySelector('#yc-plan-slug');"
        "return e ? e.value : null;"
    )
    report["deploy_gesture"] = {
        "slug_carried": carried,
        "claim": "the slug travelled; no plan, no document and no digest did",
    }


def build_pair(driver: Driver, machine: str, digest: str, port: int, report: dict) -> None:
    """Ask the Controller to build and freeze the pair, and read back phrases."""
    fill(
        driver,
        {
            "#yc-plan-machine": machine,
            "#yc-plan-image": digest,
            "#yc-plan-port": str(port),
        },
    )
    click_then_wait(
        driver,
        "Déployer",
        "return document.querySelectorAll('.yc-plan-lines li').length > 0;",
        seconds=180,
        description="the pair the Controller built",
    )
    lines = driver.execute(
        "return [...document.querySelectorAll('.yc-plan-lines li')]"
        ".map((e) => e.textContent.trim());"
    )
    report["pair"] = {
        "confirmation_lines": lines,
        "claim": "built and frozen by the Controller, rendered as sentences by the Console",
    }


def approve_in_native_window(driver: Driver, report: dict) -> None:
    """Open the real window, answer it through X11, and say what that attests."""
    click(driver, "Lire et approuver dans la fenêtre native")
    window = await_native_window()
    facts = native_window_facts(window)
    if facts["title"] != WINDOW_TITLE:
        raise RuntimeError(f"the window that opened is titled {facts['title']!r}")
    report["native_window"] = {
        **facts,
        "attests": "a separate GTK process really mapped this window; it is not the WebView",
        "does_not_attest": "that a human read the sentences it shows",
    }
    answer_native_window(window, "approve")
    wait_until(
        driver,
        "return [...document.querySelectorAll('*')].some("
        "(e) => e.children.length === 0"
        " && e.textContent.trim() === 'Approuvé dans la fenêtre native');",
        seconds=120,
        label="the core receiving the window's answer",
    )
    report["native_window"]["answered"] = "approve, by the window's own mnemonic (alt+a)"
    if not native_window_gone(window):
        raise RuntimeError("the native window is still mapped after it answered")


def sign_and_launch(driver: Driver, report: dict) -> None:
    """The one gesture whose effect leaves this machine.

    The effect is a dispatch **more** than the history already held, never « a
    dispatch exists »: the second journey of a run would otherwise be satisfied
    by the first one's record and would never notice its own submission was
    refused.
    """
    before = driver.execute("return document.querySelectorAll('.yc-dispatch').length;")
    before = before if isinstance(before, int) else 0
    click_then_wait(
        driver,
        "Signer et lancer",
        "return document.querySelectorAll('.yc-dispatch').length > arguments[0];",
        seconds=300,
        description=f"a dispatch beyond the {before} the history already held",
        argument=before,
    )
    # The history re-renders as the view reloads it, so the read is retried
    # rather than taken on the first frame: a null here is a lost observation,
    # not an absent dispatch.
    entry: object = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        entry = driver.execute(DISPATCH_SUMMARY)
        if entry:
            break
        time.sleep(0.5)
    if not entry:
        raise RuntimeError("the dispatch appeared and could not be read back")
    report["dispatch"] = entry


# What one dispatch row says, read as the human reads it: the journey in four
# steps, the sentence of its state, and the machine's own words when it spoke.
DISPATCH_SUMMARY = """
const entry = document.querySelector('.yc-dispatch');
if (!entry) return null;
const text = (selector) => {
  const node = entry.querySelector(selector);
  return node ? node.textContent.trim() : null;
};
return {
  machine: text('.yc-dispatch-machine'),
  operation: text('.yc-dispatch-operation'),
  journey: [...entry.querySelectorAll('.yc-journey li')].map((e) => e.textContent.trim()),
  state_sentence: text('.yc-prose'),
  machine_sentence: text('.yc-machine-sentence'),
  observation: text('.yc-observation'),
  facts: [...entry.querySelectorAll('.yc-dispatch-facts dt, .yc-dispatch-facts dd')]
    .map((e) => e.textContent.trim()),
};
"""


def capture_screen(driver: Driver) -> dict[str, object]:
    """The sentences the Console is showing right now, read from its own DOM.

    Refusals are rendered as phrases by this product rather than as codes, so
    what a stuck pilot needs is exactly the text a human would be reading.
    """
    try:
        return {
            "heading": driver.execute(HEADING),
            "alerts": driver.execute(
                "return [...document.querySelectorAll("
                "'[role=alert], .yc-error, .yc-alert, .yc-refusal, .yc-prose')]"
                ".map((e) => e.textContent.trim()).filter((t) => t.length).slice(0, 24);"
            ),
        }
    except Exception as failure:  # noqa: BLE001 — the capture must not mask the verdict
        return {"unreadable": f"{type(failure).__name__}: {failure}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--window-sheet", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--stage", default="associate")
    parser.add_argument("--secrets", required=True)
    parser.add_argument("--machine", default="")
    parser.add_argument("--slug", default="journal-de-bord")
    parser.add_argument("--repository", default="registry.lab.your-cloud.test/lab/synthetic-app")
    parser.add_argument("--container-port", type=int, default=8080)
    parser.add_argument("--local-port", type=int, default=18090)
    parser.add_argument("--digest", default="")
    arguments = parser.parse_args()

    report: dict[str, object] = {"stage": arguments.stage}
    driver = Driver(arguments.base_url, arguments.application)
    try:
        if arguments.stage == "associate":
            with open(arguments.window_sheet, encoding="utf-8") as handle:
                sheet = json.load(handle)
            phrase, recovery_code = reach_vault(driver, report)
            associate(driver, sheet, recovery_code, report)
            # The phrase of this run's synthetic vault, kept so the later
            # stages can open the same Console. It is a secret of this run
            # alone: mode 0600, never printed, and taken away by `remove`.
            with open(arguments.secrets, "w", encoding="utf-8") as handle:
                json.dump({"unlock_phrase": phrase}, handle)
            os.chmod(arguments.secrets, 0o600)
        else:
            with open(arguments.secrets, encoding="utf-8") as handle:
                phrase = json.load(handle)["unlock_phrase"]
            unlock(driver, phrase, report)
            select_infrastructure(driver)

        if arguments.stage == "journey":
            # The whole path, in one session, as one human would walk it.
            freeze_definition(
                driver, arguments.slug, arguments.repository, arguments.container_port, report
            )
            deploy_gesture(driver, arguments.slug, report)
            build_pair(driver, arguments.machine, arguments.digest, arguments.local_port, report)
            approve_in_native_window(driver, report)
            sign_and_launch(driver, report)
        if arguments.stage == "attach":
            # The Parc view is the first screen that reads the machines
            # projection, and the gate a machine enters the inventory through.
            # What it renders is captured whether it succeeds or refuses: a view
            # that cannot read its own Controller is a finding, not a step to
            # retry.
            attach_machine(driver, arguments.machine, report)
        status = 0
    except Exception as failure:  # noqa: BLE001 — the verdict must carry the reason
        report["failure"] = f"{type(failure).__name__}: {failure}"
        # What the product itself said, kept verbatim. A red that cannot name
        # the product's own refusal is a harness defect rather than a finding:
        # the sentence on the screen is the whole point of this palier.
        report["screen"] = capture_screen(driver)
        status = 1
    finally:
        driver.close()

    with open(arguments.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
