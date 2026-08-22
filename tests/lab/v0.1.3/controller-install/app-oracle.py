#!/usr/bin/env python3
"""Drive the real App along the whole command path, and judge what it shows.

This oracle pilots the **installed** product: the `.deb` built from this run's
sources, its own WebView process, its own native helper, its own vault. Nothing
of the App is replaced — no bundle served beside it, no IPC bridge stood in
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
import pathlib
import subprocess
import sys
import time
import urllib.parse

# ---------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 120


def request(base_url: str, method: str, path: str, body: object = None) -> object:
    """One bounded WebDriver call, returning the `value` the driver sent.

    It returns that value **whatever its type** — a string, a list, an object,
    `None` — and never a wrapper around it. An earlier version unwrapped
    dictionaries here and left the caller to unwrap again, so every script that
    returned an object read back as nothing at all: the dispatch summary of
    this proof was silently `null` from its first run. A transport that
    sometimes unwraps is a transport that lies about the shape of an answer.

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
        return None
    answer = json.loads(raw)
    value = answer.get("value")
    if isinstance(value, dict) and "error" in value:
        raise RuntimeError(f"{value.get('error')}: {value.get('message', '').strip()}")
    return value


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
        session = response if isinstance(response, dict) else {}
        self.session_id = session.get("sessionId")
        if not self.session_id:
            raise RuntimeError(f"the driver opened no session: {response!r}")

    def close(self) -> None:
        try:
            request(self.base_url, "DELETE", f"/session/{self.session_id}")
        except Exception:  # noqa: BLE001 — a lost session must not hide the verdict
            pass

    def execute(self, script: str, *arguments: object) -> object:
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": list(arguments)},
        )

    def execute_async(self, script: str, *arguments: object, seconds: int = 120) -> object:
        """Run a script that finishes by calling the callback it is handed.

        The synchronous form cannot await, and every command of this product is
        a promise: a diagnostic that could not await would only ever be able to
        say « a promise was created ».
        """
        request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/timeouts",
            {"script": seconds * 1000},
        )
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/async",
            {"script": script, "args": list(arguments)},
        )

    def screenshot(self) -> str:
        return str(request(self.base_url, "GET", f"/session/{self.session_id}/screenshot") or "")


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
    """From a cold App to the Infrastructures view, by the product's path.

    Nothing here is command path: it is the local access the human already has
    to cross before any of it exists. It is driven rather than seeded because a
    seeded vault would be an App this proof did not stand up.
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
        raise RuntimeError(f"the App generated {secrets!r} rather than two secrets")
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
    report["vault"] = "created by the App itself, on this run's own machine"
    return [phrase, recovery]


def unlock(driver: Driver, phrase: str, report: dict) -> None:
    """Open an App that already holds this run's vault and association.

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
    report["vault"] = "unlocked; this run's own, created by the App at the association stage"


INSTALL_RECORDER = """
if (window.__ycRecorder) { return 'already installed'; }
const internals = window.__TAURI_INTERNALS__;
const buffer = [];
const LIMIT = 400;
let perdues = 0;
const started = Date.now();
const installed = [];

// The transport, wrapped as well as the surface above it.
//
// Wrapping `__TAURI_INTERNALS__.invoke` alone recorded nothing at all — an
// empty tape while the application demonstrably worked — because the frontend
// bundle binds its reference when it loads, long before a WebDriver session
// exists to wrap anything. The IPC itself is a `fetch` to the `ipc:` scheme, and
// that call is made afresh every time, so it is the one place an observer that
// arrives late can still see everything.
if (typeof window.fetch === 'function') {
  const originalFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = String(typeof input === 'string' ? input : (input && input.url) || '');
    if (url.indexOf('ipc') === -1) { return originalFetch(input, init); }
    const at = Date.now() - started;
    const record = { at, name: 'ipc:' + url.split('/').pop(), via: 'fetch' };
    return originalFetch(input, init).then(
      (response) => {
        record.outcome = response.ok ? 'resolved' : 'rejected';
        record.code = 'http:' + response.status;
        record.millis = Date.now() - started - at;
        push(record);
        return response;
      },
      (error) => {
        record.outcome = 'threw'; record.code = codeOf(error);
        record.millis = Date.now() - started - at;
        push(record); throw error;
      },
    );
  };
  installed.push('fetch');
}

if (!internals || typeof internals.invoke !== 'function') {
  window.__ycRecorder = { buffer, started, lacune: () => perdues };
  return installed.length ? 'installed: ' + installed.join(',') : 'no IPC surface';
}
installed.push('invoke');
const original = internals.invoke.bind(internals);
internals.invoke = function (name, args, options) {
  const at = Date.now() - started;
  const record = { at, name, args: summarise(args) };
  let answer;
  try { answer = original(name, args, options); }
  catch (error) { record.outcome = 'threw'; record.code = codeOf(error); push(record); throw error; }
  if (!answer || typeof answer.then !== 'function') { record.outcome = 'value'; push(record); return answer; }
  return answer.then(
    (value) => {
      record.outcome = 'resolved';
      record.millis = Date.now() - started - at;
      // Le cycle de vie d'une session d'amorçage, et lui seul : ce n'est pas
      // un secret — c'est le vocabulaire que la clôture d'affaires publie et
      // que la vue traduit en phrases. Sans lui, une passe qui s'arrête laisse
      // déduire ce qu'elle aurait pu dire.
      if (value && typeof value === 'object' && typeof value.lifecycle === 'string') {
        record.lifecycle = value.lifecycle;
      }
      push(record);
      return value;
    },
    (error) => {
      record.outcome = 'rejected';
      record.code = codeOf(error);
      record.millis = Date.now() - started - at;
      push(record);
      throw error;
    },
  );
};
function push(record) {
  buffer.push(record);
  // **La lacune est déclarée, jamais silencieuse.** C'est la règle que le
  // produit s'applique à lui-même dans la chaîne d'observation : « une lacune
  // décrit explicitement les séquences supprimées lorsque le tampon atteint
  // une limite ». Un instrument qui tronque sans le dire transforme une mesure
  // en supposition — et le lecteur suivant lit une absence de trace comme une
  // trace d'absence. Mesuré le 22 août 2026 : une demi-journée passée sur trois
  // hypothèses qu'un compteur aurait départagées.
  if (buffer.length > LIMIT) { buffer.shift(); perdues += 1; }
}
function codeOf(error) {
  if (error && typeof error === 'object' && 'code' in error) { return error.code; }
  return String(error).slice(0, 120);
}
function summarise(args) {
  if (!args || typeof args !== 'object') { return null; }
  const kept = {};
  for (const [key, value] of Object.entries(args)) {
    // Never the values themselves: a recorder that copied a phrase or a code
    // would be a recorder that writes a secret into a proof artefact.
    kept[key] = typeof value === 'string' ? 'str:' + value.length : typeof value;
  }
  return kept;
}
window.__ycRecorder = { buffer, started, lacune: () => perdues };
return 'installed: ' + installed.join(',');
"""

READ_RECORDER = """
if (!window.__ycRecorder) { return null; }
// Le tampon ENTIER, borné à sa capacité et pas à une fenêtre plus étroite
// qu'elle. `slice(-60)` rendait les soixante dernières entrées d'un tampon de
// quatre cents : sur une étape qui dure cinq minutes, cela ne montrait que la
// dernière minute — et un blocage situé plus tôt devenait indevinable depuis
// l'artefact. Mesuré le 22 août 2026 : une expiration de session dont les
// artefacts ne pouvaient pas dire où le temps était parti.
// Le tampon ENTIER et sa lacune, ensemble. `slice(-60)` rendait les
// soixante dernières entrées d'un tampon de quatre cents : sur une étape de
// cinq minutes, la dernière minute seulement, et un blocage plus ancien
// devenait indevinable depuis l'artefact.
return { perdues: window.__ycRecorder.lacune(), limite: 400, bande: window.__ycRecorder.buffer };
"""


def install_recorder(driver: Driver, report: dict) -> None:
    report["recorder"] = driver.execute(INSTALL_RECORDER)


def read_recorder(driver: Driver) -> object:
    try:
        return driver.execute(READ_RECORDER)
    except Exception as failure:  # noqa: BLE001 — the tape must not hide the verdict
        return {"recorder_unreadable": f"{type(failure).__name__}: {failure}"}


# Which command of the product refuses, asked of the product's own IPC.
#
# A banner says « an operation was refused » and never which one, so a pilot
# that only reads banners can do nothing but guess — and guessing is what cost
# the previous session three wrong answers on this very symptom. This asks each
# read the views perform, one at a time, and keeps the code each one returns.
# It changes nothing: `__TAURI_INTERNALS__.invoke` is the same door the
# frontend's own `invoke` goes through.
PROBE_COMMANDS = """
const done = arguments[arguments.length - 1];
(async () => {
  const internals = window.__TAURI_INTERNALS__;
  if (!internals || typeof internals.invoke !== 'function') {
    return { unavailable: 'this build exposes no IPC surface to ask' };
  }
  const call = async (name, args) => {
    try { await internals.invoke(name, args || {}); return 'ok'; }
    catch (error) {
      if (error && typeof error === 'object' && 'code' in error) return error.code;
      return String(error);
    }
  };
  const answers = { app_status: await call('app_status') };
  let infrastructure = null;
  try {
    const status = await internals.invoke('app_status');
    infrastructure = (status.associations && status.associations[0])
      ? status.associations[0].infrastructure_id : null;
  } catch (error) { answers.status_error = String(error); }
  if (!infrastructure) { return answers; }
  answers.infrastructure_id = infrastructure;
  for (const name of ['read_machines', 'read_service_definitions', 'read_plan_dispatches',
                      'read_infrastructure', 'read_external_elements']) {
    answers[name] = await call(name, { infrastructureId: infrastructure });
  }
  return answers;
})().then(done, (error) => done({ probe_failed: String(error) }));
"""


def probe_commands(driver: Driver) -> object:
    """Name the refusal instead of inferring it from a banner."""
    try:
        return driver.execute_async(PROBE_COMMANDS)
    except Exception as failure:  # noqa: BLE001 — a probe must not mask the verdict
        return {"probe_unreadable": f"{type(failure).__name__}: {failure}"}


def capture_screen(driver: Driver) -> dict[str, object]:
    """The sentences the App is showing right now, read from its own DOM.

    Refusals are rendered as phrases by this product rather than as codes, so
    what a stuck pilot needs is exactly the text a human would be reading.
    """
    try:
        return {
            "heading": driver.execute(HEADING),
            # Every button the screen offers, with the two things that decide
            # whether a gesture is reachable: the exact text and whether it is
            # disabled. A pilot that reports « no button reads X » without this
            # cannot tell an absent control from one that is merely busy, or
            # from one whose label changed while it loads.
            "buttons": driver.execute(
                "return [...document.querySelectorAll('button')].map((e) => ({"
                "  text: e.textContent.trim().slice(0, 60),"
                "  disabled: e.disabled,"
                "}));"
            ),
            "alerts": driver.execute(
                "return [...document.querySelectorAll("
                "'[role=alert], .yc-error, .yc-alert, .yc-refusal, .yc-prose')]"
                ".map((e) => e.textContent.trim()).filter((t) => t.length).slice(0, 24);"
            ),
        }
    except Exception as failure:  # noqa: BLE001 — the capture must not mask the verdict
        return {"unreadable": f"{type(failure).__name__}: {failure}"}



# ---------------------------------------------------------------------------
# Le pilotage de la fenêtre d'accès personnel, par le chemin du fichier de clé.
#
# La séquence est celle que `personal_access_contract.rs` a éprouvée (§
# pilotage) : alt+o ouvre le sélecteur natif, la barre d'emplacement se nomme
# au clavier, la passphrase se tape dans sa propre fenêtre, puis alt+a accepte
# l'accès. XTEST toujours (`key --clearmodifiers` après `windowfocus --sync`),
# jamais `key --window` : GTK ignore les événements envoyés. Ce mécanisme est
# nommé au rapport avec sa limite : la sélection d'une identité d'AGENT au
# clavier n'est pas attestée par cette preuve — elle reste couverte côté
# transport par le contrat de #52-#54.
# ---------------------------------------------------------------------------

ACCESS_WINDOW_TITLE = "Your Cloud — autoriser l’accès personnel"
SELECTOR_TITLE = "Your Cloud — choisir la clé OpenSSH chiffrée"
PASSPHRASE_TITLE = "Your Cloud — passphrase de la clé SSH"
SUDO_TITLE = "Your Cloud — mot de passe sudo"


def window_titled(title: str) -> str | None:
    """One visible window carrying exactly `title`, read back from X."""
    listing = xdotool("search", "--onlyvisible", "--name", ".")
    if listing is None:
        return None
    for window in listing.split():
        name = xdotool("getwindowname", window)
        if name is not None and name.strip() == title:
            return window
    return None


def await_window(title: str, seconds: int = 90) -> str:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        window = window_titled(title)
        if window is not None:
            # Une fenêtre juste mappée n'est pas encore une fenêtre qui reçoit
            # une frappe : le toolkit construit encore ce qu'elle atteindrait.
            time.sleep(0.5)
            return window
        time.sleep(0.25)
    raise RuntimeError(f"no window titled «{title}» ever appeared")


def window_gone(title: str, seconds: int = 120) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if window_titled(title) is None:
            return True
        time.sleep(0.5)
    return False


def press(window: str, key: str) -> None:
    """Focus synchrone puis frappe XTEST — la séquence du contrat, en Python."""
    if xdotool("windowraise", window) is None:
        raise RuntimeError(f"the window {window} could not be raised")
    if xdotool("windowfocus", "--sync", window) is None:
        raise RuntimeError(f"the window {window} could not take the focus")
    if xdotool("key", "--clearmodifiers", key) is None:
        raise RuntimeError(f"the key {key} could not be sent")


def type_text(window: str, text: str) -> None:
    if xdotool("windowfocus", "--sync", window) is None:
        raise RuntimeError(f"the window {window} could not take the focus")
    if xdotool("type", "--clearmodifiers", "--delay", "40", text) is None:
        raise RuntimeError("the text could not be typed")


def capture_processes(moment: str) -> dict[str, object]:
    """L'arbre des processus tel qu'il est à cet instant, filiation comprise.

    La question à laquelle cette capture répond est précise : quand le verdict
    de succès exige que TOUT le groupe du helper soit parti, qui reste dans ce
    groupe, et de qui descend-il ? Un bus de session né du helper est un
    artefact de l'écran nu ; un bus préexistant dont le helper n'est que le
    client ne devrait jamais peupler son groupe.
    """
    listing = subprocess.run(
        ["ps", "-eo", "pid,ppid,pgid,sid,stat,comm,args"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    kept = [
        line.rstrip()
        for line in listing.splitlines()
        if any(
            needle in line
            for needle in ("your-cloud", "dbus", "dconf", "at-spi", "Xvfb", "xvfb")
        )
    ]
    return {
        "moment": moment,
        "bus_address": os.environ.get("DBUS_SESSION_BUS_ADDRESS", "(absente)"),
        "processes": kept,
    }


# L'origine du chronomètre d'une étape. Elle est posée au clic, et c'est ce qui
# rend les horodatages des fenêtres comparables à la borne de session.
STEP_STARTED: float = time.monotonic()


def note_window(report: dict, label: str, event: str) -> None:
    """Une fenêtre native, et QUAND elle est arrivée ou repartie.

    Une liste de titres ne dit pas où le temps est parti : la passe du 22 août
    2026 a expiré à 300 s, et son artefact ne portait qu'un titre sans instant.
    Trois causes possibles restaient indépartageables faute de cette ligne.
    """
    report.setdefault("native_windows", []).append(
        {"window": label, "event": event, "at_s": round(time.monotonic() - STEP_STARTED, 1)}
    )


def answer_access_window(key_file: str, passphrase: str, report: dict) -> None:
    """Nomme le fichier de clé, tape la passphrase, autorise l'accès."""
    window = await_window(ACCESS_WINDOW_TITLE)
    note_window(report, ACCESS_WINDOW_TITLE, "apparue")
    press(window, "alt+o")
    selector = await_window(SELECTOR_TITLE, seconds=30)
    note_window(report, SELECTOR_TITLE, "apparue")
    # La barre d'emplacement du sélecteur : ctrl+l la nomme, le chemin se tape,
    # Return répond ; alt+o en secours quand le toolkit n'active pas seul.
    press(selector, "ctrl+l")
    press(selector, "ctrl+a")
    type_text(selector, key_file)
    press(selector, "Return")
    if not window_gone(SELECTOR_TITLE, seconds=2):
        press(selector, "alt+o")
    if not window_gone(SELECTOR_TITLE, seconds=10):
        raise RuntimeError("the key selector never answered the named file")
    note_window(report, SELECTOR_TITLE, "fermée")
    # L'ordre du contrat : le fichier est nommé, PUIS l'accès est accepté sur
    # la fenêtre d'accès — et c'est cette acceptation, l'ouverture validée du
    # fichier, qui fait apparaître la fenêtre de passphrase. L'inverse laissait
    # attendre une passphrase que rien n'avait demandée.
    press(window, "alt+a")
    passphrase_window = await_window(PASSPHRASE_TITLE, seconds=30)
    note_window(report, PASSPHRASE_TITLE, "apparue")
    type_text(passphrase_window, passphrase)
    press(passphrase_window, "alt+c")
    if not window_gone(PASSPHRASE_TITLE, seconds=30):
        raise RuntimeError("the passphrase window never accepted")
    note_window(report, PASSPHRASE_TITLE, "fermée")
    if not window_gone(ACCESS_WINDOW_TITLE, seconds=60):
        raise RuntimeError("the access window never closed after the passphrase")
    note_window(report, ACCESS_WINDOW_TITLE, "fermée")
    # L'instant où le verdict se joue : le helper vient de finir, et ce qui
    # reste de son groupe décide si son succès est reconnu.
    report.setdefault("process_tree", []).append(
        capture_processes("just after the access window closed")
    )


# ---------------------------------------------------------------------------
# Le parcours « Créer une infrastructure », étape par étape.
# ---------------------------------------------------------------------------

# Les deux consentements de l'écran, depuis #219 — ils étaient trois.
#
# Ces chaînes sont les YEUX du harnais, pas un artefact figé : elles doivent
# dire ce que l'écran peint AUJOURD'HUI, sans quoi l'oracle cherche un bouton
# qui n'existe plus et la preuve rougit sur son propre vocabulaire. Cinq des
# six chaînes d'avant sont devenues fausses le jour où les consentements ont
# fusionné, et c'est la preuve de #220 qui l'a mesuré en confrontant les deux.
#
# Le libellé du bouton dérive du titre de l'étape dans la vue : le figer ici
# à la main serait une seconde définition, et les deux finiraient par diverger.
STEP_BUTTONS = {
    "audit": "Commencer : se connecter et examiner la machine",
    "commission": "Continuer : installer et mettre en service le controller",
}
STEP_SENTENCES = {
    "audit": "La machine a été auditée en lecture seule. Rien n’a été écrit.",
    "commission": "Le lot est posé et vérifié, et le Controller est actif sur la machine.",
}
def sentence_shown(wanted: str) -> str:
    """Le script qui répond LA PHRASE quand elle est à l'écran, sinon rien.

    Il rend la phrase elle-même plutôt qu'un booléen : `wait_until` compare ce
    qu'un script rend à ce qu'on attend, et un script qui répondait `true`
    faisait comparer `True` à une phrase — jamais égaux, et l'attente
    expirait sur un écran qui montrait pourtant la bonne chose. Mesuré le
    19 août 2026 : l'audit avait réussi, l'oracle ne le voyait pas.
    """
    return (
        "return [...document.querySelectorAll('p')]"
        f".map((element) => element.textContent.trim()).find((text) => text === {wanted!r})"
        " ?? null;"
    )


# Le bandeau de refus, tel qu'un humain le lit. Le titre et la phrase sont deux
# nœuds du même bandeau, et c'est la PHRASE qui porte ce que le produit dit —
# le titre ne fait que la ranger. Rendre `null` plutôt que du vide quand il n'y
# a pas de bandeau distingue « rien n'a refusé » de « quelque chose a refusé
# sans rien dire », qui ne sont pas le même constat.
FAILURE_SENTENCE = """
const banner = [...document.querySelectorAll('[role=alert], .yc-alert, .yc-error')]
  .map((element) => element.textContent.trim())
  .find((text) => text.startsWith('Cette étape n’a pas abouti'));
if (!banner) { return null; }
return banner.slice('Cette étape n’a pas abouti'.length).trim();
"""


def await_failure(driver: Driver, seconds: int = 600, label: str = "") -> str:
    """La phrase de refus que l'écran finit par montrer, ou l'échec de l'attente."""
    deadline = time.monotonic() + seconds
    last: object = None
    while time.monotonic() < deadline:
        try:
            last = driver.execute(FAILURE_SENTENCE)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            last = "<transport cut>"
        if isinstance(last, str) and last:
            return last
        time.sleep(0.25)
    raise RuntimeError(f"{label or 'a refusal'}: never shown; last value was {last!r}")


def await_outcome(driver: Driver, step: str, seconds: int = 600) -> str:
    """L'issue de l'étape, quelle qu'elle soit : sa phrase de réussite ou son refus.

    Les deux sont attendues ENSEMBLE, et la première venue gagne. Une attente
    qui ne guetterait que la réussite passerait ses dix minutes devant un écran
    qui a déjà refusé, puis dirait « la phrase n'est jamais venue » — ce qui est
    vrai et n'apprend rien. Mesuré le 19 août 2026 : le refus de la pose était à
    l'écran en quelques secondes, et l'oracle a attendu 600 s pour l'ignorer.
    """
    wanted = STEP_SENTENCES[step]
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            shown = driver.execute(sentence_shown(wanted))
            if shown == wanted:
                return wanted
            refusal = driver.execute(FAILURE_SENTENCE)
            if isinstance(refusal, str) and refusal:
                return refusal
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"the {step} step ended on neither its phrase nor a refusal")


def open_creation(driver: Driver, target: dict, report: dict) -> None:
    """De la vue Infrastructures au formulaire rempli, en phrases."""
    click_then_wait(
        driver,
        "Créer une infrastructure",
        HEADING,
        "Créer une infrastructure",
        description="the creation journey",
    )
    fill(
        driver,
        {
            "#ci-host": target["host"],
            "#ci-port": str(target["port"]),
            "#ci-username": target["username"],
            "#ci-hostkey": target["host_key"],
            "#ci-listen": target["listen"],
            "#ci-allowed": target["allowed_source"],
            "#ci-relay": target["relay_endpoint"],
        },
    )
    report["declared"] = {k: v for k, v in target.items() if k != "host_key"}


def run_step(
    driver: Driver,
    step: str,
    key_file: str,
    passphrase: str,
    report: dict,
    expect_sudo_password: str | None = None,
) -> None:
    """Une étape du parcours : le bouton, la fenêtre, l'issue en phrase."""
    # Le patch du recorder est réinstallé ici, et son verdict est retenu : une
    # WebView qui rechargerait entre deux vues emporterait le patch avec elle,
    # et une bande muette se lirait alors comme « aucun appel » au lieu de
    # « plus personne n'écoutait ». La question se répond par une mesure.
    report.setdefault("recorder_reinstall", {})[step] = driver.execute(
        INSTALL_RECORDER.replace("const buffer = [];", "const buffer = (window.__ycRecorder && window.__ycRecorder.buffer) || [];")
    )
    global STEP_STARTED
    STEP_STARTED = time.monotonic()
    click(driver, STEP_BUTTONS[step])
    answer_access_window(key_file, passphrase, report)
    if expect_sudo_password is not None:
        sudo_window = await_window(SUDO_TITLE, seconds=60)
        note_window(report, SUDO_TITLE, "apparue")
        type_text(sudo_window, expect_sudo_password)
        press(sudo_window, "alt+c")
        if not window_gone(SUDO_TITLE, seconds=30):
            raise RuntimeError("the sudo password window never accepted")
        note_window(report, SUDO_TITLE, "fermée")
    outcome = await_outcome(driver, step, seconds=600)
    note_window(report, f"issue:{step}", outcome[:60])
    report.setdefault("tape_by_step", {})[step] = read_recorder(driver)
    if outcome != STEP_SENTENCES[step]:
        raise RuntimeError(f"the {step} step was refused: {outcome}")
    report.setdefault("steps", {})[step] = outcome


def refused_step(
    driver: Driver,
    step: str,
    key_file: str,
    passphrase: str,
    report: dict,
    window_grace: int = 90,
    expect_sudo_password: str | None = None,
) -> None:
    """Une étape dont on attend le REFUS, et dont on mesure quand il tombe.

    Le constat n°10 du contrat dit « refusé avant la fenêtre : aucun
    consentement n'est demandé ». Cette fonction ne le suppose pas : elle
    attend la fenêtre d'accès pendant `window_grace`, écrit si elle est venue
    et au bout de combien de temps, et ne la pilote QUE si elle est là. Une
    fenêtre absente est le constat ; une fenêtre présente est un autre constat,
    et c'est le rapport qui en tire les conséquences — pas cet oracle.
    """
    click(driver, STEP_BUTTONS[step])
    # La fenêtre et le bandeau sont guettés ENSEMBLE, et le premier venu est
    # le constat : un refus qui tombe avant la fenêtre — celui que le contrat
    # exige — se mesure ici comme « bandeau sans fenêtre », et un refus qui
    # attendrait la fenêtre se mesure comme « fenêtre d'abord ». Une attente
    # qui ne guettait que la fenêtre brûlait sa grâce entière devant un refus
    # déjà affiché.
    started = time.monotonic()
    deadline = started + window_grace
    appeared: float | None = None
    refusal_first: str | None = None
    while time.monotonic() < deadline:
        if window_titled(ACCESS_WINDOW_TITLE) is not None:
            appeared = time.monotonic() - started
            break
        try:
            shown = driver.execute(FAILURE_SENTENCE)
        except (http.client.RemoteDisconnected, ConnectionResetError):
            shown = None
        if isinstance(shown, str) and shown:
            refusal_first = shown
            break
        time.sleep(0.25)
    measured = {
        "step": step,
        "access_window_opened": appeared is not None,
        "seconds_before_window": None if appeared is None else round(appeared, 2),
        "seconds_before_refusal": None
        if refusal_first is None
        else round(time.monotonic() - started, 2),
        "window_grace_seconds": window_grace,
    }
    if appeared is not None:
        # Elle est là : un humain la lirait et l'accepterait, donc l'oracle
        # l'accepte — c'est le seul moyen de savoir ce que le refus devient
        # APRÈS un consentement qui n'aurait pas dû être demandé.
        measured["acceptance_button_reached"] = "alt+a, mnémonique du produit"
        answer_access_window(key_file, passphrase, report)
        # **Le secret aussi, quand le refus attendu est celui de la machine.**
        # Sans cette réponse, la fenêtre de mot de passe reste ouverte, le
        # helper attend, et la session expire : on mesure alors « personne n'a
        # répondu » en croyant mesurer « la machine a refusé ». Mesuré le
        # 22 août 2026 — la phrase rendue était l'expiration, pas le refus.
        if expect_sudo_password is not None:
            # **Sa présence est la mesure, pas une précondition.** Un refus
            # jugé au prévol NON SECRET n'ouvre jamais cette fenêtre — c'est
            # même ce qui établit qu'aucun secret n'est parti. Un `await` qui
            # lèverait sur son absence transformerait donc le constat le plus
            # fort en erreur de harnais. On l'attend, on note ce qu'on trouve,
            # et on ne répond que si elle est là.
            sudo_deadline = time.monotonic() + 45
            sudo_window = None
            while time.monotonic() < sudo_deadline:
                sudo_window = window_titled(SUDO_TITLE)
                if sudo_window is not None:
                    break
                shown = None
                try:
                    shown = driver.execute(FAILURE_SENTENCE)
                except (http.client.RemoteDisconnected, ConnectionResetError):
                    pass
                if isinstance(shown, str) and shown:
                    break
                time.sleep(0.25)
            measured["sudo_window_opened"] = sudo_window is not None
            if sudo_window is not None:
                time.sleep(0.5)
                note_window(report, SUDO_TITLE, "apparue")
                type_text(sudo_window, expect_sudo_password)
                press(sudo_window, "alt+c")
                measured["sudo_window_answered"] = True
    measured["refusal"] = (
        refusal_first
        if refusal_first is not None
        else await_failure(driver, label=f"the {step} refusal")
    )
    report.setdefault("refusals", []).append(measured)


def refusals(driver: Driver, arguments, target: dict, passphrase: str, report: dict) -> None:
    """Un refus hostile à l'écran, et **où il tombe**.

    Les deux ne sont pas la même propriété, et la seconde est la plus forte :
    « la fenêtre a nommé sa cause » dit que l'humain sait quoi faire ; « le
    refus est tombé AVANT toute fenêtre » dit que rien n'a même été tenté, donc
    que la machine n'a rien vu. Les comptes hostiles ne tombent pas tous au
    même endroit, et c'est le rapport qui doit le dire pour chacun plutôt que
    de les traiter en bloc.

    `refused_step` mesure les deux — fenêtre ouverte ou non, l'instant de
    chacune — et n'accepte la fenêtre que si elle est venue.
    """
    reach_vault(driver, report)
    open_creation(driver, target, report)
    refused_step(
        driver,
        "audit",
        arguments.key_file,
        passphrase,
        report,
        expect_sudo_password=(
            pathlib.Path(arguments.sudo_password_file).read_text().rstrip("\n")
            if arguments.sudo_password_file
            else None
        ),
    )


def asymmetry(driver: Driver, arguments, target: dict, passphrase: str, report: dict) -> None:
    """Le constat n°10, dans une seule passe : le même compte, deux issues.

    Le compte porté par `--username` est ici l'étroit — son entrée sudoers ne
    nomme que la sonde d'identité. L'audit doit lui suffire, la pose doit lui
    être refusée, et c'est l'ASYMÉTRIE qui est le constat : deux mesures sur
    la même session, jamais deux passes qu'on rapprocherait après coup.
    """
    reach_vault(driver, report)
    open_creation(driver, target, report)
    run_step(driver, "audit", arguments.key_file, passphrase, report)
    report["audit_with_narrow_entry"] = (
        "l'audit rend sa phrase avec une entrée sudoers qui ne nomme que la sonde"
    )
    refused_step(driver, "commission", arguments.key_file, passphrase, report)


def hostile(driver: Driver, arguments, target: dict, passphrase: str, report: dict) -> None:
    """Le constat n°3 : un lot altéré est refusé, et la cible n'est pas touchée.

    L'altération est posée hors de cet oracle — c'est le `prove` qui réécrit un
    octet du lot embarqué de l'App installée, parce que c'est une mutation
    de MACHINE et qu'elle doit être défaite même si cette passe meurt. Ce que
    l'oracle fait ici est ce qu'un humain ferait : jouer la pose, et lire.
    """
    reach_vault(driver, report)
    open_creation(driver, target, report)
    run_step(driver, "audit", arguments.key_file, passphrase, report)
    refused_step(driver, "commission", arguments.key_file, passphrase, report)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--output", required=True)
    parser.add_argument("--secrets", required=True)
    parser.add_argument(
        "--stage",
        required=True,
        choices=["journey", "refusals", "asymmetry", "hostile"],
    )
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, default=22)
    parser.add_argument("--username", required=True)
    parser.add_argument("--host-key", required=True)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--allowed-source", required=True)
    parser.add_argument("--relay-endpoint", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--passphrase-file", required=True)
    # Le mot de passe sudo du compte prêté, quand ce compte en exige un —
    # c'est le cas du compte administrateur ORDINAIRE d'une Debian, membre du
    # groupe `sudo` : sa politique ne renonce pas à l'authentification. La
    # preuve du palier (#147) prête un compte sans mot de passe et n'en passe
    # aucun ; l'option reste donc absente par défaut, et ce chemin inchangé.
    parser.add_argument("--sudo-password-file", default=None)
    arguments = parser.parse_args()

    passphrase = pathlib.Path(arguments.passphrase_file).read_text()
    sudo_password = (
        pathlib.Path(arguments.sudo_password_file).read_text().rstrip("\n")
        if arguments.sudo_password_file
        else None
    )
    report: dict = {"stage": arguments.stage, "mechanism": (
        "WebDriver (tauri-driver → WebKitWebDriver) pour la WebView ; xdotool "
        "XTEST pour les fenêtres natives, par le chemin du fichier de clé. "
        "Non attesté par ce pilotage : la sélection d'une identité d'agent au "
        "clavier, couverte côté transport par le contrat de #52-#54."
    )}
    target = {
        "host": arguments.target_host,
        "port": arguments.target_port,
        "username": arguments.username,
        "host_key": arguments.host_key,
        "listen": arguments.listen,
        "allowed_source": arguments.allowed_source,
        "relay_endpoint": arguments.relay_endpoint,
    }

    driver = Driver(arguments.base_url, arguments.application)
    try:
        install_recorder(driver, report)
        if arguments.stage == "journey":
            phrase, recovery = reach_vault(driver, report)
            pathlib.Path(arguments.secrets).write_text(f"{phrase}\n{recovery}\n")
            os.chmod(arguments.secrets, 0o600)
            open_creation(driver, target, report)
            for step in ["audit", "commission"]:
                run_step(
                    driver,
                    step,
                    arguments.key_file,
                    passphrase,
                    report,
                    expect_sudo_password=sudo_password,
                )
        elif arguments.stage == "refusals":
            refusals(driver, arguments, target, passphrase, report)
        elif arguments.stage == "asymmetry":
            asymmetry(driver, arguments, target, passphrase, report)
        else:
            hostile(driver, arguments, target, passphrase, report)
        report["outcome"] = f"{arguments.stage}_complete"
        return 0
    except Exception as error:  # noqa: BLE001 — l'échec entier appartient au rapport.
        report["failure"] = repr(error)
        report.setdefault("process_tree", []).append(capture_processes("at the failure"))
        try:
            report["screen"] = capture_screen(driver)
            report["commands"] = probe_commands(driver)
            report["tape"] = read_recorder(driver)
        except Exception as inner:  # noqa: BLE001
            report["capture_failure"] = repr(inner)
        return 1
    finally:
        pathlib.Path(arguments.output).write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        driver.close()


if __name__ == "__main__":
    raise SystemExit(main())
