#!/usr/bin/env python3
"""Measure the Console frontend's geometry in WebKitGTK, at both contractual
window sizes, with the text at 100 % and at 200 %, on hostile labels.

Two oracles run on every case and both must be silent.

The DOM oracle asks the engine what it laid out: what is clipped, what overlaps,
what leaves the viewport, what the page's own scroll width is, and where the
keyboard goes. It is the only one of the two that can name an element.

The raster guard asks the compositor what it painted. It exists because the DOM
and the painted surface have already disagreed once on this project, under
WebKitGTK on Xvfb, and a measurement that only ever reads `getBoundingClientRect`
cannot see that disagreement. It looks for ink sliced along a clipping boundary
and for ink pressed against the window's side edges — the exact shape of the
defect `#56` records.

Neither oracle claims WCAG conformance. They claim what they measure.
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import pathlib
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# A capture that is a flat rectangle, or nearly black, is a compositing failure
# and not a layout to inspect. The three bounds are the ones the installed-UI
# proof already uses, so a corrupt capture fails here the same way it fails there.
MIN_DISTINCT_RGB = 256
MAX_DOMINANT_RGB_RATIO = 0.995
MAX_EXACT_BLACK_RATIO = 0.10

# Ink is a pixel that differs from the dominant colour of the line it sits on by
# more than this, in the sum of the three channels. Antialiasing produces a few
# faint pixels around every glyph; a sliced glyph produces a solid run.
INK_DISTANCE = 40
INK_RUN = 4

CONTROL_SELECTOR = 'button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

# The seven contractual views of `docs/objectifs/v1/CONTRAT-V0.0.3.md`, plus the
# state of the first one that displays the two local secrets, plus the eighth
# view `docs/architecture/RESPONSABILITE-EXTERNE.md` adds — named there rather
# than in the older contract, because an increment that rewrote another's
# contract would erase what that one had proven. Each case
# names the path a human takes to reach it, because a view reached by setting a
# variable proves nothing about the navigation that leads to it.
VIEWS = (
    {
        "id": "local-access",
        "contract_view": 1,
        "state": "uninitialized",
        "clicks": (),
        "heading": "Accès local",
    },
    {
        "id": "local-access-secrets",
        "contract_view": 1,
        "state": "uninitialized",
        "clicks": ("Générer les secrets locaux",),
        "heading": "Accès local",
        "requires": ".yc-secret",
    },
    {
        "id": "infrastructures",
        "contract_view": 2,
        "state": "unlocked",
        "clicks": (),
        "heading": "Infrastructures",
    },
    {
        "id": "association",
        "contract_view": 3,
        "state": "unlocked",
        "clicks": ("Associer",),
        "heading": "Association ou récupération",
    },
    {
        "id": "summary",
        "contract_view": 4,
        "state": "unlocked",
        "clicks": ("Ouvrir",),
        "heading": "Synthèse",
    },
    {
        "id": "fleet",
        "contract_view": 5,
        "state": "unlocked",
        "clicks": ("Ouvrir", "Parc"),
        "heading": "Parc",
    },
    {
        "id": "observations",
        "contract_view": 6,
        "state": "unlocked",
        "clicks": ("Ouvrir", "Observations"),
        "heading": "Observations",
    },
    {
        "id": "profile",
        "contract_view": 7,
        "state": "unlocked",
        "clicks": ("Ouvrir", "Profil et sessions"),
        "heading": "Profil et sessions",
    },
    {
        "id": "external",
        "contract_view": 8,
        "state": "unlocked",
        "clicks": ("Ouvrir", "Éléments externes"),
        "heading": "Éléments externes",
    },
)

SIZES = ((1280, 800), (640, 560))
ZOOMS = (100, 200)


# --------------------------------------------------------------------------
# WebDriver, spoken directly. The repository already talks to WebKitWebDriver
# this way in `tests/lab/v0.0.3/console-ui-proof.py`; a second client library
# would be a second thing to trust.


def request(base_url: str, method: str, path: str, payload: object | None = None) -> object:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    call = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(call, timeout=60) as response:
            document = json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"WebDriver {method} {path} failed: {error.code} {detail}") from error
    return document.get("value")


class Driver:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        response = request(
            self.base_url,
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": {"webkitgtk:browserOptions": {"args": ["--automation"]}}}},
        )
        self.session_id = response["sessionId"]
        self.engine = f"{response.get('capabilities', {}).get('browserName', '?')} " f"{response.get('capabilities', {}).get('browserVersion', '?')}"

    def close(self) -> None:
        request(self.base_url, "DELETE", f"/session/{self.session_id}")

    def go(self, url: str) -> None:
        request(self.base_url, "POST", f"/session/{self.session_id}/url", {"url": url})

    def execute(self, script: str, *arguments: object) -> object:
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/execute/sync",
            {"script": script, "args": list(arguments)},
        )

    def set_rect(self, width: int, height: int) -> dict[str, int]:
        return request(
            self.base_url,
            "POST",
            f"/session/{self.session_id}/window/rect",
            {"x": 0, "y": 0, "width": width, "height": height},
        )

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
                            {"type": "keyDown", "value": ""},
                            {"type": "keyUp", "value": ""},
                        ],
                    }
                ]
            },
        )

    def screenshot(self) -> bytes:
        encoded = request(self.base_url, "GET", f"/session/{self.session_id}/screenshot")
        return base64.b64decode(encoded, validate=True)

    def wait_for_paint(self) -> None:
        # `execute/sync` cannot await. The font promise and two frames are read
        # through a polled flag instead, which keeps the call synchronous.
        self.execute(
            "window.__ycPainted = false;"
            "Promise.resolve(document.fonts ? document.fonts.ready : null).then(() =>"
            " requestAnimationFrame(() => requestAnimationFrame(() => { window.__ycPainted = true; })));"
            "return true;"
        )
        for _ in range(200):
            if self.execute("return window.__ycPainted === true;") is True:
                return
            time.sleep(0.05)
        raise RuntimeError("the page never reported a painted frame")

    def restore_keyboard_focus(self) -> None:
        """Give the browser window the X input focus back.

        There is no window manager on the virtual screen, and resizing the window
        leaves it without input focus: `document.hasFocus()` becomes false, `:focus`
        stops matching and no ring is painted. That is a property of a bare X
        server, not of the product, and a proof that read it as a missing focus
        ring would be reporting its own harness. `xdotool` sets the input focus
        directly, which is what a window manager would have done.
        """
        if self.execute("return document.hasFocus();") is True:
            return
        listing = subprocess.run(
            ["xdotool", "search", "--onlyvisible", "--name", "."],
            capture_output=True,
            text=True,
            check=False,
        )
        for window in listing.stdout.split():
            subprocess.run(["xdotool", "windowfocus", window], capture_output=True, check=False)
        for _ in range(30):
            if self.execute("return document.hasFocus();") is True:
                return
            time.sleep(0.1)
        raise RuntimeError("the browser window never regained the keyboard focus")

    def viewport(self, width: int, height: int) -> dict[str, int]:
        """Set the *viewport* to an exact size, not the window."""
        self.set_rect(width, height)
        for _ in range(6):
            inner = self.execute(
                "return {w: window.innerWidth, h: window.innerHeight,"
                " ow: window.outerWidth, oh: window.outerHeight};"
            )
            delta_w = width - int(inner["w"])
            delta_h = height - int(inner["h"])
            if delta_w == 0 and delta_h == 0:
                return {"width": width, "height": height}
            rect = request(self.base_url, "GET", f"/session/{self.session_id}/window/rect")
            self.set_rect(int(rect["width"]) + delta_w, int(rect["height"]) + delta_h)
            time.sleep(0.1)
        raise RuntimeError(f"the viewport never settled on {width}x{height}")


# --------------------------------------------------------------------------
# The DOM oracle.

MEASURE_SCRIPT = r"""
const CONTROL = arguments[0];
const root = document.documentElement;
const body = document.body;
window.scrollTo(0, 0);

function describe(el) {
  const id = el.id ? '#' + el.id : '';
  const raw = typeof el.className === 'string' ? el.className.trim() : '';
  const cls = raw ? '.' + raw.split(/\s+/u).join('.') : '';
  const text = (el.textContent || '').replace(/\s+/gu, ' ').trim().slice(0, 72);
  return { selector: el.tagName.toLowerCase() + id + cls, text: text };
}

function laidOut(el) {
  const r = el.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) return false;
  const s = getComputedStyle(el);
  return s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0.01;
}

const clipping = [];
const clipped = [];
for (const el of document.querySelectorAll('*')) {
  if (el === root || el === body) continue;
  if (el.closest('svg')) continue;
  const r = el.getBoundingClientRect();
  if (r.width <= 2 || r.height <= 2) continue;
  const s = getComputedStyle(el);
  if (s.visibility === 'hidden' || s.display === 'none') continue;
  const cutsX = s.overflowX !== 'visible';
  const cutsY = s.overflowY !== 'visible';
  const control = ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName);
  if ((cutsX || cutsY) && !control) {
    clipping.push(Object.assign(describe(el), {
      left: r.left + parseFloat(s.borderLeftWidth || '0'),
      top: r.top + parseFloat(s.borderTopWidth || '0'),
      client_width: el.clientWidth,
      client_height: el.clientHeight,
      cuts_x: cutsX,
      cuts_y: cutsY
    }));
  }
  if (control) continue;
  const held = s.whiteSpace === 'nowrap' || s.whiteSpace === 'pre' || s.textOverflow === 'ellipsis';
  if ((cutsX || held) && el.scrollWidth > el.clientWidth + 1) {
    clipped.push(Object.assign(describe(el), {
      axis: 'x', scroll: el.scrollWidth, client: el.clientWidth
    }));
  }
  if (cutsY && el.scrollHeight > el.clientHeight + 1) {
    clipped.push(Object.assign(describe(el), {
      axis: 'y', scroll: el.scrollHeight, client: el.clientHeight
    }));
  }
}

const controls = [...document.querySelectorAll(CONTROL)].filter(laidOut);
const overlaps = [];
for (let i = 0; i < controls.length; i += 1) {
  for (let j = i + 1; j < controls.length; j += 1) {
    const a = controls[i], b = controls[j];
    if (a.contains(b) || b.contains(a)) continue;
    const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
    const w = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
    const h = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
    if (w > 1 && h > 1) {
      overlaps.push({ a: describe(a), b: describe(b), area: Math.round(w * h) });
    }
  }
}

const outside = [];
for (const el of controls) {
  const r = el.getBoundingClientRect();
  if (r.left < -1 || r.right > root.clientWidth + 1) {
    outside.push(Object.assign(describe(el), { left: r.left, right: r.right }));
  }
}

const obscured = [];
for (const el of controls) {
  el.scrollIntoView({ block: 'center', inline: 'nearest' });
  const r = el.getBoundingClientRect();
  const x = Math.min(root.clientWidth - 1, Math.max(0, r.left + r.width / 2));
  const y = Math.min(root.clientHeight - 1, Math.max(0, r.top + r.height / 2));
  const hit = document.elementFromPoint(x, y);
  if (!hit || !(hit === el || el.contains(hit))) {
    obscured.push(Object.assign(describe(el), { hit: hit ? describe(hit).selector : null }));
  }
}
window.scrollTo(0, 0);

const before = window.scrollX;
window.scrollTo(root.scrollWidth + 4096, 0);
const afterRight = window.scrollX;
window.scrollTo(0, 0);

// Two separate facts about the shell, because the defect confused them. The
// compact layout engaging is read on the sidebar's separator, which the compact
// block moves from the inline edge to the block edge; whether the navigation
// wraps is read on the navigation itself. Before the fix the first was true at
// `640x560` and the second was false, and the second is what let the bar scroll.
const sidebar = document.querySelector('.yc-sidebar');
const nav = document.querySelector('.yc-sidebar__nav');
// The target is what a pointer can hit, not the painted glyph. A checkbox drawn
// at the icon size inside a label that is a full control tall is a full control
// tall to a finger, and the contract's minimum is about the target.
const heights = controls.map((el) => {
  const label = el.closest('label');
  const own = el.getBoundingClientRect().height;
  return label ? Math.max(own, label.getBoundingClientRect().height) : own;
});

return {
  heading: document.querySelector('h1') ? document.querySelector('h1').textContent : null,
  inner_width: window.innerWidth,
  inner_height: window.innerHeight,
  device_pixel_ratio: window.devicePixelRatio,
  root_font_size: getComputedStyle(root).fontSize,
  body_font_size: getComputedStyle(body).fontSize,
  client_width: root.clientWidth,
  client_height: root.clientHeight,
  root_scroll_width: root.scrollWidth,
  body_scroll_width: body.scrollWidth,
  document_scroll_height: root.scrollHeight,
  horizontal_overflow: root.scrollWidth > root.clientWidth + 1 || body.scrollWidth > root.clientWidth + 1,
  scroll_x_when_pushed_right: afterRight,
  scroll_x_at_rest: before,
  container_queries: CSS.supports('container-type', 'inline-size'),
  window_has_focus: document.hasFocus(),
  compact_layout: sidebar ? parseFloat(getComputedStyle(sidebar).borderInlineEndWidth || '0') === 0 : null,
  navigation_wraps: nav ? getComputedStyle(nav).flexWrap === 'wrap' : null,
  navigation_scrolls: nav ? nav.scrollWidth > nav.clientWidth + 1 : null,
  control_count: controls.length,
  controls_taller_than_window: controls.filter(
    (el) => el.getBoundingClientRect().height > root.clientHeight
  ).length,
  minimum_control_height: heights.length ? Math.min.apply(null, heights) : null,
  remote_resources: performance.getEntriesByType('resource')
    .map((entry) => entry.name)
    .filter((name) => /^https?:/u.test(name) && !name.startsWith(location.origin + '/')),
  clipping_boxes: clipping,
  clipped: clipped,
  overlaps: overlaps,
  outside_viewport: outside,
  obscured: obscured
};
"""

FOCUS_ORDER_SCRIPT = r"""
const CONTROL = arguments[0];
function laidOut(el) {
  const r = el.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) return false;
  const s = getComputedStyle(el);
  return s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0.01;
}
window.scrollTo(0, 0);
if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
window.__ycOrder = [...document.querySelectorAll(CONTROL)].filter(laidOut).filter((el) => !el.disabled);
return window.__ycOrder.length;
"""

FOCUS_STEP_SCRIPT = r"""
const el = document.activeElement;
const root = document.documentElement;
if (!el || el === document.body || el === root) return { end: true };
const order = window.__ycOrder || [];
const index = order.indexOf(el);
// WebKitGTK defers the scroll that follows a focus change, so the harness does
// it here, with the same `nearest` box the engine uses and honouring the
// `scroll-margin` the stylesheet sets. Measuring before that scroll would judge
// the ring of a control the user has not been shown yet.
el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
const r = el.getBoundingClientRect();
const s = getComputedStyle(el);
const width = parseFloat(s.outlineWidth || '0') || 0;
const offset = parseFloat(s.outlineOffset || '0') || 0;
const x = Math.min(root.clientWidth - 1, Math.max(0, r.left + r.width / 2));
const y = Math.min(root.clientHeight - 1, Math.max(0, r.top + r.height / 2));
const hit = document.elementFromPoint(x, y);
const raw = typeof el.className === 'string' ? el.className.trim() : '';
return {
  end: false,
  index: index,
  selector: el.tagName.toLowerCase() + (raw ? '.' + raw.split(/\s+/u).join('.') : ''),
  text: (el.textContent || '').replace(/\s+/gu, ' ').trim().slice(0, 48),
  focus_visible: el.matches(':focus-visible'),
  outline_style: s.outlineStyle,
  outline_width: width,
  outline_offset: offset,
  // A control whose ring is taller than the window cannot show all four of its
  // sides at once, and no layout can change that. What is required of it is that
  // the indicator be visible, which its two vertical sides are, across the whole
  // window. The inline axis is judged strictly: nothing excuses a ring cut by
  // the side of the window, because that is exactly the defect #56 records.
  ring_inside_viewport:
    r.left - offset - width >= -0.5 &&
    r.right + offset + width <= root.clientWidth + 0.5 &&
    ((r.top - offset - width >= -0.5 && r.bottom + offset + width <= root.clientHeight + 0.5) ||
      (r.bottom - r.top) + 2 * (offset + width) > root.clientHeight),
  ring_taller_than_window: (r.bottom - r.top) + 2 * (offset + width) > root.clientHeight,
  obscured: !(hit && (hit === el || el.contains(hit))),
  hit: hit ? hit.tagName.toLowerCase() + (typeof hit.className === 'string' && hit.className.trim()
    ? '.' + hit.className.trim().split(/\s+/u).join('.') : '') : null,
  rect: { left: r.left, top: r.top, right: r.right, bottom: r.bottom },
  viewport: { width: root.clientWidth, height: root.clientHeight },
  scroll_y: window.scrollY,
  scroll_x: window.scrollX
};
"""

CLICK_SCRIPT = r"""
const wanted = arguments[0];
const nodes = [...document.querySelectorAll('button')];
const hit = nodes.find((node) => (node.textContent || '').replace(/\s+/gu, ' ').trim() === wanted);
if (!hit) return false;
hit.click();
return true;
"""


# --------------------------------------------------------------------------
# The raster guard.


class RasterError(RuntimeError):
    pass


def paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    da, db, dc = abs(estimate - left), abs(estimate - above), abs(estimate - upper_left)
    if da <= db and da <= dc:
        return left
    if db <= dc:
        return above
    return upper_left


def decode_png(payload: bytes) -> tuple[int, int, list[bytearray], dict[str, object]]:
    """Decode an RGB8 or RGBA8 PNG and report the three sanity ratios."""
    if not payload.startswith(PNG_SIGNATURE):
        raise RasterError("capture is not a PNG")
    cursor = len(PNG_SIGNATURE)
    header = None
    compressed = bytearray()
    saw_data = False
    saw_end = False
    while cursor < len(payload):
        if len(payload) - cursor < 12:
            raise RasterError("capture PNG chunk is truncated")
        length = struct.unpack_from(">I", payload, cursor)[0]
        end = cursor + 12 + length
        if end > len(payload):
            raise RasterError("capture PNG chunk exceeds the payload")
        kind = payload[cursor + 4 : cursor + 8]
        chunk = payload[cursor + 8 : cursor + 8 + length]
        expected = struct.unpack_from(">I", payload, cursor + 8 + length)[0]
        actual = zlib.crc32(chunk, zlib.crc32(kind)) & 0xFFFFFFFF
        if actual != expected:
            raise RasterError("capture PNG chunk CRC is invalid")
        if header is None and kind != b"IHDR":
            raise RasterError("capture PNG does not start with IHDR")
        if kind == b"IHDR":
            if header is not None or length != 13:
                raise RasterError("capture PNG IHDR is duplicated or invalid")
            header = struct.unpack(">IIBBBBB", chunk)
        elif kind == b"IDAT":
            saw_data = True
            compressed.extend(chunk)
        elif kind == b"IEND":
            if length != 0 or not saw_data:
                raise RasterError("capture PNG IEND is invalid")
            saw_end = True
            cursor = end
            break
        elif kind[0] & 0x20 == 0:
            raise RasterError("capture PNG contains an unsupported critical chunk")
        cursor = end
    if header is None or not saw_end:
        raise RasterError("capture PNG is incomplete")
    width, height, depth, colour, compression, filtering, interlace = header
    if depth != 8 or colour not in {2, 6} or compression or filtering or interlace:
        raise RasterError("capture PNG encoding is outside the RGB8 contract")

    stride = 3 if colour == 2 else 4
    row_length = width * stride
    raw = zlib.decompress(bytes(compressed))
    if len(raw) != (row_length + 1) * height:
        raise RasterError("capture PNG decompressed length is invalid")

    rows: list[bytearray] = []
    previous = bytearray(row_length)
    colours: collections.Counter[tuple[int, int, int]] = collections.Counter()
    black = 0
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        line = bytearray(raw[cursor : cursor + row_length])
        cursor += row_length
        if filter_type == 1:
            for index in range(stride, row_length):
                line[index] = (line[index] + line[index - stride]) & 0xFF
        elif filter_type == 2:
            for index in range(row_length):
                line[index] = (line[index] + previous[index]) & 0xFF
        elif filter_type == 3:
            for index in range(row_length):
                left = line[index - stride] if index >= stride else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif filter_type == 4:
            for index in range(row_length):
                left = line[index - stride] if index >= stride else 0
                upper_left = previous[index - stride] if index >= stride else 0
                line[index] = (line[index] + paeth(left, previous[index], upper_left)) & 0xFF
        elif filter_type != 0:
            raise RasterError("capture PNG uses an unknown row filter")
        previous = line
        if stride == 4:
            packed = bytearray(width * 3)
            for pixel in range(width):
                if line[pixel * 4 + 3] != 255:
                    raise RasterError("capture PNG contains a transparent pixel")
                packed[pixel * 3 : pixel * 3 + 3] = line[pixel * 4 : pixel * 4 + 3]
            line = packed
        rows.append(line)
        for pixel in range(0, width * 3, 3):
            key = (line[pixel], line[pixel + 1], line[pixel + 2])
            colours[key] += 1
            if key == (0, 0, 0):
                black += 1

    total = width * height
    stats = {
        "width": width,
        "height": height,
        "distinct_rgb": len(colours),
        "dominant_rgb_ratio": max(colours.values()) / total,
        "exact_black_ratio": black / total,
    }
    return width, height, rows, stats


def column_ink(rows: list[bytearray], x: int, top: int, bottom: int) -> tuple[int, int]:
    """Count how many pixels of one column differ from that column's own base."""
    seen: collections.Counter[tuple[int, int, int]] = collections.Counter()
    sampled: list[tuple[int, int, int]] = []
    for y in range(max(0, top), min(len(rows), bottom)):
        row = rows[y]
        pixel = (row[x * 3], row[x * 3 + 1], row[x * 3 + 2])
        sampled.append(pixel)
        seen[pixel] += 1
    if not sampled:
        return 0, 0
    base = seen.most_common(1)[0][0]
    ink = sum(
        1
        for pixel in sampled
        if abs(pixel[0] - base[0]) + abs(pixel[1] - base[1]) + abs(pixel[2] - base[2]) > INK_DISTANCE
    )
    return ink, len(sampled)


def raster_findings(
    rows: list[bytearray],
    width: int,
    height: int,
    metrics: dict[str, object],
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    inner_width = float(metrics["inner_width"])
    inner_height = float(metrics["inner_height"])
    scale = width / inner_width
    # The capture is the viewport. A driver that returned window furniture would
    # shift every box, so the mapping is checked rather than assumed.
    if abs(height - inner_height * scale) > 2:
        findings.append(
            {
                "kind": "capture_is_not_the_viewport",
                "detail": f"{width}x{height} for a viewport of {inner_width}x{inner_height}",
            }
        )
        return findings

    for name, x in (("left", 0), ("right", width - 1)):
        ink, sampled = column_ink(rows, x, 0, height)
        if ink >= INK_RUN:
            findings.append(
                {
                    "kind": "ink_on_the_window_edge",
                    "edge": name,
                    "ink_pixels": ink,
                    "sampled": sampled,
                }
            )

    for box in metrics["clipping_boxes"]:
        left = int(round(float(box["left"]) * scale))
        top = int(round(float(box["top"]) * scale))
        client_width = int(round(float(box["client_width"]) * scale))
        client_height = int(round(float(box["client_height"]) * scale))
        if client_width < 4 or client_height < 4:
            continue
        right = min(width - 1, left + client_width - 1)
        left = max(0, left)
        if right <= left:
            continue
        for name, x in (("left", left), ("right", right)):
            ink, sampled = column_ink(rows, x, top, top + client_height)
            if ink >= INK_RUN:
                findings.append(
                    {
                        "kind": "ink_sliced_on_a_clipping_boundary",
                        "edge": name,
                        "element": box["selector"],
                        "text": box["text"],
                        "ink_pixels": ink,
                        "sampled": sampled,
                    }
                )
    return findings


# --------------------------------------------------------------------------


def drive(driver: Driver, app_url: str, view: dict[str, object], zoom: int) -> None:
    driver.go(f"{app_url}?state={view['state']}")
    for _ in range(120):
        heading = driver.execute("const h = document.querySelector('h1'); return h ? h.textContent : null;")
        if heading:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(f"{view['id']}: the fixture never rendered a heading")
    if zoom != 100:
        driver.execute(f"document.documentElement.style.fontSize = '{16 * zoom // 100}px'; return true;")
    for label in view["clicks"]:
        for _ in range(60):
            if driver.execute(CLICK_SCRIPT, label) is True:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"{view['id']}: no button reads « {label} »")
        time.sleep(0.15)
    for _ in range(120):
        heading = driver.execute("const h = document.querySelector('h1'); return h ? h.textContent : null;")
        if heading == view["heading"]:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(f"{view['id']}: the heading never became « {view['heading']} »")
    if view.get("requires"):
        found = driver.execute("return document.querySelector(arguments[0]) !== null;", view["requires"])
        if found is not True:
            raise RuntimeError(f"{view['id']}: {view['requires']} is absent")
    driver.wait_for_paint()


def walk_focus(driver: Driver) -> tuple[list[dict[str, object]], int]:
    driver.restore_keyboard_focus()
    expected = int(driver.execute(FOCUS_ORDER_SCRIPT, CONTROL_SELECTOR))
    steps: list[dict[str, object]] = []
    for _ in range(expected + 3):
        driver.press_tab()
        step = driver.execute(FOCUS_STEP_SCRIPT)
        if step.get("end"):
            break
        steps.append(step)
        if len(steps) >= expected:
            break
    return steps, expected


def judge(
    case: str,
    metrics: dict[str, object],
    focus: list[dict[str, object]],
    expected_focus: int,
    raster: list[dict[str, object]] | None,
    stats: dict[str, object] | None,
    compact_expected: bool,
) -> list[str]:
    failures: list[str] = []

    def red(claim: str) -> None:
        failures.append(f"{case}: {claim}")

    if metrics["horizontal_overflow"]:
        red(
            "the page forces a horizontal scroll "
            f"({metrics['root_scroll_width']} > {metrics['client_width']})"
        )
    if metrics["scroll_x_when_pushed_right"] not in (0, 0.0):
        red(f"the page really scrolls sideways to {metrics['scroll_x_when_pushed_right']}")
    for entry in metrics["clipped"]:
        red(
            f"« {entry['text']} » is cut on {entry['axis']} in {entry['selector']} "
            f"({entry['scroll']} inside {entry['client']})"
        )
    for entry in metrics["overlaps"]:
        red(f"{entry['a']['selector']} overlaps {entry['b']['selector']} over {entry['area']} px²")
    for entry in metrics["outside_viewport"]:
        red(f"{entry['selector']} « {entry['text']} » leaves the viewport horizontally")
    for entry in metrics["obscured"]:
        red(f"{entry['selector']} « {entry['text']} » is covered by {entry['hit']}")
    if metrics["remote_resources"]:
        red(f"the fixture loaded a remote resource: {metrics['remote_resources'][0]}")
    if metrics["navigation_scrolls"] is True:
        red("the compact navigation scrolls horizontally")
    if metrics["compact_layout"] is not None and metrics["compact_layout"] is not compact_expected:
        red(
            "the compact layout did not follow the text size "
            f"(compact={metrics['compact_layout']}, expected {compact_expected})"
        )
    if metrics["compact_layout"] is True and metrics["navigation_wraps"] is not True:
        red("the compact navigation does not wrap, so a row that overflows has nowhere to go")
    if metrics["container_queries"] is not True:
        red("the engine does not support container queries, so the compact threshold cannot follow the text")
    if metrics["minimum_control_height"] is not None and metrics["minimum_control_height"] < 44:
        red(f"a control is only {metrics['minimum_control_height']} px tall")

    if expected_focus == 0:
        red("no control is focusable")
    if len(focus) != expected_focus:
        red(f"the keyboard reached {len(focus)} controls of {expected_focus}")
    previous = -1
    for step in focus:
        if step["index"] < 0:
            red(f"the keyboard reached « {step['text']} », which is not a laid out control")
            continue
        if step["index"] <= previous:
            red(f"the keyboard order goes backwards at « {step['text']} »")
        previous = step["index"]
        if step["focus_visible"] is not True:
            red(f"« {step['text']} » takes focus without :focus-visible")
        if step["outline_style"] == "none" or step["outline_width"] <= 0:
            red(f"« {step['text']} » takes focus without a visible ring")
        if step["ring_inside_viewport"] is not True:
            red(f"the focus ring of « {step['text']} » is cut by the window")
        if step["obscured"] is True:
            red(f"« {step['text']} » is covered while focused")
        if step["scroll_x"] not in (0, 0.0):
            red(f"focusing « {step['text']} » scrolled the page sideways")

    if stats is None or raster is None:
        return failures
    if stats["distinct_rgb"] < MIN_DISTINCT_RGB:
        red(f"the capture holds only {stats['distinct_rgb']} distinct colours")
    if stats["dominant_rgb_ratio"] > MAX_DOMINANT_RGB_RATIO:
        red(f"one colour covers {stats['dominant_rgb_ratio']:.4f} of the capture")
    if stats["exact_black_ratio"] > MAX_EXACT_BLACK_RATIO:
        red(f"exact black covers {stats['exact_black_ratio']:.4f} of the capture")
    for finding in raster:
        if finding["kind"] == "ink_on_the_window_edge":
            red(f"painted ink touches the {finding['edge']} window edge on {finding['ink_pixels']} rows")
        elif finding["kind"] == "ink_sliced_on_a_clipping_boundary":
            red(
                f"painted ink is sliced on the {finding['edge']} boundary of "
                f"{finding['element']} « {finding['text'][:40]} » over {finding['ink_pixels']} rows"
            )
        else:
            red(f"{finding['kind']}: {finding.get('detail', '')}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4444")
    parser.add_argument("--app-url", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--capture-zoom", type=int, default=200)
    parser.add_argument("--only", default="", help="restrict the matrix to cases whose name contains this")
    arguments = parser.parse_args()

    arguments.output.mkdir(parents=True, exist_ok=True)
    driver = Driver(arguments.base_url)
    report: dict[str, object] = {
        "schema_version": 1,
        "proof": "console-reflow",
        "issue": "#56",
        "contract": "docs/objectifs/v1/CONTRAT-V0.0.3.md",
        "revision": arguments.revision,
        "run": arguments.run,
        "platform": "linux",
        "engine": driver.engine,
        "instrumentation": "WebKitWebDriver driving MiniBrowser on Xvfb",
        "under_test": "the shipped frontend bundle with the Tauri IPC bridge replaced",
        "cases": [],
    }
    failures: list[str] = []
    try:
        for width, height in SIZES:
            driver.go("about:blank")
            driver.viewport(width, height)
            for zoom in ZOOMS:
                for view in VIEWS:
                    case = f"{view['id']}-{width}x{height}-text-{zoom}"
                    if arguments.only and arguments.only not in case:
                        continue
                    drive(driver, arguments.app_url, view, zoom)
                    driver.viewport(width, height)
                    metrics = driver.execute(MEASURE_SCRIPT, CONTROL_SELECTOR)
                    focus, expected_focus = walk_focus(driver)
                    driver.execute(
                        "window.scrollTo(0, 0);"
                        "if (document.activeElement && document.activeElement.blur)"
                        " document.activeElement.blur();"
                        "return true;"
                    )
                    stats: dict[str, object] | None = None
                    raster: list[dict[str, object]] | None = None
                    captured = zoom == arguments.capture_zoom
                    if captured:
                        driver.wait_for_paint()
                        payload = driver.screenshot()
                        (arguments.output / f"linux-{case}.png").write_bytes(payload)
                        image_width, image_height, rows, stats = decode_png(payload)
                        raster = raster_findings(rows, image_width, image_height, metrics)
                    compact_expected = width <= 644 * zoom / 100
                    case_failures = judge(case, metrics, focus, expected_focus, raster, stats, compact_expected)
                    failures.extend(case_failures)
                    report["cases"].append(
                        {
                            "case": case,
                            "view": view["id"],
                            "contract_view": view["contract_view"],
                            "width": width,
                            "height": height,
                            "text_zoom": zoom,
                            "captured": captured,
                            "compact_expected": compact_expected,
                            "metrics": metrics,
                            "focus_steps": focus,
                            "focusable_controls": expected_focus,
                            "raster": stats,
                            "raster_findings": raster,
                            "failures": case_failures,
                        }
                    )
                    print(
                        f"{'PASS' if not case_failures else 'RED '} {case:<52} "
                        f"controls={metrics['control_count']:>3} "
                        f"compact={metrics['compact_layout']} "
                        f"scroll_w={metrics['root_scroll_width']}/{metrics['client_width']}",
                        flush=True,
                    )
                    for line in case_failures:
                        print(f"     FAILED: {line}", flush=True)
    finally:
        try:
            driver.close()
        except Exception:  # noqa: BLE001 — a lost session must not hide the verdict
            pass

    report["outcome"] = "pass" if not failures else "red"
    report["failures"] = failures
    (arguments.output / "reflow-result.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"reflow: cases={len(report['cases'])} captures="
        f"{sum(1 for case in report['cases'] if case['captured'])} outcome={report['outcome']}"
    )
    if failures:
        for line in failures:
            print(f"FAILED: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
