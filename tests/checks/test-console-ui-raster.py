#!/usr/bin/env python3
"""Hostile standard-library checks for the installed Console UI proof oracles."""

from __future__ import annotations

import base64
import http.client
import importlib.util
import pathlib
import struct
import tempfile
import zlib


PROOF_PATH = pathlib.Path(__file__).with_name("console-windows-ui-proof.py")
SPEC = importlib.util.spec_from_file_location("console_ui_proof", PROOF_PATH)
if SPEC is None or SPEC.loader is None:
    raise AssertionError("Console UI proof module could not be loaded")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type)
    checksum = zlib.crc32(payload, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)


def encode_png(
    width: int,
    height: int,
    pixel,
    *,
    rgba: bool = False,
    filter_type: int = 0,
    extra_chunk: tuple[bytes, bytes] | None = None,
) -> bytes:
    color_type = 6 if rgba else 2
    bytes_per_pixel = 4 if rgba else 3
    rows = bytearray()
    previous = bytes(width * bytes_per_pixel)
    for y in range(height):
        current = bytearray()
        for x in range(width):
            current.extend(pixel(x, y))
        rows.append(filter_type)
        for index, value in enumerate(current):
            left = current[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
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
                estimate = left + above - upper_left
                distances = (
                    abs(estimate - left),
                    abs(estimate - above),
                    abs(estimate - upper_left),
                )
                predictor = (left, above, upper_left)[distances.index(min(distances))]
            else:
                predictor = 0
            rows.append((value - predictor) & 0xFF)
        previous = bytes(current)
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    chunks = [png_chunk(b"IHDR", header)]
    if extra_chunk is not None:
        chunks.append(png_chunk(*extra_chunk))
    chunks.extend(
        (
            png_chunk(b"IDAT", zlib.compress(bytes(rows))),
            png_chunk(b"IEND", b""),
        )
    )
    return PROOF.PNG_SIGNATURE + b"".join(chunks)


def varied_rgb(x: int, y: int) -> tuple[int, int, int]:
    return (16 + x % 200, 16 + y % 200, 16 + (x * 17 + y * 29) % 200)


def expect_rejection(payload: bytes, width: int, height: int, fragment: str) -> None:
    try:
        PROOF.inspect_png_raster(payload, width, height)
    except PROOF.ScreenshotRasterError as error:
        if fragment not in str(error):
            raise AssertionError(f"unexpected raster rejection: {error}") from error
    else:
        raise AssertionError(f"hostile raster was accepted instead of: {fragment}")


def exercise_screenshot_retry(
    responses: list[object],
    valid_payload: bytes,
    *,
    expected_attempts: int,
    should_succeed: bool,
) -> None:
    driver = object.__new__(PROOF.Driver)
    driver.base_url = "http://127.0.0.1:4444"
    driver.session_id = "synthetic"
    paint_barriers = 0

    def paint() -> None:
        nonlocal paint_barriers
        paint_barriers += 1

    driver.wait_for_paint = paint
    pending = iter(responses)
    requests = 0

    def synthetic_request(base_url, method, path, payload=None, timeout_seconds=30):
        nonlocal requests
        if (
            base_url != driver.base_url
            or method != "GET"
            or path != "/session/synthetic/screenshot"
            or payload is not None
            or timeout_seconds != 30
        ):
            raise AssertionError("screenshot retry called an unexpected WebDriver endpoint")
        requests += 1
        return next(pending)

    original_request = PROOF.request
    original_delay = PROOF.SCREENSHOT_RETRY_DELAY_SECONDS
    PROOF.request = synthetic_request
    PROOF.SCREENSHOT_RETRY_DELAY_SECONDS = 0
    try:
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "capture.png"
            if should_succeed:
                facts = driver.screenshot(target, 320, 200)
                if facts["capture_attempts"] != expected_attempts:
                    raise AssertionError("screenshot retry count was not reported exactly")
                if target.read_bytes() != valid_payload:
                    raise AssertionError("an invalid screenshot was written before the valid raster")
            else:
                try:
                    driver.screenshot(target, 320, 200)
                except AssertionError as error:
                    if "remained invalid after 5 attempts" not in str(error):
                        raise
                else:
                    raise AssertionError("five invalid screenshots did not fail closed")
                if target.exists():
                    raise AssertionError("an exhausted screenshot retry wrote an invalid artifact")
    finally:
        PROOF.request = original_request
        PROOF.SCREENSHOT_RETRY_DELAY_SECONDS = original_delay
    if requests != expected_attempts or paint_barriers != expected_attempts:
        raise AssertionError("each screenshot retry must cross one paint barrier and issue one GET")


def exercise_async_retry_boundary() -> None:
    driver = object.__new__(PROOF.Driver)
    driver.base_url = "http://127.0.0.1:4444"
    driver.session_id = "synthetic"
    calls: list[tuple[str, str, object | None]] = []
    timeout_attempts = 0

    def timeout_disconnect_request(
        base_url,
        method,
        path,
        payload=None,
        timeout_seconds=30,
    ):
        nonlocal timeout_attempts
        if base_url != driver.base_url or method != "POST" or timeout_seconds != 30:
            raise AssertionError("async retry boundary called an unexpected WebDriver endpoint")
        calls.append((method, path, payload))
        if path == "/session/synthetic/timeouts":
            timeout_attempts += 1
            if timeout_attempts == 1:
                raise http.client.RemoteDisconnected("synthetic timeout disconnect")
            return None
        if path == "/session/synthetic/execute/async":
            return {"ok": True}
        raise AssertionError("async retry boundary called an unknown WebDriver path")

    original_request = PROOF.request
    PROOF.request = timeout_disconnect_request
    try:
        outcome = driver.execute_async("return arguments[0];", ["synthetic"], 45)
    finally:
        PROOF.request = original_request
    expected_timeout_payload = {"script": 45000}
    if outcome != {"ok": True} or calls != [
        ("POST", "/session/synthetic/timeouts", expected_timeout_payload),
        ("POST", "/session/synthetic/timeouts", expected_timeout_payload),
        (
            "POST",
            "/session/synthetic/execute/async",
            {"script": "return arguments[0];", "args": ["synthetic"]},
        ),
    ]:
        raise AssertionError("only the idempotent script timeout may be retried")

    calls = []

    def mutating_disconnect_request(
        base_url,
        method,
        path,
        payload=None,
        timeout_seconds=30,
    ):
        if base_url != driver.base_url or method != "POST" or timeout_seconds != 30:
            raise AssertionError("mutating retry boundary called an unexpected WebDriver endpoint")
        calls.append((method, path, payload))
        if path == "/session/synthetic/timeouts":
            return None
        if path == "/session/synthetic/execute/async":
            raise http.client.RemoteDisconnected("synthetic mutating disconnect")
        raise AssertionError("mutating retry boundary called an unknown WebDriver path")

    PROOF.request = mutating_disconnect_request
    try:
        try:
            driver.execute_async("return arguments[0];", ["synthetic"], 45)
        except http.client.RemoteDisconnected:
            pass
        else:
            raise AssertionError("a disconnected mutating async request was hidden or retried")
    finally:
        PROOF.request = original_request
    if calls != [
        ("POST", "/session/synthetic/timeouts", expected_timeout_payload),
        (
            "POST",
            "/session/synthetic/execute/async",
            {"script": "return arguments[0];", "args": ["synthetic"]},
        ),
    ]:
        raise AssertionError("a mutating async request was retried after disconnection")


def main() -> int:
    width = 320
    height = 200
    valid = encode_png(width, height, varied_rgb)
    facts = PROOF.inspect_png_raster(valid, width, height)
    if facts["distinct_rgb"] < PROOF.MIN_SCREENSHOT_DISTINCT_RGB:
        raise AssertionError("valid synthetic raster lost its distinct colors")
    for filter_type in range(1, 5):
        filtered = encode_png(width, height, varied_rgb, filter_type=filter_type)
        PROOF.inspect_png_raster(filtered, width, height)
    unknown_filter = encode_png(width, height, varied_rgb, filter_type=5)
    expect_rejection(unknown_filter, width, height, "unknown row filter")

    opaque_rgba = encode_png(
        width,
        height,
        lambda x, y: (*varied_rgb(x, y), 255),
        rgba=True,
    )
    PROOF.inspect_png_raster(opaque_rgba, width, height)

    uniform = encode_png(width, height, lambda _x, _y: (250, 250, 249))
    expect_rejection(uniform, width, height, "too few distinct RGB colors")

    black_damage = encode_png(
        width,
        height,
        lambda x, y: (0, 0, 0) if x < 86 else varied_rgb(x, y),
    )
    expect_rejection(black_damage, width, height, "too much exact black")

    def dominant_pixel(x: int, y: int) -> tuple[int, int, int]:
        index = y * width + x
        if index >= 300:
            return (250, 250, 249)
        return (16 + index % 200, 16 + index // 200, 16 + (index * 37) % 200)

    dominant = encode_png(width, height, dominant_pixel)
    expect_rejection(dominant, width, height, "dominated by one RGB color")

    transparent = encode_png(
        width,
        height,
        lambda x, y: (*varied_rgb(x, y), 0 if (x, y) == (0, 0) else 255),
        rgba=True,
    )
    expect_rejection(transparent, width, height, "transparent pixel")
    expect_rejection(valid, width + 1, height, "dimensions differ")

    corrupt_crc = bytearray(valid)
    corrupt_crc[-1] ^= 1
    expect_rejection(bytes(corrupt_crc), width, height, "CRC is invalid")
    expect_rejection(valid[:-1], width, height, "chunk is truncated")
    unknown_critical = encode_png(
        width,
        height,
        varied_rgb,
        extra_chunk=(b"ABCD", b"synthetic-critical-chunk"),
    )
    expect_rejection(unknown_critical, width, height, "unsupported critical chunk")

    valid_base64 = base64.b64encode(valid).decode("ascii")
    uniform_base64 = base64.b64encode(uniform).decode("ascii")
    exercise_screenshot_retry(
        [uniform_base64, valid_base64],
        valid,
        expected_attempts=2,
        should_succeed=True,
    )
    exercise_screenshot_retry(
        ["not-base64!", {"unexpected": True}, valid_base64],
        valid,
        expected_attempts=3,
        should_succeed=True,
    )
    exercise_screenshot_retry(
        [uniform_base64] * PROOF.MAX_SCREENSHOT_ATTEMPTS,
        valid,
        expected_attempts=PROOF.MAX_SCREENSHOT_ATTEMPTS,
        should_succeed=False,
    )
    exercise_async_retry_boundary()

    print(
        "PASS: damaged rasters fail closed, screenshots retry safely and async mutations do not"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
