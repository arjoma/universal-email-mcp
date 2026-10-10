"""The HTML view is built on a bounded worker of its own, with a time limit."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from typing import Any, cast

import pytest

import universal_email_mcp.service.viewer as viewer_mod
from universal_email_mcp.errors import Busy
from universal_email_mcp.mail.htmlview import TooComplex
from universal_email_mcp.service.viewer import Viewer

RAW = b"Content-Type: text/html\r\n\r\n<p>hi</p>"


def make_viewer() -> Viewer:
    async def run_one(account: object, fn: Any) -> bytes:
        return await fn(account)

    async def call(_account: object, _fn: Any) -> bytes:
        return RAW

    router = SimpleNamespace(run_one=run_one, call=call)
    service = SimpleNamespace(
        router=router,
        resolve=lambda _id: ("ref", "account"),
        limits=SimpleNamespace(max_message_bytes=1024),
    )
    return Viewer(cast(Any, service), max_download_bytes=1)


async def test_html_view_runs_off_the_default_executor(monkeypatch: pytest.MonkeyPatch):
    names: list[str] = []

    def fake(raw: bytes, *, remote_images: bool = False) -> str:
        names.append(threading.current_thread().name)
        return "view"

    monkeypatch.setattr(viewer_mod, "build_html_view", fake)
    assert await make_viewer().html("m", remote_images=False) == "view"  # pyright: ignore[reportUnnecessaryComparison]
    assert names == ["uem-worker"]


async def test_a_slow_sanitiser_ends_as_too_complex_and_does_not_block_the_loop(
    monkeypatch: pytest.MonkeyPatch,
):
    release = threading.Event()
    monkeypatch.setattr(viewer_mod, "HTML_VIEW_SECONDS", 0.3)
    monkeypatch.setattr("universal_email_mcp.bounded.GRACE", 0.1)
    monkeypatch.setattr(viewer_mod, "GRACE", 0.1)
    monkeypatch.setattr(
        viewer_mod, "build_html_view", lambda raw, *, remote_images=False: release.wait(10)
    )
    t0 = time.monotonic()
    with pytest.raises(TooComplex):
        await make_viewer().html("m", remote_images=False)
    assert time.monotonic() - t0 < 2
    release.set()


async def test_too_many_sanitisations_at_once_answer_busy(monkeypatch: pytest.MonkeyPatch):
    release = threading.Event()
    monkeypatch.setattr(viewer_mod, "_html_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(viewer_mod, "HTML_VIEW_QUEUE_SECONDS", 0.1)
    monkeypatch.setattr(
        viewer_mod, "build_html_view", lambda raw, *, remote_images=False: release.wait(5)
    )
    first = asyncio.create_task(make_viewer().html("m", remote_images=False))
    await asyncio.sleep(0.1)
    with pytest.raises(Busy):
        await make_viewer().html("m", remote_images=False)
    release.set()
    await first


async def test_a_stuck_sanitiser_keeps_its_slot_until_it_ends(monkeypatch: pytest.MonkeyPatch):
    release = threading.Event()
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(viewer_mod, "_html_slots", slots)
    monkeypatch.setattr(viewer_mod, "HTML_VIEW_SECONDS", 0.3)
    monkeypatch.setattr(viewer_mod, "HTML_VIEW_QUEUE_SECONDS", 0.1)
    monkeypatch.setattr("universal_email_mcp.bounded.GRACE", 0.1)
    monkeypatch.setattr(viewer_mod, "GRACE", 0.1)
    monkeypatch.setattr(
        viewer_mod, "build_html_view", lambda raw, *, remote_images=False: release.wait(10)
    )
    with pytest.raises(TooComplex):
        await make_viewer().html("m", remote_images=False)
    with pytest.raises(Busy):  # the abandoned thread still holds the only slot
        await make_viewer().html("m", remote_images=False)
    release.set()
    await asyncio.sleep(0.2)
    assert slots.acquire(blocking=False)
