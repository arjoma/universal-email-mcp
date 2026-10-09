"""Blocking mail I/O off the event loop - never on asyncio's default executor.

``asyncio.to_thread`` runs on one small shared pool (a few threads on a small
instance). A mail server that trickles bytes keeps a worker for as long as it likes
(a per-read socket timeout never fires while single bytes keep arriving), so a handful
of tarpitting hosts used to stall everything else that uses the pool: sign-in, the
client-metadata fetch, SMTP submission, the viewer. Mail I/O therefore runs on a
daemon thread of its own (:func:`run_daemon`) under an absolute
:class:`~universal_email_mcp.mail.net.Deadline` (:func:`run_deadline`) that shuts the
sockets down when the time is up, so the thread is freed too.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

from universal_email_mcp.mail.net import Deadline

GRACE = 5.0
"""Seconds past the deadline the caller still waits for the thread (the watchdog has
shut the sockets by then, so it normally returns at once)."""


def run_daemon[**P, T](
    loop: asyncio.AbstractEventLoop, fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs
) -> asyncio.Future[T]:
    """Like ``loop.run_in_executor`` but on a daemon thread of its own: a mail server
    that hangs (TLS handshake, dead connection) keeps its worker only until the
    socket times out, and neither ``asyncio.run`` nor the interpreter waits for it
    at exit. Callers bound the number of concurrent calls (a per-account lock, a
    semaphore), so threads stay few."""
    fut: asyncio.Future[T] = loop.create_future()

    def deliver(result: T | None, error: BaseException | None) -> None:
        if fut.cancelled():
            return
        if error is not None:
            if isinstance(error, StopIteration):  # not allowed in a future
                error = RuntimeError("worker raised StopIteration")
            fut.set_exception(error)
        else:
            fut.set_result(result)  # pyright: ignore[reportArgumentType]

    def run() -> None:
        try:
            result = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - handed to the awaiting task
            error, result = e, None
        else:
            error = None
        try:
            loop.call_soon_threadsafe(deliver, result, error)
        except RuntimeError:  # the loop is closed: nobody is waiting any more
            pass

    threading.Thread(target=run, name="uem-worker", daemon=True).start()
    return fut


async def run_deadline[T](
    fn: Callable[[], T], *, seconds: float, expired_as_timeout: bool = False
) -> T:
    """Run ``fn()`` on its own daemon thread inside ``with Deadline(seconds)``.

    Every socket ``fn`` opens through :func:`~universal_email_mcp.mail.net.open_connection`
    is shut down when the deadline passes, so a blocked call fails and the thread ends.
    ``expired_as_timeout=True`` reports such a failure as :class:`TimeoutError` (whatever
    error the cut connection produced); otherwise the error is passed on as it is.
    Raises :class:`TimeoutError` if the thread has not returned ``GRACE`` seconds after
    the deadline (a blocked name lookup); the thread is then abandoned.
    """

    def job() -> T:
        with Deadline(seconds) as deadline:
            try:
                return fn()
            except Exception:
                if expired_as_timeout and deadline.expired:
                    raise TimeoutError("deadline exceeded") from None
                raise

    fut = run_daemon(asyncio.get_running_loop(), job)
    # On timeout wait_for cancels the future: a late result or error is dropped quietly.
    return await asyncio.wait_for(fut, seconds + GRACE)
