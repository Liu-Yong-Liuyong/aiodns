"""Lifecycle tests for DNSResolver: closing while queries are pending.

These tests replace the pycares channel with ``FakeChannel`` so that the
test decides exactly when each query finishes. No network is needed and
every run follows the same order of events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any

import pycares
import pytest

import aiodns
from aiodns.error import ARES_ECANCELLED, DNSError

Resolver = tuple[aiodns.DNSResolver, 'FakeChannel']


class FakeChannel:
    """Stand-in for ``pycares.Channel`` that the test drives by hand.

    ``cancel()`` behaves like c-ares: every query that is still running
    gets its callback called once with ``ARES_ECANCELLED``.
    """

    def __init__(self) -> None:
        self.pending: dict[str, Callable[..., None]] = {}
        self.calls: list[str] = []

    def query(
        self,
        host: str,
        qtype: int,
        *,
        callback: Callable[..., None],
        **kwargs: Any,
    ) -> None:
        self.pending[host] = callback

    def complete(self, host: str, result: object) -> None:
        self.pending.pop(host)(result, None)

    def fail(self, host: str, errno: int) -> None:
        self.pending.pop(host)(None, errno)

    def cancel(self) -> None:
        self.calls.append('cancel')
        pending, self.pending = self.pending, {}
        for callback in pending.values():
            callback(None, ARES_ECANCELLED)

    def close(self) -> None:
        self.calls.append('close')


@pytest.fixture(params=[True, False], ids=['event_thread', 'sock_state_cb'])
async def resolver_and_fake(
    request: pytest.FixtureRequest,
) -> AsyncIterator[Resolver]:
    """A resolver whose channel is a FakeChannel.

    Every test runs twice: once with callbacks scheduled through
    ``loop.call_soon_threadsafe`` (event thread mode, the default) and
    once with callbacks called directly (sock_state_cb fallback mode).
    """
    resolver = aiodns.DNSResolver(loop=asyncio.get_running_loop())
    real_channel = resolver._channel
    fake = FakeChannel()
    resolver._channel = fake  # type: ignore[assignment]
    resolver._event_thread = request.param
    yield resolver, fake
    await resolver.close()  # does nothing if the test already closed it
    real_channel.close()


@pytest.fixture
async def loop_errors() -> AsyncIterator[list[dict[str, object]]]:
    """Collect exceptions raised inside event loop callbacks.

    An exception inside a scheduled callback (for example
    ``InvalidStateError``) is only logged by asyncio and does not fail
    the test, so the test has to collect it and check the list.
    """
    loop = asyncio.get_running_loop()
    errors: list[dict[str, object]] = []
    loop.set_exception_handler(lambda _loop, ctx: errors.append(ctx))
    yield errors
    loop.set_exception_handler(None)


async def run_pending_callbacks() -> None:
    """Let the event loop run callbacks scheduled by the resolver."""
    await asyncio.sleep(0)


def assert_cancelled_by_resolver(fut: asyncio.Future[Any]) -> None:
    exc = fut.exception()
    assert isinstance(exc, DNSError)
    assert exc.args == (
        ARES_ECANCELLED,
        pycares.errno.strerror(ARES_ECANCELLED),
    )
