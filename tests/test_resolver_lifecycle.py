"""Lifecycle tests for DNSResolver: closing while queries are pending.

These tests replace the pycares channel with ``FakeChannel`` so that the
test decides exactly when each query finishes. No network is needed and
every run follows the same order of events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any
from unittest.mock import Mock

import pycares
import pytest

import aiodns
from aiodns.error import ARES_ECANCELLED, ARES_ENOTFOUND, DNSError

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


@pytest.mark.parametrize('count', [1, 3, 100])
async def test_lifecycle_close_cancels_all_pending_queries(
    resolver_and_fake: Resolver, count: int
) -> None:
    """Every pending query ends with ARES_ECANCELLED after close()."""
    resolver, fake = resolver_and_fake
    futures = [
        resolver.query_dns(f'host{i}.example', 'A') for i in range(count)
    ]
    assert len(fake.pending) == count
    assert not any(fut.done() for fut in futures)

    await resolver.close()
    await run_pending_callbacks()

    for fut in futures:
        assert fut.done()
        assert_cancelled_by_resolver(fut)
    assert fake.pending == {}
    # Pending queries are cancelled before the channel is destroyed.
    assert fake.calls == ['cancel', 'close']
    assert resolver._closed
    assert resolver._timer is None
    assert not resolver._read_fds
    assert not resolver._write_fds


async def test_lifecycle_close_without_pending_queries(
    resolver_and_fake: Resolver,
) -> None:
    """Boundary case: closing an idle resolver still releases it."""
    resolver, fake = resolver_and_fake

    await resolver.close()

    assert fake.calls == ['cancel', 'close']
    assert resolver._closed


async def test_lifecycle_close_with_mixed_query_states(
    resolver_and_fake: Resolver, loop_errors: list[dict[str, object]]
) -> None:
    """close() only touches queries that are still pending.

    a: finished with a result, b: finished with an error,
    c: cancelled by the caller, d: still pending.
    """
    resolver, fake = resolver_and_fake
    fut_a = resolver.query_dns('a.example', 'A')
    fut_b = resolver.query_dns('b.example', 'A')
    fut_c = resolver.query_dns('c.example', 'A')
    fut_d = resolver.query_dns('d.example', 'A')

    result_a = Mock(name='result_a')
    fake.complete('a.example', result_a)
    fake.fail('b.example', ARES_ENOTFOUND)
    await run_pending_callbacks()
    # c-ares does not know about this; c stays pending in the channel.
    fut_c.cancel()

    await resolver.close()
    await run_pending_callbacks()

    assert fut_a.result() is result_a
    exc_b = fut_b.exception()
    assert isinstance(exc_b, DNSError)
    assert exc_b.args[0] == ARES_ENOTFOUND
    assert fut_c.cancelled()
    assert_cancelled_by_resolver(fut_d)
    # Setting a result on the cancelled future would raise
    # InvalidStateError inside a loop callback.
    assert loop_errors == []


async def test_lifecycle_result_arrives_just_before_close(
    resolver_and_fake: Resolver, loop_errors: list[dict[str, object]]
) -> None:
    """A result already delivered by c-ares is kept, not replaced."""
    resolver, fake = resolver_and_fake
    fut_a = resolver.query_dns('a.example', 'A')
    fut_b = resolver.query_dns('b.example', 'A')

    result_a = Mock(name='result_a')
    # In event thread mode this only schedules the callback; close()
    # runs before the event loop gets to it.
    fake.complete('a.example', result_a)
    await resolver.close()
    await run_pending_callbacks()

    assert fut_a.result() is result_a
    assert_cancelled_by_resolver(fut_b)
    assert loop_errors == []


async def test_lifecycle_close_is_idempotent_with_pending_queries(
    resolver_and_fake: Resolver,
) -> None:
    """Repeated close() calls cancel and release resources only once."""
    resolver, fake = resolver_and_fake
    futures = [resolver.query_dns(f'host{i}.example', 'A') for i in range(3)]

    await resolver.close()
    await resolver.close()
    await resolver.close()
    await run_pending_callbacks()

    for fut in futures:
        assert_cancelled_by_resolver(fut)
    assert fake.calls == ['cancel', 'close']


async def test_lifecycle_context_manager_exit_on_error_cancels_queries(
    resolver_and_fake: Resolver,
) -> None:
    """Leaving ``async with`` because of an error closes the resolver."""
    resolver, fake = resolver_and_fake
    futures: list[asyncio.Future[Any]] = []

    with pytest.raises(ValueError, match='boom'):
        async with resolver:
            futures.append(resolver.query_dns('a.example', 'A'))
            futures.append(resolver.query_dns('b.example', 'A'))
            raise ValueError('boom')

    await run_pending_callbacks()

    for fut in futures:
        assert_cancelled_by_resolver(fut)
    assert fake.calls == ['cancel', 'close']
    assert resolver._closed