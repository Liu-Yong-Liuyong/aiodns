#!/usr/bin/env python

import asyncio
import gc
import ipaddress
import logging
import socket
import sys
import time
import unittest
import unittest.mock
import warnings
from typing import Any, cast

import pycares
import pytest

import aiodns
from aiodns.compat import (
    AresHostResult,
    AresQueryAAAAResult,
    AresQueryAResult,
    AresQueryCNAMEResult,
    AresQueryMXResult,
    AresQueryNAPTRResult,
    AresQueryNSResult,
    AresQueryPTRResult,
    AresQuerySOAResult,
    AresQuerySRVResult,
    AresQueryTXTResult,
)

try:
    if sys.platform == 'win32':
        import winloop as uvloop

        skip_uvloop = False
    else:
        import uvloop

        skip_uvloop = False
except ModuleNotFoundError:
    skip_uvloop = True

# Skip uvloop tests on Python 3.14+ due to EventLoopPolicy deprecation
if sys.version_info >= (3, 14):
    skip_uvloop = True


class DNSTest(unittest.TestCase):
    #setUp() 會由測試框架 unittest 自動呼叫
    #setUp() 不是整個 Test Suite 只執行一次，而是每個 Test Case 都會執行一次。
    '''
    ex:
        pytest 找到 test_query_a()
        unittest 執行 setUp()
        建立 Event Loop、DNSResolver
        執行 test_query_a()
        發出 DNS 查詢並驗證結果
        unittest 執行 tearDown()
        關閉 DNSResolver
        執行 Cleanup
        關閉 Event Loop
    '''
    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                # Policy deprecated in 3.14, create SelectorEventLoop directly
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close) #當這個 Test Case 結束時，記得呼叫 self.loop.close()。
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

    def tearDown(self) -> None:
        # 測試結束後先關閉 Resolver，再由 Cleanup 關閉 Event Loop
        self.loop.run_until_complete(self.resolver.close())#讓 Event Loop 執行並等待 Resolver 的關閉作業完成。
        self.resolver = None  # type: ignore[assignment]
    '''
    發起查詢時：建立 Future、Callback，並交給 pycares。
    DNS 查詢完成時：pycares 呼叫 cb()，透過 call_soon_threadsafe() 排程 _callback()。
    Event Loop 執行排程工作時：真正執行 _callback()，完成 Future。
    Future 完成後：等待它的 Coroutine 會被排程恢復執行。
    '''
    def test_query_a(self) -> None:
        f = self.resolver.query('google.com', 'A') #query() 是 aiodns 保留的相容性 API，會將 DNS 查詢結果轉換成舊版資料格式。
        result = self.loop.run_until_complete(f) #啟動event loop，等待 Future 完成
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryAResult) #確認 List 裡的第一個元素是 AresQueryAResult 物件。

    def test_query_async_await(self) -> None:
        async def f() -> list[AresQueryAResult]: #它會建立一個 Coroutine Object，但不會立即執行函式裡面的 DNS 查詢。
            return await self.resolver.query('google.com', 'A')
        #Event Loop 執行 f() 的內容：呼叫 resolver.query()，發起 DNS 查詢並取得 Future。
        #遇到 await future：如果 Future 尚未完成，Coroutine 暫停，Event Loop 可以處理其他工作。
        #Future 完成：Event Loop 排程恢復這個 Task，讓 f() 回傳結果。
        result = self.loop.run_until_complete(f()) 
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryAResult)

    #這個測試實際上只驗證：如果拋出了 DNSError，那麼它的錯誤碼必須是 ARES_ENOTFOUND。
    def test_query_a_bad(self) -> None:
        f = self.resolver.query('hgf8g2od29hdohid.com', 'A')
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            #ARES_ENOTFOUND 表示 DNS 查詢沒有找到指定的名稱或紀錄。如果錯誤碼相符，Assertion 就會通過。
            self.assertEqual(e.args[0], aiodns.error.ARES_ENOTFOUND)
        # 注意：若查詢意外成功，此測試不會失敗
        # 因為沒有明確驗證 DNSError 必須被拋出
    '''
    #確保：DNS 查詢一定要拋出 DNSError。
    def test_query_a_bad(self) -> None:
        f = self.resolver.query('hgf8g2od29hdohid.com', 'A')

        with self.assertRaises(aiodns.error.DNSError) as cm:
            self.loop.run_until_complete(f)

        self.assertEqual(
            cm.exception.args[0],
            aiodns.error.ARES_ENOTFOUND
        )
    '''
    def test_query_aaaa(self) -> None:
        f = self.resolver.query('ipv6.google.com', 'AAAA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryAAAAResult)

    def test_query_cname(self) -> None:
        f = self.resolver.query('www.amazon.com', 'CNAME')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, AresQueryCNAMEResult)

    def test_query_mx(self) -> None:
        f = self.resolver.query('google.com', 'MX')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryMXResult)

    def test_query_ns(self) -> None:
        f = self.resolver.query('google.com', 'NS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryNSResult)

    @unittest.skipIf(
        sys.platform == 'darwin', 'skipped on Darwin as it is flakey on CI'
    )
    def test_query_txt(self) -> None:
        f = self.resolver.query('google.com', 'TXT')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryTXTResult)

    def test_query_soa(self) -> None:
        f = self.resolver.query('google.com', 'SOA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, AresQuerySOAResult)

    def test_query_srv(self) -> None:
        f = self.resolver.query('_xmpp-server._tcp.jabber.org', 'SRV')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQuerySRVResult)

    def test_query_naptr(self) -> None:
        f = self.resolver.query('sip2sip.info', 'NAPTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], AresQueryNAPTRResult)

    def test_query_ptr(self) -> None:
        ip = '172.253.122.26'
        f = self.resolver.query(
            ipaddress.ip_address(ip).reverse_pointer, 'PTR'
        )
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, AresQueryPTRResult)

    def test_query_bad_type(self) -> None:
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'XXX')

    def test_query_bad_class(self) -> None:
        self.assertRaises(
            ValueError, self.resolver.query, 'google.com', 'A', 'INVALIDCLASS'
        )

    def test_query_cancel(self) -> None:
        '''
        resolver.query() 發起 DNS 查詢，回傳 Future f。
        resolver.cancel() 要求底層 Resolver 取消尚未完成的 DNS 查詢。
        run_until_complete(f) 啟動 Event Loop，等待 Future 完成。
        預期 pycares 透過 Callback 回報 ARES_ECANCELLED。
        aiodns 將錯誤轉換成 DNSError，並設定到 Future。
        測試捕捉 DNSError，確認錯誤碼為 ARES_ECANCELLED。
        '''
        f = self.resolver.query('google.com', 'A')
        self.resolver.cancel() #要求底層 Channel 取消其未完成的查詢
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e: #預期的error是DNS error
            self.assertEqual(e.args[0], aiodns.error.ARES_ECANCELLED)
    '''
    #避免如果 Future 意外成功完成，就不會進入 except的情形
    def test_query_cancel(self) -> None:
        f = self.resolver.query('google.com', 'A')
        self.resolver.cancel()

        with self.assertRaises(aiodns.error.DNSError) as cm:
            self.loop.run_until_complete(f)

        self.assertEqual(
            cm.exception.args[0],
            aiodns.error.ARES_ECANCELLED
        )
    '''
    #取消單一future
    def test_future_cancel(self) -> None:
        f = self.resolver.query('google.com', 'A')
        f.cancel() #直接把這個 Future 設為 Cancelled。不等於取消底層 DNS 查詢。

        async def coro() -> None:
            await asyncio.sleep(0.1) #讓 Event Loop 運作一段時間。
            await f #因為 Future 已取消，會拋出 asyncio.CancelledError。

        try:
            self.loop.run_until_complete(coro())
        except asyncio.CancelledError as e:
            self.assertTrue(e)
    '''
    #避免如果 Future 意外成功完成，就不會進入 except的情形
    def test_future_cancel(self) -> None:
        f = self.resolver.query('google.com', 'A')
        f.cancel()

        async def coro() -> None:
            await asyncio.sleep(0.1)
            await f

        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(coro())

        self.assertTrue(f.cancelled())
    '''
    #同一個 DNSResolver 能否依序執行兩次 DNS 查詢，並且兩次都成功取得結果。not concurrent
    def test_query_twice(self) -> None:
        async def coro(self: DNSTest) -> None:
            for _ in range(2):
                result = await self.resolver.query('gmail.com', 'MX')
                self.assertTrue(result)

        self.loop.run_until_complete(coro(self))
    '''
    def test_query_concurrent(self) -> None:
        async def coro() -> None:
            # 先發起兩筆查詢，不立即等待
            future_a = self.resolver.query_dns('google.com', 'A')
            future_b = self.resolver.query_dns('example.com', 'A')

            # 等待兩筆查詢都完成
            result_a, result_b = await asyncio.gather(
                future_a,
                future_b,
            )

            self.assertIsNotNone(result_a)
            self.assertIsNotNone(result_b)

        self.loop.run_until_complete(coro())
    The existing test_query_twice test executes two DNS queries sequentially, as each query is awaited before the next one starts. Additional tests could verify multiple pending queries and out-of-order callback completion.
    '''

    def test_gethostbyname(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            f = self.resolver.gethostbyname('google.com', socket.AF_INET)
            result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, AresHostResult)
        self.assertGreater(len(result.addresses), 0)

    def test_getaddrinfo_address_family_0(self) -> None:
        f = self.resolver.getaddrinfo('google.com')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(len(result.nodes) > 1)

    def test_getaddrinfo_address_family_af_inet(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(
            all(node.family == socket.AF_INET for node in result.nodes)
        )

    def test_getaddrinfo_address_family_af_inet6(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(
            all(node.family == socket.AF_INET6 for node in result.nodes)
        )

    def test_getnameinfo_ipv4(self) -> None:
        f = self.resolver.getnameinfo(('127.0.0.1', 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    def test_getnameinfo_ipv6(self) -> None:
        f = self.resolver.getnameinfo(('::1', 0, 0, 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    @unittest.skipIf(sys.platform == 'win32', 'skipped on Windows')
    def test_gethostbyaddr(self) -> None:
        f = self.resolver.gethostbyaddr('127.0.0.1')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_gethostbyname_ipv6(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            f = self.resolver.gethostbyname('ipv6.google.com', socket.AF_INET6)
            result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertGreater(len(result.addresses), 0)

    def test_gethostbyname_bad_family(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            f = self.resolver.gethostbyname('ipv6.google.com', -1)  # type: ignore[arg-type]
            with self.assertRaises(aiodns.error.DNSError):
                self.loop.run_until_complete(f)


#    def test_query_bad_chars(self) -> None:
#        f = self.resolver.query('xn--cardeosapeluqueros-r0b.com', 'MX')
#        result = self.loop.run_until_complete(f)
#        self.assertTrue(result)


class TestQueryTxtChaos(DNSTest):
    """Test DNS queries with CHAOS class."""

    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']

    def test_query_txt_chaos(self) -> None:
        f = self.resolver.query('id.server', 'TXT', 'CHAOS')
        # CHAOS queries may be refused by some servers
        try:
            result = self.loop.run_until_complete(f)
            self.assertTrue(result)
        except aiodns.error.DNSError:
            # CHAOS queries are often refused, that's ok
            pass


class TestQueryTimeout(unittest.TestCase):
    """Test DNS queries with timeout configuration."""

    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(
            timeout=0.1, tries=1, loop=self.loop
        )
        self.resolver.nameservers = ['1.2.3.4']

    def tearDown(self) -> None:
        self.loop.run_until_complete(self.resolver.close())
        self.resolver = None  # type: ignore[assignment]

    def test_query_timeout(self) -> None:
        f = self.resolver.query('google.com', 'A')
        started = time.monotonic()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ETIMEOUT)
        # Ensure timeout really cuts time deadline.
        # Limit duration to one second
        self.assertLess(time.monotonic() - started, 1)


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_DNS(DNSTest):
    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_QueryTxtChaos(TestQueryTxtChaos):
    """Test DNS queries with CHAOS class using uvloop."""

    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_QueryTimeout(TestQueryTimeout):
    """Test DNS queries with timeout configuration using uvloop."""

    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(
            timeout=0.1, tries=1, loop=self.loop
        )
        self.resolver.nameservers = ['1.2.3.4']


@unittest.skipIf(sys.platform != 'win32', 'Only run on Windows')
def test_win32_inapproperate_event_loop() -> None:
    """Test DNSResolver with Windows with inapproperate eventloop.

    With pycares 5, event_thread is used by default. The SelectorEventLoop
    check only triggers when event_thread creation fails and we fall back
    to sock_state_cb mode.
    """
    # Create a ProactorEventLoop to trigger the error
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)
    mock_loop.__class__ = asyncio.ProactorEventLoop  # type: ignore[attr-defined]

    # Mock channel creation to fail on first call (event_thread),
    # triggering the fallback path where SelectorEventLoop is required
    mock_channel = unittest.mock.MagicMock()

    with (
        pytest.raises(
            RuntimeError,
            match=r'ProactorEventLoop will not work with aiodns on Windows'
            r' without event threads.',
        ),
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch(
            'aiodns.pycares.Channel',
            side_effect=[
                pycares.AresError(1, 'mock error'),  # First call fails
                mock_channel,  # Second call would succeed
            ],
        ),
    ):
        aiodns.DNSResolver(loop=mock_loop, timeout=5.0)


@pytest.mark.parametrize(
    ('platform', 'expected_msg_parts', 'unexpected_msg_parts'),
    [
        (
            'linux',
            [
                'automatic monitoring of',
                'resolver configuration changes',
                'system ran out of inotify watches',
                'Falling back to socket state callback',
                'Consider increasing the system inotify watch limit',
            ],
            [],
        ),
        (
            'darwin',
            [
                'automatic monitoring',
                'resolver configuration changes',
                'Falling back to socket state callback',
            ],
            [
                'system ran out of inotify watches',
                'Consider increasing the system inotify watch limit',
            ],
        ),
        (
            'win32',
            [
                'automatic monitoring',
                'resolver configuration changes',
                'Falling back to socket state callback',
            ],
            [
                'system ran out of inotify watches',
                'Consider increasing the system inotify watch limit',
            ],
        ),
    ],
)
async def test_make_channel_ares_error(
    platform: str,
    expected_msg_parts: list[str],
    unexpected_msg_parts: list[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test exception handling in _make_channel on different platforms."""
    # Set log level to capture warnings
    caplog.set_level(logging.WARNING)

    # Create a mock loop that is a SelectorEventLoop to
    # avoid Windows-specific errors
    mock_loop = unittest.mock.MagicMock(spec=asyncio.SelectorEventLoop)
    mock_channel = unittest.mock.MagicMock()

    with (
        unittest.mock.patch('sys.platform', platform),
        # Configure first Channel call to raise AresError,
        # second call to return our mock
        unittest.mock.patch(
            'aiodns.pycares.Channel',
            side_effect=[
                pycares.AresError('Mock error'),
                mock_channel,
            ],
        ),
        # Also patch asyncio.get_event_loop to return our mock loop
        unittest.mock.patch('asyncio.get_event_loop', return_value=mock_loop),
    ):
        # Create resolver which will call _make_channel
        resolver = aiodns.DNSResolver(loop=mock_loop)

        # Check that event_thread is False due to fallback
        assert resolver._event_thread is False

        # Check expected message parts in the captured log
        for part in expected_msg_parts:
            assert part in caplog.text

        # Check unexpected message parts aren't in the captured log
        for part in unexpected_msg_parts:
            assert part not in caplog.text

        # Manually set _closed to True to prevent cleanup logic from
        # running during the test.
        resolver._closed = True


@pytest.mark.asyncio
async def test_close_resolver() -> None:
    """Test that DNSResolver.close() properly shuts down the resolver."""
    # Use a non-routable IP to ensure the query doesn't complete before close
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['192.0.2.1']  # TEST-NET-1, non-routable

    # Create a query to ensure resolver is active
    query_future = resolver.query('google.com', 'A')

    # Close the resolver
    await resolver.close()

    # Verify resolver is marked as closed
    assert resolver._closed

    # Verify timers are cancelled
    assert resolver._timer is None

    # Verify file descriptors are cleared
    assert len(resolver._read_fds) == 0
    assert len(resolver._write_fds) == 0

    #驗證 Pending Query 收到取消錯誤
    # The query should fail with cancellation
    with pytest.raises(aiodns.error.DNSError) as exc_info:
        await query_future
    assert exc_info.value.args[0] == aiodns.error.ARES_ECANCELLED


@pytest.mark.asyncio
async def test_close_resolver_multiple_times() -> None:
    """Test that close() is idempotent and safe to call multiple times."""
    resolver = aiodns.DNSResolver()

    # Close multiple times
    await resolver.close()
    await resolver.close() #應安全返回
    await resolver.close() #應安全返回

    # All closes should succeed without error
    assert resolver._closed

#接下來這三個測試都沒有呼叫 resolver.close()，而是在驗證 Destructor 的自動 Cleanup；真正的差別是 Resolver 被銷毀時 Event Loop 的狀態。
def test_del_with_no_running_loop() -> None:
    """Test __del__ when there's no running event loop."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)

    # Track if cleanup was called via channel.close
    cleanup_called = False
    original_close = resolver._channel.close

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    #Resolver 的清理流程呼叫 channel.close() 時，測試就能偵測到。
    resolver._channel.close = mock_close  # type: ignore[method-assign]
    loop.close() #它刻意讓 Event Loop 處於 Closed 狀態，模擬 Resolver 被刪除時，已經無法依靠正常運作的 Event Loop 執行非同步清理的情境。

    # Delete the resolver without closing it
    del resolver
    gc.collect() #主動要求 Python 執行 Garbage Collection。

    # Should have called cleanup
    assert cleanup_called #如果resolver的destructor有呼叫self._channel.close()，就會觸發前面替換的mock_close()，進而驗證 Cleanup 有執行

#可能可以重寫涵蓋stop的情形
def test_del_with_stopped_event_loop() -> None:
    """Test __del__ when event loop is not running."""
    # Create a new event loop
    loop = asyncio.new_event_loop()

    # Create resolver with this loop
    resolver = aiodns.DNSResolver(loop=loop)

    # Track if cleanup was called via channel.close
    cleanup_called = False
    original_close = resolver._channel.close

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    resolver._channel.close = mock_close  # type: ignore[method-assign]

    # Close the loop so it's not running
    loop.close()

    # Delete resolver when its loop is not running
    del resolver
    gc.collect()

    # Should have called cleanup
    assert cleanup_called

#與之前兩個 Destructor Tests 不同，這個測試在執行時有一個正在運作的 Event Loop。
@pytest.mark.asyncio
async def test_del_with_running_event_loop() -> None:
    """Test __del__ when event loop is running performs cleanup."""
    resolver = aiodns.DNSResolver()#使用目前的 Event Loop。

    # Mark that cleanup was called by checking if channel.close was called
    original_close = resolver._channel.close
    cleanup_called = False

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    resolver._channel.close = mock_close  # type: ignore[method-assign]

    # Delete resolver while loop is running
    del resolver
    gc.collect()

    # Verify cleanup was called
    assert cleanup_called


@pytest.mark.asyncio
async def test_cleanup_method() -> None:
    """Test that _cleanup() properly cleans up resources."""
    resolver = aiodns.DNSResolver()
    #直接在 Resolver 的集合裡放入測試用 FD 編號。
    # Mock file descriptors and timer
    resolver._read_fds.add(1)
    resolver._read_fds.add(2)
    resolver._write_fds.add(3)
    resolver._write_fds.add(4)

    #用 MagicMock 模擬 Timer。當_cleanup()執行self._timer.cancel()時，mock會記錄cancel()被呼叫
    # Mock timer
    mock_timer = unittest.mock.MagicMock()
    resolver._timer = mock_timer

    #沒有替換整個 Event Loop，只是把其中兩個方法替換成 MagicMock()，避免真的操作 Event Loop 的 Socket 監聽，同時記錄 _cleanup() 是否呼叫正確的方法。
    # Mock loop methods
    resolver.loop.remove_reader = unittest.mock.MagicMock()  # type: ignore[method-assign]
    resolver.loop.remove_writer = unittest.mock.MagicMock()  # type: ignore[method-assign]

    # Call cleanup
    resolver._cleanup()

    # Verify timer was cancelled
    mock_timer.cancel.assert_called_once()
    assert resolver._timer is None

    # Verify file descriptors were removed
    resolver.loop.remove_reader.assert_any_call(1)  # type: ignore[unreachable]
    resolver.loop.remove_reader.assert_any_call(2)
    resolver.loop.remove_writer.assert_any_call(3)
    resolver.loop.remove_writer.assert_any_call(4)

    # Verify sets are cleared
    assert len(resolver._read_fds) == 0
    assert len(resolver._write_fds) == 0


@pytest.mark.asyncio
async def test_context_manager() -> None:
    """Test DNSResolver as async context manager."""
    resolver_closed = False

    # Create resolver and use as context manager
    async with aiodns.DNSResolver() as resolver:
        # Check resolver is not closed
        assert not resolver._closed

        # Mock the close method to track if it's called
        original_close = resolver.close

        async def mock_close() -> None:
            nonlocal resolver_closed
            resolver_closed = True
            await original_close()

        resolver.close = mock_close  # type: ignore[method-assign]

        # Resolver should be usable within context
        assert isinstance(resolver, aiodns.DNSResolver)

    # After exiting context, close should have been called
    assert resolver_closed


@pytest.mark.asyncio
async def test_context_manager_with_exception() -> None:
    """Test DNSResolver context manager handles exceptions properly."""
    resolver_closed = False

    try:
        async with aiodns.DNSResolver() as resolver:
            # Mock the close method to track if it's called
            original_close = resolver.close

            async def mock_close() -> None:
                nonlocal resolver_closed
                resolver_closed = True
                await original_close()

            resolver.close = mock_close  # type: ignore[method-assign]

            # Raise an exception within the context
            raise ValueError('Test exception')
    except ValueError:
        pass  # Expected

    # Close should still be called even with exception
    assert resolver_closed


@pytest.mark.asyncio
async def test_context_manager_close_idempotent() -> None:
    """Test that close() can be called multiple times safely."""
    close_count = 0

    async with aiodns.DNSResolver() as resolver:
        original_close = resolver.close

        async def mock_close() -> None:
            nonlocal close_count
            close_count += 1
            await original_close()

        resolver.close = mock_close  # type: ignore[method-assign]

        # Manually close resolver within context
        await resolver.close()
        assert close_count == 1

    # Context manager should call close again, but it should be idempotent
    assert close_count == 2


@pytest.mark.asyncio
async def test_temporary_resolver_not_garbage_collected() -> None:
    """Test temporary resolver is not garbage collected before query completes.

    Regression test for https://github.com/aio-libs/aiodns/issues/209

    When calling query() on a temporary resolver (not stored in a variable),
    the resolver should not be garbage collected before the query completes.
    Previously, the callback was a @staticmethod which didn't hold a reference
    to self, causing the resolver to be garbage collected and the query
    cancelled.
    """
    # Force garbage collection to ensure any weak references are cleared
    gc.collect()

    # This pattern previously failed with DNSError(24, 'DNS query cancelled')
    # because the resolver was garbage collected before the query completed
    result = await aiodns.DNSResolver(nameservers=['8.8.8.8']).query(
        'google.com', 'A'
    )

    # Query should succeed
    assert result
    assert len(result) > 0
    assert isinstance(result[0], AresQueryAResult)


def test_sock_state_cb_fallback_with_real_query() -> None:
    """Test that sock_state_cb fallback path works for actual DNS queries.

    This test forces the event_thread channel creation to fail, triggering
    the sock_state_cb fallback, then performs a real DNS query to verify
    the fallback path works correctly.
    """
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Perform a real DNS query through the sock_state_cb path
            result = await resolver.query('google.com', 'A')

            # Query should succeed
            assert result
            assert len(result) > 0
            assert isinstance(result[0], AresQueryAResult)

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


@pytest.mark.asyncio
async def test_gethostbyname_cancelled_future() -> None:
    """Test _gethostbyname_callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['192.0.2.1']  # Non-routable

    # Start a query
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        fut = resolver.gethostbyname('example.com', socket.AF_INET)

    # Cancel the future
    fut.cancel()

    # Manually invoke the callback with a cancelled future
    # This should not raise and should return early
    resolver._gethostbyname_callback(fut, 'example.com', None, None)

    await resolver.close()


def test_gethostbyname_with_sock_state_cb_fallback() -> None:
    """Test gethostbyname works with sock_state_cb fallback path."""
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Perform gethostbyname through the sock_state_cb path
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                result = await resolver.gethostbyname(
                    'google.com', socket.AF_INET
                )

            # Query should succeed
            assert isinstance(result, AresHostResult)
            assert len(result.addresses) > 0

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_sock_state_cb_wrapper_with_dead_weak_ref() -> None:
    """Test sock_state_cb_wrapper handles dead weak reference.

    When the resolver is garbage collected but the callback is still
    referenced by pycares, calling the callback should not raise an error.
    The weak reference will return None and the callback should exit early.
    """
    call_count = 0
    captured_callback: Any = None

    def patched_channel(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count, captured_callback
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call - capture the sock_state_cb and return a mock
        captured_callback = kwargs.get('sock_state_cb')
        return unittest.mock.MagicMock()

    # Use a mock loop to avoid any real socket operations
    mock_loop = unittest.mock.MagicMock(spec=asyncio.SelectorEventLoop)

    # Create a mock weak ref that returns None (simulating dead resolver)
    mock_dead_weak_ref = unittest.mock.MagicMock(return_value=None)

    with unittest.mock.patch(
        'aiodns.pycares.Channel', side_effect=patched_channel
    ):
        with unittest.mock.patch(
            'aiodns.weakref.ref', return_value=mock_dead_weak_ref
        ):
            resolver = aiodns.DNSResolver(loop=mock_loop, timeout=5.0)

            # Verify we captured the callback and are using fallback path
            assert resolver._event_thread is False
            assert captured_callback is not None

            # Mark as closed to prevent cleanup issues
            resolver._closed = True

    # Call the captured callback - should not raise since weak ref returns None
    # This exercises the "if this is not None:" branch when this IS None
    captured_callback(5, True, False)


def test_nameservers_property_getter() -> None:
    """Test that nameservers property getter returns channel servers."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)

    # Get nameservers through the property (covers _channel.servers getter)
    servers = resolver.nameservers

    # Should return a sequence (might be empty or have system defaults)
    assert isinstance(servers, (list, tuple))

    resolver._closed = True
    loop.close()


def test_nameservers_strips_port() -> None:
    """Test that nameservers getter strips port suffix."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)

    # Set nameservers - pycares 5.x will store them with :53 suffix
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    # Getter should return without port suffix for backward compatibility
    servers = resolver.nameservers
    assert servers == ['8.8.8.8', '8.8.4.4']

    # Verify no port suffix in any server
    for server in servers:
        assert ':' not in server

    resolver._closed = True
    loop.close()

#@pytest.mark.asyncio 是 pytest-asyncio 提供的 Marker，讓 pytest 知道這是一個非同步測試。
#測試框架會負責提供並執行 Event Loop，所以你可以直接在測試函式內使用 await。
'''
resolver.query_dns('google.com', 'A'):建立 Future 和 Callback，向 pycares 發起查詢
await Future:Future 尚未完成時，暫停目前測試 Coroutine
pycares 回傳 DNS Result:透過 Callback 通知 aiodns
_callback():呼叫 Future.set_result(result)
測試 Coroutine 恢復執行:將 DNSResult 指派給 result
'''
@pytest.mark.asyncio
async def test_query_dns() -> None:
    """Test query_dns returns native pycares DNSResult."""
    resolver = aiodns.DNSResolver(timeout=5.0) #這裡沒有傳入 loop，因此會使用目前 asyncio 環境提供的 Event Loop。但是舊版是需要透過呼叫setup建立resolver，傳入loop
    resolver.nameservers = ['8.8.8.8'] #使用真實 DNS Server 的 Integration Test

    result = await resolver.query_dns('google.com', 'A')

    # Should return pycares.DNSResult
    assert isinstance(result, pycares.DNSResult) #query_dns() 回傳的結果是原生 pycares.DNSResult
    assert hasattr(result, 'answer')
    assert hasattr(result, 'authority')
    assert hasattr(result, 'additional')

    # Answer should contain DNSRecord objects
    assert len(result.answer) > 0 #確認 answer 至少有一筆 DNS Record。
    record = result.answer[0]
    assert hasattr(record, 'type') #dns record type: ex: A
    assert hasattr(record, 'ttl') #time to live
    assert hasattr(record, 'data') #dns record 的實際資料
    assert record.type == pycares.QUERY_TYPE_A #result = await resolver.query_dns('google.com', 'A')

    await resolver.close()


@pytest.mark.asyncio
async def test_query_deprecation_warning() -> None:
    """Test that query() emits deprecation warning."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        await resolver.query('google.com', 'A')

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert 'query() is deprecated' in str(w[0].message)

    await resolver.close()


@pytest.mark.asyncio
async def test_gethostbyname_deprecation_warning() -> None:
    """Test that gethostbyname() emits deprecation warning."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        await resolver.gethostbyname('google.com', socket.AF_INET)

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert 'gethostbyname() is deprecated' in str(w[0].message)

    await resolver.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == 'win32', reason='CHAOS class unreliable')
async def test_query_dns_with_qclass() -> None:
    """Test query_dns with qclass parameter."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['1.1.1.1']

    # CHAOS class queries may be refused by some servers
    try:
        result = await resolver.query_dns('id.server', 'TXT', 'CHAOS')
        assert isinstance(result, pycares.DNSResult)
        assert len(result.answer) > 0
    except aiodns.error.DNSError:
        # CHAOS queries are often refused, that's ok
        pass

    await resolver.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == 'darwin', reason='skipped on Darwin as it is flakey on CI'
)
async def test_compat_txt_returns_str() -> None:
    """Test deprecated query() TXT returns str for ASCII text."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        result = await resolver.query('google.com', 'TXT')

    assert len(result) > 0
    # pycares 4.x returned str for ASCII TXT records
    assert isinstance(result[0].text, str)

    await resolver.close()


@pytest.mark.asyncio
async def test_compat_naptr_returns_str() -> None:
    """Test deprecated query() NAPTR returns str fields."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        result = await resolver.query('sip2sip.info', 'NAPTR')

    assert len(result) > 0
    # pycares 4.x returned str for these fields
    assert isinstance(result[0].flags, str)
    assert isinstance(result[0].service, str)
    assert isinstance(result[0].regex, str)

    await resolver.close()


@pytest.mark.asyncio
async def test_compat_caa_returns_str() -> None:
    """Test deprecated query() CAA returns str fields."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        try:
            result = await resolver.query('google.com', 'CAA')
        except aiodns.error.DNSError:
            # CAA may not exist, skip test
            await resolver.close()
            return

    if len(result) > 0:
        # pycares 4.x returned str for these fields
        assert isinstance(result[0].property, str)
        assert isinstance(result[0].value, str)

    await resolver.close()


def test_getaddrinfo_with_sock_state_cb_fallback() -> None:
    """Test getaddrinfo with sock_state_cb fallback.

    This covers the non-event_thread callback path in _get_future_callback.
    """
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Call getaddrinfo - this uses _get_future_callback
            # which exercises line 190 (non-event_thread cb path)
            result = await resolver.getaddrinfo(
                'google.com', family=socket.AF_INET
            )

            # Query should succeed
            assert result is not None
            assert result.nodes

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_sock_state_cb_and_timer_cb() -> None:
    """Test _sock_state_cb and _timer_cb with real file descriptors."""
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise pycares.AresError(1, 'Simulated failure')
        return original_channel(*args, **kwargs)

    # Create real socket pairs for testing
    sock1, sock2 = socket.socketpair()
    sock3, sock4 = socket.socketpair()
    fd1 = sock1.fileno()
    fd2 = sock3.fileno()

    try:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=0)
            assert resolver._event_thread is False

            # Test writable only (readable=False, writable=True)
            resolver._sock_state_cb(fd1, False, True)
            assert fd1 in resolver._write_fds
            assert fd1 not in resolver._read_fds
            assert resolver._timer is not None

            # Test _timer_cb with active fds - should restart timer
            resolver._timer_cb()
            assert resolver._timer is not None

            # Test socket close for write fd
            resolver._sock_state_cb(fd1, False, False)
            assert fd1 not in resolver._write_fds

            # Test readable and writable together
            resolver._sock_state_cb(fd2, True, True)
            assert fd2 in resolver._read_fds
            assert fd2 in resolver._write_fds

            # Test socket close for both
            resolver._sock_state_cb(fd2, False, False)
            assert fd2 not in resolver._read_fds
            assert fd2 not in resolver._write_fds

            # Timer should be cancelled when no fds left
            assert resolver._timer is None

            # Test _timer_cb without active fds - should clear timer
            resolver._timer = loop.call_later(1, lambda: None)  # type: ignore[unreachable]
            resolver._timer_cb()
            assert resolver._timer is None

            resolver._closed = True
    finally:
        sock1.close()
        sock2.close()
        sock3.close()
        sock4.close()
        loop.close()

#主要驗證：當 Future 已經被取消後，即使 _callback() 收到成功結果或錯誤，也不應再次修改 Future。
@pytest.mark.asyncio
async def test_callback_cancelled_future() -> None:
    """Test _callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[str] = asyncio.get_event_loop().create_future()
    fut.cancel() #這裡只是取消 Future，沒有執行 resolver.cancel()，也沒有任何 DNS 查詢需要取消。

    # Directly call _callback with cancelled future - should return early
    #理論上因為_callback()有fut.done()，所以會直接return，result不會被寫入future。
    resolver._callback(fut, 'result', None) #模擬 pycares 已經取得成功結果，現在要通知 aiodns。預期會被忽略
    #建議加入assert fut.cancelled()
    # Also test with errorno - should still return early
    # Pass empty string as result (ignored when errorno is set)
    resolver._callback(fut, '', 1) #預期會忽略錯誤
    #建議加入assert fut.cancelled()
    resolver._closed = True #不等於await resolver.close()，只是避免在測試結束時觸發清理邏輯。

#新版 Callback 收到錯誤，Future 儲存 DNSError
@pytest.mark.asyncio
async def test_callback_error() -> None:
    """Test _callback handles error."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[str] = asyncio.get_event_loop().create_future()

    # Call _callback with an error
    # Pass empty string as result (ignored when errorno is set)
    resolver._callback(fut, '', pycares.errno.ARES_ENOTFOUND)

    # Future should have exception set
    with pytest.raises(aiodns.error.DNSError):
        fut.result()

    resolver._closed = True

#舊版 Callback 收到已取消 Future，直接返回，不修改 Future
@pytest.mark.asyncio
async def test_query_callback_cancelled_future() -> None:
    """Test _query_callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    fut.cancel()

    # Directly call _query_callback with cancelled future - should return early
    # Cast None to DNSResult since the result is not used when cancelled
    resolver._query_callback(
        fut, pycares.QUERY_TYPE_A, cast(pycares.DNSResult, None), None
    )

    resolver._closed = True

#舊版 _query_callback() 有兩種不同的錯誤來源
#1:舊版 Callback 收到錯誤，直接fut.set_exception -> Future 儲存 DNSError
@pytest.mark.asyncio
async def test_query_callback_error() -> None:
    """Test _query_callback handles error."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()

    # Call _query_callback with an error
    # Cast None to DNSResult since the result is not used when errorno is set
    resolver._query_callback(
        fut,
        pycares.QUERY_TYPE_A,
        cast(pycares.DNSResult, None),
        pycares.errno.ARES_ENOTFOUND,
    )

    # Future should have exception set
    with pytest.raises(aiodns.error.DNSError):
        fut.result()

    resolver._closed = True
#2:舊版 Callback 收到空的 DNSResult(pycares沒有回報錯誤)，enter convert_result() -> Future 儲存 DNSError
@pytest.mark.asyncio
async def test_query_callback_empty_result_raises_enodata() -> None:
    """convert_result raising must route through fut.set_exception."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    #使用 MagicMock 模擬 DNSResult，MagicMock 是 Python unittest.mock 提供的 Mock 物件，可以模擬其他物件的行為。
    empty = unittest.mock.MagicMock(spec=pycares.DNSResult)#讓 Mock 參照 pycares.DNSResult 的介面，限制它能使用的屬性名稱。
    empty.answer = []#建立了一個沒有 Answer Records 的假 DNSResult，用來測試舊版資料轉換的錯誤處理。

    resolver._query_callback(fut, pycares.QUERY_TYPE_PTR, empty, None)#_query_callback() 不會進入直接處理 pycares 錯誤碼的分支，而是嘗試轉換查詢結果。

    #驗證 Future 儲存正確的 Exception
    with pytest.raises(aiodns.error.DNSError) as exc_info:
        fut.result()
    assert exc_info.value.args[0] == pycares.errno.ARES_ENODATA

    resolver._closed = True

#當 pycares 在發起 DNS 查詢時同步拋出 AresError，aiodns 應將錯誤儲存在 Future，而不是直接從 query_dns() 或 query() 拋出，造成future無法反應最終結果
#驗證 _capture_ares_error() 是否能正確處理同步發生的 pycares.AresError。
#新版舊版共用測試 Helper，驗證不合法 Hostname 的錯誤會透過 Future 傳遞
async def _assert_malformed_name_routes_through_future(
    fut: asyncio.Future[Any],
) -> None: #接收 Future
    # 驗證 API 回傳的是 Future，而不是直接同步拋出錯誤
    assert isinstance(fut, asyncio.Future)
    # await Future 時應收到 DNSError
    with pytest.raises(aiodns.error.DNSError) as exc_info:
        await fut
    # 驗證錯誤碼為不合法 Hostname
    assert exc_info.value.args[0] == aiodns.error.ARES_EBADNAME


@pytest.mark.asyncio
async def test_query_dns_malformed_name_routes_through_future() -> None:
    """Synchronous pycares.AresError must be routed through the future.

    Regression test for https://github.com/aio-libs/aiodns/issues/231:
    previously a malformed name raised AresError synchronously, leaving
    the internally-created future orphaned with an unretrieved exception.
    """
    async with aiodns.DNSResolver() as resolver:
        # 新版 query_dns() 應回傳 Future
        # 不合法 Hostname 的錯誤應透過 await 傳遞
        await _assert_malformed_name_routes_through_future(
            resolver.query_dns('example test.com', 'A')
        )


@pytest.mark.asyncio
async def test_query_malformed_name_routes_through_future() -> None:
    """Same as above for the deprecated query() entry point."""
    async with aiodns.DNSResolver() as resolver:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)

            # 驗證舊版 API 也能正確處理同步 AresError
            fut = resolver.query('example test.com', 'A')
        await _assert_malformed_name_routes_through_future(fut)


def _call_resolver_entry_point(
    resolver: aiodns.DNSResolver, channel_method: str
) -> asyncio.Future[Any]:
    if channel_method == 'getaddrinfo':
        return resolver.getaddrinfo('host')
    if channel_method == 'getnameinfo':
        return resolver.getnameinfo(('127.0.0.1', 0))
    assert channel_method == 'gethostbyaddr'
    return resolver.gethostbyaddr('127.0.0.1')

#還是在驗證 _capture_ares_error() 能否正確處理同步發生的 pycares.AresError，差別主要在於如何觸發錯誤(這邊是用mock)。
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'channel_method', ['getaddrinfo', 'getnameinfo', 'gethostbyaddr']
)
async def test_wrapped_entry_points_route_sync_ares_error(
    channel_method: str,
) -> None:
    """Each wrapper routes a synchronous AresError to the returned future.

    pycares does not currently validate inputs to these entry points
    synchronously, so we inject an AresError via mock to prove the
    wrapper is wired up and would not regress to a sync raise.
    """
    async with aiodns.DNSResolver() as resolver:
        exc = pycares.AresError(
            aiodns.error.ARES_EBADNAME, 'Misformatted domain name'
        )
        #暫時將 resolver._channel.getaddrinfo() 替換成 Mock，並設定每次呼叫這個方法時，直接拋出指定的 AresError。
        with unittest.mock.patch.object(
            resolver._channel, channel_method, side_effect=exc
        ):
            fut = _call_resolver_entry_point(resolver, channel_method)#Mock 就會立即拋出 AresError。
        await _assert_malformed_name_routes_through_future(fut)#如果 _capture_ares_error() 正常運作，這時 Future 已經被設定 Exception。


@pytest.mark.asyncio
async def test_capture_ares_error_leaves_done_future_untouched() -> None:
    """When the callback already finished the future, the captured
    AresError must be discarded; reaching the body of the context
    manager would call set_exception() on a done future and raise
    InvalidStateError, so passing through cleanly is the assertion."""
    async with aiodns.DNSResolver() as resolver:
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        fut.set_result(None)
        with resolver._capture_ares_error(fut):
            raise pycares.AresError(
                aiodns.error.ARES_EBADNAME, 'Misformatted domain name'
            )


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
