from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import socket
import sys
import warnings
import weakref
from collections.abc import Callable, Iterable, Iterator, Sequence
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import pycares #pycares 是 Python 對 c-ares 非同步 DNS Resolver 函式庫的封裝。

from . import error #匯入error.py，提供 aiodns 使用的錯誤相關定義，後續閱讀異常處理時會遇到。
from .compat import ( #從compat.py，提供 DNS 查詢結果的型別，以及結果格式轉換相關功能。
    AresHostResult,
    AresQueryAAAAResult,
    AresQueryAResult, #A Record 查詢結果的型別
    AresQueryCAAResult,
    AresQueryCNAMEResult,
    AresQueryMXResult,
    AresQueryNAPTRResult,
    AresQueryNSResult,
    AresQueryPTRResult,
    AresQuerySOAResult,
    AresQuerySRVResult,
    AresQueryTXTResult,
    QueryResult, #查詢結果的型別註記
    convert_result, #結果格式轉換函式
)

__version__ = '4.0.4'

__all__ = (
    'DNSResolver',
    'error',
)

_T = TypeVar('_T') #用來表示泛型型別

#表示在某些 Windows 環境中，如果 pycares 沒有啟用適當的 Event Thread 支援，ProactorEventLoop 可能無法正常搭配 aiodns 使用。
WINDOWS_SELECTOR_ERR_MSG = (
    'ProactorEventLoop will not work with aiodns on Windows without event '
    'threads. See more: https://github.com/aio-libs/aiodns#note-for-windows-users'
)

_LOGGER = logging.getLogger(__name__)

#DNS Record 類型對應表，這是一個 Dictionary，用來把使用者輸入的 DNS Record Type 字串，轉換成 pycares 使用的常數。
query_type_map = {
    'A': pycares.QUERY_TYPE_A,
    'AAAA': pycares.QUERY_TYPE_AAAA,
    'ANY': pycares.QUERY_TYPE_ANY,
    'CAA': pycares.QUERY_TYPE_CAA,
    'CNAME': pycares.QUERY_TYPE_CNAME,
    'MX': pycares.QUERY_TYPE_MX,
    'NAPTR': pycares.QUERY_TYPE_NAPTR,
    'NS': pycares.QUERY_TYPE_NS,
    'PTR': pycares.QUERY_TYPE_PTR,
    'SOA': pycares.QUERY_TYPE_SOA,
    'SRV': pycares.QUERY_TYPE_SRV,
    'TXT': pycares.QUERY_TYPE_TXT,
}
#DNS Query Class 對應表，和 query_type_map 類似，但是描述 DNS Class，不是 Record Type。
query_class_map = {
    'IN': pycares.QUERY_CLASS_IN,
    'CHAOS': pycares.QUERY_CLASS_CHAOS,
    'HS': pycares.QUERY_CLASS_HS,
    'NONE': pycares.QUERY_CLASS_NONE,
    'ANY': pycares.QUERY_CLASS_ANY,
}
'''
Resolver（DNS 解析器）：負責把網域名稱查詢成 IP 位址或其他 DNS 資訊。
pycares：一個 Python 函式庫，讓 Python 程式能使用底層的非同步 DNS 查詢功能。
為什麼 aiodns 需要 Event Loop？因為後續 DNS 查詢是非同步操作，需要 Event Loop 來管理 Future、Callback 和 I/O 事件。
Resolver 是負責 DNS 解析的物件，pycares 提供底層非同步 DNS 功能，而 aiodns 負責把 pycares 的 Callback 整合成 asyncio Future，讓 Python 程式能用 await 取得查詢結果。
Callback 是一個傳給其他函式、等待被呼叫的函式。

1. Python 呼叫 aiodns:resolver.query_dns("google.com", "A")

2. aiodns 建立 Future:代表這筆 DNS 查詢未來會產生的結果

3. aiodns 呼叫 pycares.query():發起查詢，並把 Callback 交給 pycares

4. DNS 查詢進行中:Future 處於 Pending，程式可以處理其他工作

5. pycares 呼叫 Callback:將 DNS 回傳的結果或錯誤通知 aiodns

6. aiodns 完成 Future:set_result() 或 set_exception()

7. await 恢復執行:取得查詢結果，或收到例外
'''
class DNSResolver:
    def __init__(
        self,
        nameservers: Sequence[str] | None = None, #使用者指定的DNS server，ex: 8.8.8.8
        loop: asyncio.AbstractEventLoop | None = None, #使用者指定的 asyncio Event Loop
        **kwargs: Any, #額外提供給底層 Channel 的設定參數
    ) -> None:  # TODO(PY311): Use Unpack for kwargs. #constructor不回傳值
        self._closed = True #暫時把resolver設成不可使用的狀態
        self.loop = loop or asyncio.get_event_loop() #如果使用者有提供 loop，就使用指定的 Event Loop。如果沒有提供，則透過 asyncio.get_event_loop() 取得 Event Loop。
        if TYPE_CHECKING:
            assert self.loop is not None
        kwargs.pop('sock_state_cb', None)
        timeout = kwargs.pop('timeout', None)
        self._timeout = timeout
        self._event_thread, self._channel = self._make_channel(**kwargs) #呼叫 DNSResolver 裡面的另一個方法，負責建立 pycares Channel。
        if nameservers:
            self.nameservers = nameservers
        #當某個 DNS Socket 有資料可以讀取時，Event Loop 可以通知對應的處理函式。
        self._read_fds: set[int] = set() #需要監控可讀取事件的 File Descriptors
        self._write_fds: set[int] = set() #需要監控可寫入事件的 File Descriptors
        self._timer: asyncio.TimerHandle | None = None
        self._closed = False #標示resolver初始化完成

    def _make_channel(self, **kwargs: Any) -> tuple[bool, pycares.Channel]:
        # pycares 5+ uses event_thread by default when sock_state_cb
        # is not provided
        #Event Thread 模式（優先使用）：由 pycares 的內部 Event Thread 處理底層事件。
        #Socket State Callback 模式（備援）：由 aiodns 使用 asyncio Event Loop 監控 Socket 事件。
        try:
            return True, pycares.Channel(timeout=self._timeout, **kwargs)
        except pycares.AresError as e:
            if sys.platform == 'linux':
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. This '
                    'usually means the system ran out of inotify watches. '
                    'Falling back to socket state callback. Consider '
                    'increasing the system inotify watch limit: %s',
                    e,
                )
            else:
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. '
                    'Falling back to socket state callback: %s',
                    e,
                )
        # Fall back to sock_state_cb
        # We cannot use a ProactorEventLoop because it does not
        # provide an add_reader or add_writer function to utilize.
        if sys.platform == 'win32':
            if hasattr(asyncio, 'ProactorEventLoop'):
                if isinstance(self.loop, asyncio.ProactorEventLoop):
                    raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG)
        # Use weak reference for deterministic cleanup. Without it there's a
        # reference cycle (DNSResolver -> _channel -> callback -> DNSResolver).
        # Python 3.4+ can handle cycles with __del__, but weak ref ensures
        # cleanup happens immediately when last reference is dropped.
        weak_self = weakref.ref(self)

        #這個 Wrapper 是交給 pycares 的 Callback。Socket 監控需求改變，通知 aiodns 哪些 Socket 需要監控讀取或寫入，不是DNS query callback
        def sock_state_cb_wrapper(
            fd: int, readable: bool, writable: bool
        ) -> None:
            this = weak_self()
            if this is not None:
                this._sock_state_cb(fd, readable, writable)
        # 建立 Fallback Channel，回傳 False 表示未使用 Event Thread
        return False, pycares.Channel(
            sock_state_cb=sock_state_cb_wrapper,
            timeout=self._timeout,
            **kwargs,
        )

    @property
    def nameservers(self) -> Sequence[str]:
        # pycares 5.x returns servers with port (e.g., '8.8.8.8:53')
        # Strip port for backward compatibility with pycares 4.x
        return [s.rsplit(':', 1)[0] for s in self._channel.servers]

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        self._channel.servers = value

    #fut	這筆 DNS Query 對應的 Future
    #result	pycares 回傳的 DNS 查詢結果
    #errorno	錯誤代碼，若無錯誤則為 None
    def _callback(
        self, fut: asyncio.Future[_T], result: _T, errorno: int | None
    ) -> None:
        # The future can already be done if pycares raised synchronously
        # and _capture_ares_error set the exception before c-ares delivered
        # the same error through this callback.
        if fut.done():#檢查future是不是進入完成模式
            return #不再修改future
        if errorno is not None:
            # 如果有錯誤，將錯誤設置到 future 中
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            fut.set_result(result) #將 DNS 查詢結果存入 Future，並將它標記為已完成。
    '''
    pycares Event Thread
        |
        | DNS 查詢完成
        v
    cb(result, error)
        |
        | call_soon_threadsafe(...)
        v
    asyncio Event Loop
        |
        | 排程執行
        v
    self._callback(future, result, error)
        |
        v
    Future 完成
        |
        v
    await 恢復執行
    '''
    def _get_future_callback(
        self,
    ) -> tuple[asyncio.Future[_T], Callable[[_T, int | None], None]]:
        """Return a future and a callback to set the result of the future."""
        cb: Callable[[_T, int | None], None] #型別宣告
        future: asyncio.Future[_T] = self.loop.create_future()#建立真正future
        if self._event_thread:
            #建立callback時先把future綁定進去，等到callback被呼叫時，可以知道應該更新哪個 Future。
            cb = functools.partial(  # type: ignore[assignment] #預先固定函式的一部分參數，產生一個新的可呼叫物件。
                #為什麼需要 call_soon_threadsafe()？
                #因為 Event Thread 模式下，pycares 可能在自己的背景執行緒呼叫 Callback。
                #但是 asyncio.Future 應該由它所屬的 Event Loop 安全地操作，而不是直接從其他執行緒修改。
                self.loop.call_soon_threadsafe,#把真正更新 Future 的操作排程到 asyncio Event Loop。
                self._callback,  # type: ignore[arg-type]
                future,
            ) #當pycares呼叫cb(result, error)時，並不會直接執行_callback()(更新future)，而是把self._callback(future, result, error)排到asyncio event loop，等event loop執行它
        else:
            cb = functools.partial(self._callback, future)#在callback被呼叫時直接執行
        return future, cb

    def _query_callback(
        self,
        fut: asyncio.Future[QueryResult],
        qtype: int,
        result: pycares.DNSResult,
        errorno: int | None,
    ) -> None:
        """Callback for query that converts results to compatible format."""
        # See _callback for why we guard on done() rather than cancelled().
        if fut.done():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
            return
        try:
            converted = convert_result(result, qtype)
        except error.DNSError as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(converted)

    def _get_query_future_callback(
        self, qtype: int
    ) -> tuple[asyncio.Future[QueryResult], Callable[..., None]]:
        """Return a future and callback for query with result conversion."""
        future: asyncio.Future[QueryResult] = self.loop.create_future()
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(  # type: ignore[assignment]
                self.loop.call_soon_threadsafe,
                self._query_callback,  # type: ignore[arg-type]
                future,
                qtype,
            )
        else:
            cb = functools.partial(self._query_callback, future, qtype)
        return future, cb

    #即使 pycares 在 channel.query() 當下就發生錯誤，aiodns 仍會把錯誤存入 Future，讓使用者透過 await future 收到例外。
    @contextlib.contextmanager
    def _capture_ares_error(self, fut: asyncio.Future[_T]) -> Iterator[None]:
        # When pycares raises synchronously (e.g. ARES_EBADNAME for a
        # malformed hostname), c-ares may also invoke the callback first,
        # leaving the future already done. Route the error through the
        # future so callers can rely on `await` to raise.
        try:
            yield
        except pycares.AresError as exc:
            # 若 Callback 已先完成 Future，或 Future 已取消，
            # 則不再重複設定錯誤，避免 InvalidStateError
            if fut.done():
                return
            # pycares always raises (errno, message), but be defensive:
            # an args-less AresError should still resolve the future to
            # avoid an indefinite hang on `await`.
            # 取得 pycares 的錯誤碼
            # 若 Exception 沒有參數，則使用 ARES_EFORMERR
            errno = exc.args[0] if exc.args else error.ARES_EFORMERR
            # 將錯誤轉換為 DNSError 並存入 Future
            fut.set_exception(
                error.DNSError(errno, pycares.errno.strerror(errno))
            )

    @overload
    def query(
        self, host: str, qtype: Literal['A'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['AAAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAAAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryCAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CNAME'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryCNAMEResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['MX'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryMXResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NAPTR'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNAPTRResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NS'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNSResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['PTR'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryPTRResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SOA'], qclass: str | None = ...
    ) -> asyncio.Future[AresQuerySOAResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SRV'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQuerySRVResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['TXT'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryTXTResult]]: ...

    #舊版api
    def query(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[list[Any]] | asyncio.Future[Any]:
        """Query DNS records (deprecated, use query_dns instead)."""
        warnings.warn(
            'query() is deprecated, use query_dns() instead',
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            qtype_int = query_type_map[qtype]
        except KeyError as e:
            raise ValueError(f'invalid query type: {qtype}') from e
        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = query_class_map[qclass]
            except KeyError as e:
                raise ValueError(f'invalid query class: {qclass}') from e

        fut, cb = self._get_query_future_callback(qtype_int)
        with self._capture_ares_error(fut):
            if qclass_int is not None:
                self._channel.query(
                    host, qtype_int, query_class=qclass_int, callback=cb
                )
            else:
                self._channel.query(host, qtype_int, callback=cb)
        return fut
    
    #接收使用者的 DNS 查詢需求，建立一個 Future 和對應的 Callback，交給 pycares 執行 DNS 查詢，最後把 Future 回傳給使用者。
    #query_dns() 本身不是 async def，所以它不會在函式內等待 DNS 結果，而是直接回傳 Future。使用者可以寫: result = await future
    def query_dns(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[pycares.DNSResult]:
        """Query DNS records, returning native pycares 5.x DNSResult."""
        try:
            qtype_int = query_type_map[qtype] #轉換DNS query type
        except KeyError as e:
            raise ValueError(f'invalid query type: {qtype}') from e
        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = query_class_map[qclass]
            except KeyError as e:
                raise ValueError(f'invalid query class: {qclass}') from e
        #建立 Future 和 Callback
        fut: asyncio.Future[pycares.DNSResult] #只是宣告 fut 的型別，還沒有真正建立 Future。
        fut, cb = self._get_future_callback() #真正建立 Future
        with self._capture_ares_error(fut):
            if qclass_int is not None:
                #這裡的 self._channel，就是你先前在 _make_channel() 建立的 pycares Channel。
                self._channel.query(
                    host, qtype_int, query_class=qclass_int, callback=cb
                )#真正向 pycares 發起 DNS 查詢的地方。請 pycares 查詢 google.com 的 A Record，查詢完成後呼叫 cb。
            else:
                self._channel.query(host, qtype_int, callback=cb)
        return fut #result = await resolver.query_dns("google.com", "A")
 
    def _gethostbyname_callback(
        self,
        fut: asyncio.Future[AresHostResult],
        host: str,
        result: pycares.AddrInfoResult | None,
        errorno: int | None,
    ) -> None:
        """Callback for gethostbyname that converts AddrInfoResult."""
        # See _callback for why we guard on done() rather than cancelled().
        if fut.done():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            assert result is not None  # noqa: S101
            # node.addr is (address_bytes, port) - extract and decode
            addresses = [node.addr[0].decode() for node in result.nodes]
            # Get canonical name from cnames if available
            name = result.cnames[0].name if result.cnames else host
            fut.set_result(
                AresHostResult(name=name, aliases=[], addresses=addresses)
            )

    def gethostbyname(
        self, host: str, family: socket.AddressFamily
    ) -> asyncio.Future[AresHostResult]:
        """
        Resolve hostname to addresses.

        Deprecated: Use getaddrinfo() instead. This is implemented using
        getaddrinfo as pycares 5.x removed the gethostbyname method.
        """
        warnings.warn(
            'gethostbyname() is deprecated, use getaddrinfo() instead',
            DeprecationWarning,
            stacklevel=2,
        )
        fut: asyncio.Future[AresHostResult] = self.loop.create_future()
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(  # type: ignore[assignment]
                self.loop.call_soon_threadsafe,
                self._gethostbyname_callback,  # type: ignore[arg-type]
                fut,
                host,
            )
        else:
            cb = functools.partial(self._gethostbyname_callback, fut, host)
        with self._capture_ares_error(fut):
            self._channel.getaddrinfo(host, None, family=family, callback=cb)
        return fut

    def getaddrinfo(
        self,
        host: str,
        family: socket.AddressFamily = socket.AF_UNSPEC,
        port: int | None = None,
        proto: int = 0,
        type: int = 0,
        flags: int = 0,
    ) -> asyncio.Future[pycares.AddrInfoResult]:
        fut: asyncio.Future[pycares.AddrInfoResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.getaddrinfo(
                host,
                port,
                family=family,
                type=type,
                proto=proto,
                flags=flags,
                callback=cb,
            )
        return fut

    def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> asyncio.Future[pycares.NameInfoResult]:
        fut: asyncio.Future[pycares.NameInfoResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.getnameinfo(sockaddr, flags, callback=cb)
        return fut

    def gethostbyaddr(self, name: str) -> asyncio.Future[pycares.HostResult]:
        fut: asyncio.Future[pycares.HostResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.gethostbyaddr(name, callback=cb)
        return fut

    def cancel(self) -> None:
        self._channel.cancel()

    def _sock_state_cb(self, fd: int, readable: bool, writable: bool) -> None:
        if readable or writable:
            if readable:
                self.loop.add_reader(
                    fd, self._channel.process_fd, fd, pycares.ARES_SOCKET_BAD
                )
                self._read_fds.add(fd)
            if writable:
                self.loop.add_writer(
                    fd, self._channel.process_fd, pycares.ARES_SOCKET_BAD, fd
                )
                self._write_fds.add(fd)
            if self._timer is None:
                self._start_timer()
        else:
            # socket is now closed
            if fd in self._read_fds:
                self._read_fds.discard(fd)
                self.loop.remove_reader(fd)

            if fd in self._write_fds:
                self._write_fds.discard(fd)
                self.loop.remove_writer(fd)

            if (
                not self._read_fds
                and not self._write_fds
                and self._timer is not None
            ):
                self._timer.cancel()
                self._timer = None

    def _timer_cb(self) -> None:
        if self._read_fds or self._write_fds:
            self._channel.process_fd(
                pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD
            )
            self._start_timer()
        else:
            self._timer = None

    def _start_timer(self) -> None:
        timeout = self._timeout
        if timeout is None or timeout < 0 or timeout > 1:
            timeout = 1
        elif timeout == 0:
            timeout = 0.1

        self._timer = self.loop.call_later(timeout, self._timer_cb)

    def _cleanup(self) -> None:
        """Cleanup timers and file descriptors when closing resolver."""
        if self._closed: #避免重複清理，如果 Resolver 已經關閉，就直接返回
            return
        # Mark as closed first to prevent double cleanup
        self._closed = True #避免 Cleanup 過程中再次進入 _cleanup() 時，重複釋放相同的資源。
        # Cancel timer if running
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        #移除 DNSResolver 原本註冊到 Event Loop 的 Socket 監聽。
        # Remove all file descriptors
        for fd in self._read_fds:
            self.loop.remove_reader(fd)
        for fd in self._write_fds:
            self.loop.remove_writer(fd)
        #清空 Resolver 內部記錄的 File Descriptors。
        self._read_fds.clear()
        self._write_fds.clear()
        self._channel.close() #呼叫底層 pycares Channel 的 close()，關閉 Resolver 使用的 DNS Channel。

    async def close(self) -> None:
        """
        Cleanly close the DNS resolver.

        This should be called to ensure all resources are properly released.
        After calling close(), the resolver should not be used again.
        """
        if not self._closed:
            #pycares 通常會透過對應的 Callback 回報 ARES_ECANCELLED，再由 aiodns 將 DNSError 設定到 Future。
            self._channel.cancel()#會要求 pycares 取消尚未完成的查詢。
        self._cleanup()

    async def __aenter__(self) -> DNSResolver:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the async context manager."""
        await self.close()

    def __del__(self) -> None:
        """Handle cleanup when the resolver is garbage collected."""
        # Check if we have a channel to clean up
        # This can happen if an exception occurs during __init__ before
        # _channel is created (e.g., RuntimeError on Windows
        # without proper loop)
        if hasattr(self, '_channel'):
            self._cleanup()
