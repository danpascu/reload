# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from asyncio import AbstractEventLoop, CancelledError, Event, Future, get_running_loop
from collections import deque
from collections.abc import Generator
from enum import Enum
from typing import Any, Final, Literal, Self

from . import exceptions

__all__ = 'Channel', 'unlimited'


class WaiterQueue[T](deque[T]):
    def discard(self, value: T) -> None:
        try:  # noqa: SIM105
            self.remove(value)
        except ValueError:
            pass


class un(float, Enum):  # noqa: N801
    limited = float('inf')

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}.{self.name}'

    __str__ = __repr__


unlimited: Final = un.limited


class Channel[T]:
    def __init__(self, buffer_size: int | Literal[un.limited] = un.limited) -> None:
        if buffer_size < 0:
            raise ValueError('buffer_size must be a non-negative integer')
        self._buffer_size = buffer_size
        self._queue = deque[T]()
        self._readers = WaiterQueue[Future[T]]()
        self._writers = WaiterQueue[tuple[Future[None], T]]()
        self._done = Event()
        self._closed = False

    @property
    def _loop(self) -> AbstractEventLoop:
        loop = get_running_loop()
        if '_loop' not in self.__dict__ and self.__dict__.setdefault('_loop', loop) is not loop:
            raise RuntimeError(f'{self!r} is bound to a different event loop')
        return loop

    def send_nowait(self, value: T) -> None:
        if self._closed:
            raise exceptions.ClosedResourceError
        assert not self._readers or len(self._queue) == 0  # noqa: S101
        while self._readers:
            future = self._readers.popleft()
            if not future.cancelled():
                future.set_result(value)
                return
        # No active pending readers. Add to the queue if permitted by the maximum queue size.
        if len(self._queue) < self._buffer_size:
            self._queue.append(value)
        else:
            raise exceptions.WouldBlock

    async def send(self, value: T) -> None:
        try:
            self.send_nowait(value)
        except exceptions.WouldBlock:
            future = self._loop.create_future()
            self._writers.append((future, value))
            try:
                await future
            except CancelledError:
                self._writers.discard((future, value))
                if self._closed and not self._done.is_set() and not self._writers and not self._queue:
                    self._done.set()
                raise

    def receive_nowait(self) -> T:
        assert not self._writers or len(self._queue) == self._buffer_size  # noqa: S101
        while self._writers:
            future, value = self._writers.popleft()
            if not future.cancelled():
                self._queue.append(value)
                future.set_result(None)
                break
        if self._closed:
            if not self._done.is_set():
                if not self._writers and len(self._queue) <= 1:
                    self._done.set()
                if self._queue:
                    return self._queue.popleft()
            raise exceptions.EndOfChannel
        if self._queue:
            return self._queue.popleft()
        raise exceptions.WouldBlock

    async def receive(self) -> T:
        try:
            value = self.receive_nowait()
        except exceptions.WouldBlock:
            future = self._loop.create_future()
            self._readers.append(future)
            try:
                value = await future
            except CancelledError:
                self._readers.discard(future)
                raise
        return value

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        while self._readers:
            # terminate pending readers as they would otherwise wait forever.
            future = self._readers.popleft()
            if not future.cancelled():
                future.set_exception(exceptions.EndOfChannel)
        if not self._writers and not self._queue:
            self._done.set()

    def __await__(self) -> Generator[Any, Any, None]:
        # use yield from to avoid returning True from _done.wait().__await__()
        yield from self._done.wait().__await__()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_value: object, exc_traceback: object) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, exc_traceback: object) -> None:
        self.close()
        await self._done.wait()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> T:
        try:
            return await self.receive()
        except exceptions.EndOfChannel as exc:
            raise StopAsyncIteration from exc
