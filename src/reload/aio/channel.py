# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from asyncio import Event, CancelledError, get_running_loop
from collections import deque
from math import inf

from . import exceptions


__all__ = 'Channel',


class WaiterQueue(deque):
    def discard(self, value):
        try:
            self.remove(value)
        except ValueError:
            pass


class Channel:
    def __init__(self, buffer_size=inf):
        if buffer_size != inf and not isinstance(buffer_size, int):
            raise TypeError('buffer_size must be a positive integer or math.inf')
        if buffer_size < 0:
            raise ValueError('buffer_size must be >= 0')
        self._buffer_size = buffer_size
        self._queue = deque()
        self._readers = WaiterQueue()
        self._writers = WaiterQueue()
        self._done = Event()
        self._closed = False

    @property
    def _loop(self):
        loop = get_running_loop()
        if '_loop' not in self.__dict__ and self.__dict__.setdefault('_loop', loop) is not loop:
            raise RuntimeError(f'{self!r} is bound to a different event loop')
        return loop

    def send_nowait(self, value):
        if self._closed:
            raise exceptions.ClosedResourceError
        assert not self._readers or len(self._queue) == 0
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

    async def send(self, value):
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

    def receive_nowait(self):
        assert not self._writers or len(self._queue) == self._buffer_size
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
        else:
            if self._queue:
                return self._queue.popleft()
            raise exceptions.WouldBlock

    async def receive(self):
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

    def close(self):
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

    def __await__(self):
        # use yield from to avoid returning True from _done.wait().__await__()
        yield from self._done.wait().__await__()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, exc_traceback):
        self.close()
        await self._done.wait()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except exceptions.EndOfChannel:
            raise StopAsyncIteration
