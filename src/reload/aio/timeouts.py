# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio


__all__ = 'timeout',


if hasattr(asyncio, 'timeout'):
    timeout = asyncio.timeout
else:
    class Timeout:
        def __init__(self, delay: 'float | None'):
            self._delay = delay
            self._expired = False
            self._timed_task = None
            self._timer_task = None

        async def __aenter__(self):
            assert self._timer_task is None
            self._expired = False
            self._timed_task = asyncio.current_task()
            self._timer_task = asyncio.create_task(self._timeout_handler())
            return self

        async def __aexit__(self, exc_type, exc_value, exc_traceback):
            self._timer_task.cancel()
            self._timer_task = None
            self._timed_task = None
            if exc_type is asyncio.CancelledError and self._expired:
                raise asyncio.TimeoutError from exc_value

        # noinspection PyProtectedMember
        async def _timeout_handler(self):
            if self._delay is not None and self._timed_task is not None:
                await asyncio.sleep(self._delay)
                assert self._timed_task._fut_waiter is not None
                if not self._timed_task._fut_waiter.cancelled():
                    self._expired = True
                    self._timed_task.cancel()

    timeout = Timeout
