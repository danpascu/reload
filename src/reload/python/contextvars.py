# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from collections.abc import Callable
from contextvars import ContextVar, copy_context
from functools import wraps

__all__ = 'run_in_context',  # noqa: COM818


def run_in_context[T, **P](*, sentinel: ContextVar[bool]) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Run the decorated function in a contextvars context.

    The context is created on entry and is active until the function returns.
    All functions called from the decorated function will run in the context.
    If the decorated function is recursive or calls to other functions decorated
    with the same decorator and using the same sentinel they'll find the context
    active and will directly execute their code without re-creating the context.
    """

    def decorate_function(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kw: P.kwargs) -> T:
            if sentinel.get(False):
                return func(*args, **kw)
            context = copy_context()
            context.run(sentinel.set, True)  # noqa: FBT003
            return context.run(func, *args, **kw)

        return wrapper

    return decorate_function
