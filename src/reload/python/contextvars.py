# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from collections.abc import Callable, Mapping
from contextvars import ContextVar, Token, copy_context
from functools import wraps
from typing import Self

__all__ = 'ContextSpec', 'run_in_context', 'setup_context'


class ContextSpec[T]:
    context_vars: Mapping[ContextVar[T], T]
    reset_tokens: Mapping[ContextVar[T], Token[T]]

    def __init__(self, context_vars: Mapping[ContextVar[T], T]) -> None:
        self.context_vars = context_vars
        self.reset_tokens = {}

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}: {', '.join(f'{var.name}={value!r}' for var, value in self.context_vars.items())}'

    def __enter__(self) -> Self:
        self.setup()
        return self

    def __exit__(self, *_: object) -> None:
        self.reset()

    def setup(self) -> None:
        reset_tokens = {var: var.set(value) for var, value in self.context_vars.items()}
        if not self.reset_tokens:
            self.reset_tokens = reset_tokens

    def reset(self) -> None:
        if self.reset_tokens:
            for var, token in self.reset_tokens.items():
                var.reset(token)
            self.reset_tokens = {}


setup_context = ContextSpec


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
