# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


__all__ = 'WouldBlock', 'ResourceNotConnectedError', 'ClosedResourceError', 'BrokenResourceError', 'EndOfChannel'


class WouldBlock(Exception):
    """Raised by ``X_nowait`` functions if ``X`` would block."""


class ResourceNotConnectedError(Exception):
    """
    Raised when attempting to use a resource before it is connected.

    This applies to resources that need to be connected in order to operate,
    like for example a network connection.

    """


class ClosedResourceError(Exception):
    """
    Raised when attempting to use a resource after it has been closed.

    Note that "closed" here means that the resource was explicitly closed,
    generally by calling a method with a name like ``close`` or ``aclose``,
    or by exiting a context manager that calls one of those methods on exit.

    Problems caused by external circumstances, - like for example a network
    failure, or a remote peer that closed their end of a connection - should
    raise a different exception type, like :exc:`BrokenResourceError` or an
    :exc:`OSError` subclass.

    """


class BrokenResourceError(Exception):
    """
    Raised when attempting to use a resource fails due to external causes.

    For example, trying to send data on a stream where the remote side has
    already closed the connection.

    This *won't* be raised after the resource was closed explicitly, in that
    case the exception will be :exc:`ClosedResourceError`.

    This exception's ``__cause__`` attribute will often contain more
    information about the underlying error.

    """


class EndOfChannel(Exception):
    """
    Raised when trying to receive from an :class:`aio.Channel` that has no
    more data to receive.

    This is similar to the "end-of-file" condition, but for channels.

    """
