# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


__all__ = 'UnknownKindError',  # noqa: COM818


class UnknownKindError(ValueError):
    """Raised when a message references a Kind that is not defined."""
