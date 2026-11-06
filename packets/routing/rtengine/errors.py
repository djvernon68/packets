# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Exceptions the engine raises deliberately.

These live in their own module, not in ``__init__``, so that ``engine.py``,
``config.py`` and the future API blueprints can import them without the
package ``__init__`` having to be half-initialised first. Every one of them
carries the fields the REST layer needs to build its uniform error body
(``{error, detail, path}``), so the translation in Stage 5 is a lookup rather
than a set of ``isinstance`` special cases.

The engine's own never-raise surfaces -- the RIB, the codec primitives -- do
not use these. They report by return value. These are for the control plane:
configuration, lifecycle and command submission, where an exception is the
honest answer and the caller is a human or an HTTP client.
"""

__all__ = ['RtEngineError', 'ConfigError', 'ConflictError', 'ApplyError',
           'UnavailableError', 'PreconditionFailed']


class RtEngineError(Exception):
    """Base class for every error the engine raises deliberately.

    ``error`` is the token the REST layer puts in the response body; each
    subclass sets it. ``detail`` is human readable, ``path`` is the config
    or resource path the failure applies to, or None.
    """

    error = 'Error'

    def __init__(self, detail, path=None):
        super(RtEngineError, self).__init__(detail)
        self.detail = detail
        self.path = path

    def as_dict(self):
        """Return the uniform error body for this exception."""
        return {'error': self.error, 'detail': self.detail, 'path': self.path}


class ConfigError(RtEngineError):
    """A configuration document, or a change to one, was rejected.

    Raised by schema validation and by a plugin's ``prepare_config``. The
    running configuration and its revision are untouched when this is
    raised: nothing has been committed yet.
    """

    error = 'Invalid'


class ConflictError(RtEngineError):
    """A change collided with existing state.

    The v1 single-``router bgp`` rule is the one that raises this today: a
    second ASN is a conflict, not an invalid document.
    """

    error = 'Conflict'


class ApplyError(RtEngineError):
    """A commit failed after at least one plugin had already committed.

    ``rolled_back`` says whether the inverse diff was delivered to the
    plugins that had already committed. Rollback is best effort by design:
    runtime side effects a plugin caused before failing (a reset session, a
    closed socket) are not undone, and the running configuration does not
    advance either way.
    """

    error = 'ApplyFailed'

    def __init__(self, detail, rolled_back=False, path=None):
        super(ApplyError, self).__init__(detail, path)
        self.rolled_back = rolled_back

    def as_dict(self):
        body = super(ApplyError, self).as_dict()
        body['rolled_back'] = self.rolled_back
        return body


class UnavailableError(RtEngineError):
    """The engine is not running, or is shutting down, so it cannot serve.

    Submitting work to a stopped engine raises this rather than blocking
    forever on a loop that will never run the callback.
    """

    error = 'Unavailable'


class PreconditionFailed(RtEngineError):
    """An ``if_revision`` guard did not match the running revision.

    Optimistic concurrency for configuration changes: the caller read
    revision N, someone else committed N+1, and the caller's change is
    refused rather than silently applied on top of state it never saw.
    """

    error = 'PreconditionFailed'

    def __init__(self, detail, expected=None, actual=None, path=None):
        super(PreconditionFailed, self).__init__(detail, path)
        self.expected = expected
        self.actual = actual

    def as_dict(self):
        body = super(PreconditionFailed, self).as_dict()
        body['expected'] = self.expected
        body['revision'] = self.actual
        return body
