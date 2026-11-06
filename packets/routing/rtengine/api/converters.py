# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""URL converters for the things routing configuration is keyed by.

A prefix has a ``/`` in it. That is the whole problem with this API's URLs
and the reason this module exists: Werkzeug's default converter stops at a
slash, so ``/network/192.0.2.0/24`` would route as two segments and a
``path`` converter would swallow the rest of the URL. A converter with an
explicit pattern matches exactly one prefix and nothing else, which keeps
``192.0.2.0/24`` and ``2001:db8::/32`` readable in a URL bar and in a curl
command -- and ``%2F`` still works, because a WSGI server has already decoded
it by the time routing sees the path.

**Keys are canonicalised on the way in.** ``parse_prefix`` is the same
function the configuration schema validates keys with, and the converter
returns its canonical rendering: ``2001:db8:0::/32`` and ``2001:db8::/32``
are the same destination, and a client that wrote one and then read back the
other would conclude its change had not applied.

**A malformed key is a 400, not a 404 (A-4).** A value the pattern admits
but ``parse_prefix`` refuses -- ``192.0.2.300/24``, ``10.0.0.0/33``, an AS
number of 0 -- raises ``BadRequest`` with the reason. It used to raise
``ValidationError``, which tells Werkzeug to try the next rule and, with
none left, answer 404 -- "no such neighbour" to a client that typed an
address that cannot exist, which sends them looking in the configuration
for something they will not find. Werkzeug lets any ``HTTPException`` out
of a converter, and Flask holds a routing error until after the
``before_request`` hooks, so the authentication check still runs first and
an unauthenticated caller learns nothing from the difference. It is safe
only because no two rules put converters at the same position, so there
is never another rule this one should have fallen through to; the
converter tests pin that.
"""

from werkzeug.exceptions import BadRequest
from werkzeug.routing import BaseConverter

from packets.routing.rtengine.rib.prefix import parse_prefix


class PrefixConverter(BaseConverter):
    """Matches ``192.0.2.0/24`` or ``2001:db8::/32`` as one URL segment."""

    # Hex digits, dots and colons, then a length. Deliberately loose:
    # parse_prefix is the authority on what is actually an address, and
    # duplicating its grammar in a regex would give two answers to one
    # question. The regex only has to be tight enough not to swallow
    # neighbouring path segments.
    regex = r'[0-9A-Fa-f:.]+/[0-9]{1,3}'

    def to_python(self, value):
        try:
            return parse_prefix(value).to_str()
        except ValueError as exc:
            # parse_prefix's message already names the value and the fault.
            raise BadRequest(str(exc))

    def to_url(self, value):
        # Returned verbatim rather than percent-encoded: the slash is the
        # point of this converter, and encoding it would produce a URL
        # that no longer matches the rule that generated it.
        return str(value)


class AddrConverter(BaseConverter):
    """Matches a bare IPv4 or IPv6 address -- a neighbour's address."""

    regex = r'[0-9A-Fa-f:.]+'

    def to_python(self, value):
        try:
            parsed = parse_prefix(value)
        except ValueError as exc:
            raise BadRequest(str(exc))
        if not parsed.is_host:
            raise BadRequest('%r is not a valid address' % (value,))
        return parsed.to_str().split('/')[0]

    def to_url(self, value):
        return str(value)


class AsnConverter(BaseConverter):
    """Matches an AS number, and keeps it a string.

    The configuration document keys ``router bgp`` by AS number, and JSON
    object keys are strings, so ``65000`` and ``'65000'`` are two
    different keys in the only place it matters. Converting to ``int``
    here -- which the built-in ``int`` converter would do -- would make
    every lookup in this API miss.
    """

    # Any run of digits, so that one too long to be an AS number reaches
    # the range check and is a 400 like any other out-of-range value.
    regex = r'[0-9]+'

    def to_python(self, value):
        asn = int(value)
        if asn < 1 or asn > 4294967295:
            raise BadRequest('%r is not an AS number (1..4294967295)'
                             % (value,))
        return str(asn)

    def to_url(self, value):
        return str(value)


#: Registered on every application built by ``app.create_app``.
CONVERTERS = {
    'prefix': PrefixConverter,
    'addr': AddrConverter,
    'asn': AsnConverter,
}


def match_key(section, wanted):
    """Find the key in a configuration section that names the same thing.

    The converter canonicalises what arrived in the URL, but a document
    loaded from a file may hold a key spelled another way -- the schema
    accepts any spelling ``parse_prefix`` accepts. Comparing canonical
    forms means ``DELETE /network/2001:db8:0::/32`` removes the entry
    stored as ``2001:db8::/32`` instead of reporting that it does not
    exist while the operator is looking straight at it.

    :param section: the dict to search, or None.
    :param wanted: the canonical key from the URL.
    :return: the key as stored, or ``wanted`` when there is no match.
    """
    if not isinstance(section, dict) or wanted in section:
        return wanted
    for key in section:
        try:
            candidate = parse_prefix(key).to_str()
        except (ValueError, TypeError):
            continue
        if candidate == wanted or candidate.split('/')[0] == wanted:
            return key
    return wanted
