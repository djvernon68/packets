# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""TCP-MD5, TCP-AO and GTSM, packed by hand and probed at runtime.

Three RFCs meet in this module and all three are enforced by the kernel, not
by us: TCP-MD5 (RFC 2385), TCP-AO (RFC 5925) and the Generalized TTL
Security Mechanism (RFC 5082). Every one of them is a ``setsockopt`` that
must be in place *before* the handshake it protects, so this module is only
ever called from :mod:`packets.routing.rtengine.transport.tcp`, before a
connect and before an accept.

**Why the structs are hand-packed.** ``struct tcp_md5sig`` and
``struct tcp_ao_add`` are uapi types. Python's ``socket`` module has never
wrapped them, and the build hosts (CentOS 8) do not carry a kernel-headers
package new enough to describe TCP-AO at all, so there is nothing to read
them out of and no C shim we are willing to add to a pure-Python leaf of the
engine. The layouts are therefore written out here as ``struct`` format
strings with the byte offsets spelled out in comments, which has one real
consequence worth stating plainly: **if a layout is wrong, the kernel reads
a key from the wrong offset and the session fails to authenticate**, which
looks like a peer problem and is not. That risk is the reason the AO path is
gated behind :func:`ao_supported` and the reason the offsets below are
commented field by field rather than left as a bare format string.

**Why every constant is probed rather than imported.** The option numbers
are Linux ABI values. The development host is macOS, where option 14 on
``IPPROTO_TCP`` is simply unassigned and option 21 on ``IPPROTO_IP`` is
``IP_IPSEC_POLICY`` -- a different option that takes a different argument.
So a missing option is not the only failure mode; a *colliding* option is.
Both probes below therefore prove the option behaves the way the Linux one
behaves rather than settling for "``setsockopt`` returned zero":
:func:`md5_supported` requires a short buffer to be rejected, and
:func:`gtsm_inbound_supported` requires the value it set to read back. The
probes are cached because they cost a socket each and the answer cannot
change inside one process.

**Why the policy lives here.** :func:`resolve_auth` is the most important
function in the file, and it is here rather than in the FSM because it is a
security decision, not a state-machine step. It is deliberately
**fail-closed**: a peer configured for AO on a kernel without AO does not
quietly fall back to MD5 and it does not quietly come up unauthenticated. It
stays Idle with the reason ``ao-unsupported``, visible in
``show ip bgp neighbors`` and as ``degraded`` in health. MD5 is substituted
for AO in exactly one case -- ``ao.fallback-md5`` explicitly true *and* a
``password`` actually configured -- because that is an operator asking for
the downgrade in writing. Even then it is logged at WARNING and reported as
``md5 (ao-fallback)``, because a session that an operator believes is
AO-protected while it is really carrying a 1998 keyed MD5 digest is a
security regression, and the only thing worse than the downgrade is the
downgrade being invisible.
"""

import errno
import ipaddress
import logging
import socket
import struct

_log = logging.getLogger('packets.rtengine.transport.auth')

__all__ = ['TCP_MD5SIG', 'TCP_MD5SIG_EXT', 'TCP_MD5SIG_MAXKEYLEN',
           'TCP_MD5SIG_FLAG_PREFIX', 'TCP_AO_ADD_KEY', 'TCP_AO_DEL_KEY',
           'TCP_AO_INFO', 'TCP_AO_GET_KEYS', 'TCP_AO_REPAIR',
           'TCP_AO_MAXKEYLEN', 'IP_MINTTL', 'IPV6_MINHOPCOUNT',
           'AUTH_NONE', 'AUTH_MD5', 'AUTH_AO', 'AUTH_MD5_AO_FALLBACK',
           'AUTH_MODES', 'REASON_MD5_UNSUPPORTED', 'REASON_AO_UNSUPPORTED',
           'REASON_AO_FALLBACK', 'GTSM_TTL', 'AO_ALG_CMAC_AES_128',
           'AO_ALG_HMAC_SHA1', 'pack_sockaddr_storage', 'pack_md5sig',
           'set_md5', 'clear_md5', 'md5_supported', 'pack_ao_add',
           'pack_ao_del', 'set_ao', 'del_ao', 'ao_supported',
           'resolve_auth', 'gtsm_inbound_supported', 'set_gtsm', 'set_ttl',
           'reset_probe_cache']

# --- kernel ABI numbers -----------------------------------------------------
#
# From include/uapi/linux/tcp.h. Written out rather than imported because
# there is nothing to import them from: CPython's socket module does not
# define any of them on any platform, and the build hosts lack the uapi
# headers. Whether the running kernel implements them is a separate
# question, answered by md5_supported()/ao_supported() and never assumed.

TCP_MD5SIG = 14                  # setsockopt: install/remove an MD5 key
TCP_MD5SIG_EXT = 32              # as above, with tcpm_flags honoured
TCP_MD5SIG_MAXKEYLEN = 80        # sizeof(tcpm_key)
TCP_MD5SIG_FLAG_PREFIX = 1       # tcpm_prefixlen applies (needs _EXT)

TCP_AO_ADD_KEY = 38              # setsockopt(struct tcp_ao_add)
TCP_AO_DEL_KEY = 39              # setsockopt(struct tcp_ao_del)
TCP_AO_INFO = 40                 # get/setsockopt(struct tcp_ao_info_opt)
TCP_AO_GET_KEYS = 41             # getsockopt(struct tcp_ao_getsockopt)
TCP_AO_REPAIR = 42               # get/setsockopt, TCP_REPAIR of AO state
TCP_AO_MAXKEYLEN = 80            # sizeof(key)
TCP_AO_ALG_NAMELEN = 64          # sizeof(alg_name)

# GTSM (RFC 5082) inbound options. The numeric values are Linux; note that
# they are *not* portable numbers -- 21 is IP_IPSEC_POLICY on Darwin and
# IP_MINTTL is 66 on FreeBSD -- which is precisely why
# gtsm_inbound_supported() verifies behaviour instead of trusting the
# number. The getattr() keeps us honest if a future CPython does export
# them.
IP_MINTTL = getattr(socket, 'IP_MINTTL', 21)
IPV6_MINHOPCOUNT = getattr(socket, 'IPV6_MINHOPCOUNT', 73)

#: The TTL/hop-limit GTSM sends with, per RFC 5082: the maximum, so that a
#: packet which has crossed even one unexpected router arrives below the
#: receiver's minimum and is dropped by the kernel.
GTSM_TTL = 255

# sizeof(struct __kernel_sockaddr_storage). Fixed by the ABI at 128 bytes on
# every Linux architecture, which is what makes the offsets below constant.
SOCKADDR_STORAGE_LEN = 128

SIZEOF_TCP_MD5SIG = 216
SIZEOF_TCP_AO_ADD = 288
SIZEOF_TCP_AO_DEL = 144

# --- auth modes and reasons -------------------------------------------------
#
# Strings, not an enum, for the same reason the event names in events.py are
# strings: they are rendered verbatim by `show ip bgp neighbors` and by the
# REST layer, and a caller comparing against 'md5' should not have to import
# a symbol to do it. AUTH_MD5_AO_FALLBACK is the displayed form of the
# downgrade and is intentionally not a bare 'md5': the operator has to be
# able to tell, at a glance, that this session is not the AO they asked for.

AUTH_NONE = 'none'
AUTH_MD5 = 'md5'
AUTH_AO = 'ao'
AUTH_MD5_AO_FALLBACK = 'md5 (ao-fallback)'

AUTH_MODES = (AUTH_NONE, AUTH_MD5, AUTH_AO, AUTH_MD5_AO_FALLBACK)

#: A password is configured but the kernel has no TCP-MD5. Peer stays Idle.
REASON_MD5_UNSUPPORTED = 'md5-unsupported'
#: AO is configured but the kernel has no TCP-AO, and no sanctioned
#: fallback exists. Peer stays Idle. This is the fail-closed rule.
REASON_AO_UNSUPPORTED = 'ao-unsupported'
#: AO was configured, is unavailable, and the operator sanctioned MD5.
REASON_AO_FALLBACK = 'ao-fallback'

#: RFC 5926 algorithms, spelled the way the Linux crypto API names them.
#: The config vocabulary uses the RFC-ish spelling; _ao_alg_name() maps one
#: to the other so a configuration file never has to contain "cmac(aes128)".
AO_ALG_CMAC_AES_128 = 'cmac(aes128)'
AO_ALG_HMAC_SHA1 = 'hmac(sha1)'

_AO_ALG_ALIASES = {
    'cmac-aes-128': AO_ALG_CMAC_AES_128,
    'aes-128-cmac-96': AO_ALG_CMAC_AES_128,
    'cmac(aes128)': AO_ALG_CMAC_AES_128,
    'hmac-sha-1-96': AO_ALG_HMAC_SHA1,
    'hmac-sha1': AO_ALG_HMAC_SHA1,
    'hmac(sha1)': AO_ALG_HMAC_SHA1,
}

#: Default AO algorithm. RFC 5926 makes AES-128-CMAC-96 mandatory and it is
#: the cheaper of the two on the kernels that have AO at all.
AO_ALG_DEFAULT = 'cmac-aes-128'

# errnos that mean "this kernel does not implement the option", as opposed
# to "the option exists and you called it wrongly". EINVAL is in the set
# because a platform that reuses the number for something else usually
# rejects our argument with EINVAL rather than ENOPROTOOPT -- macOS does
# exactly that for IP option 21.
_UNSUPPORTED = frozenset([
    getattr(errno, 'ENOPROTOOPT', 92),
    getattr(errno, 'EOPNOTSUPP', 95),
    getattr(errno, 'ENOTSUP', 95),
    getattr(errno, 'EINVAL', 22),
    getattr(errno, 'EAFNOSUPPORT', 97),
    getattr(errno, 'ENOSYS', 38),
])

_md5_probe = None
_ao_probe = None
_gtsm_probe = {}


def reset_probe_cache():
    """Forget every cached capability probe.

    Test support only. The answers cannot change within the lifetime of a
    process, so production code never needs this; a test that wants to
    exercise both the supported and unsupported branch of a caller does.
    """
    global _md5_probe, _ao_probe
    _md5_probe = None
    _ao_probe = None
    _gtsm_probe.clear()


# --- address packing --------------------------------------------------------


def _as_text(value):
    """Return ``value`` as text, accepting bytes from a config decoder."""
    if isinstance(value, bytes):
        return value.decode('ascii')
    return value


def _zone_index(zone):
    """Translate an IPv6 zone ('en0', '3') to an interface index.

    A link-local neighbor address is meaningless without its zone, and the
    kernel wants the numeric index in ``sin6_scope_id``. A name we cannot
    translate yields 0 rather than an exception: the caller is packing a key
    for an address the configuration already accepted, and failing the whole
    session because an interface has since been renamed would turn a
    cosmetic problem into an outage. A zero scope simply means the kernel
    matches the key without one.

    :param zone: the text after ``%`` in an address.
    :return: an interface index, or 0 when it cannot be determined.
    """
    if zone.isdigit():
        return int(zone)
    getter = getattr(socket, 'if_nametoindex', None)
    if getter is None:
        return 0
    try:
        return getter(zone)
    except (OSError, ValueError):
        return 0


def parse_addr(addr):
    """Split an address string into family, wire bytes and IPv6 scope.

    ``ipaddress`` does the parsing rather than ``inet_pton`` because it
    rejects the ambiguous forms ``inet_pton`` accepts on some libcs
    (``10.1`` for instance) and because the engine already uses it in
    ``config.py``, so an address that validated at config time parses the
    same way here. The zone is stripped first: ``ip_address`` only learned
    to accept ``fe80::1%en0`` in 3.9 and the floor is 3.6.

    :param addr: an IPv4 or IPv6 address as text, optionally with ``%zone``.
    :return: ``(family, packed_bytes, scope_id)``.
    :raises ValueError: the address is not a bare IPv4/IPv6 address.
    """
    text = _as_text(addr).strip()
    scope = 0
    if '%' in text:
        text, _, zone = text.partition('%')
        scope = _zone_index(zone)
    ip = ipaddress.ip_address(text)
    if ip.version == 4:
        return socket.AF_INET, ip.packed, 0
    return socket.AF_INET6, ip.packed, scope


def pack_sockaddr_storage(addr, port):
    """Pack ``struct __kernel_sockaddr_storage`` for an address and port.

    The kernel takes the peer of a key as a 128-byte sockaddr_storage in
    every one of the options here, so this is written once. Two byte orders
    coexist inside those 128 bytes and getting them the wrong way round is
    the classic way to install a key the kernel never matches:

    * ``ss_family`` is an ``unsigned short`` in **host** order, because it
      is a kernel enum and never travels on a wire;
    * ``sin_port``/``sin6_port`` are in **network** order, because they do.

    Layout for AF_INET (``struct sockaddr_in``, padded to 128)::

        0   u16  sin_family      host order
        2   u16  sin_port        network order
        4   u32  sin_addr        network order (4 address bytes)
        8        sin_zero[8] and storage padding, zero

    Layout for AF_INET6 (``struct sockaddr_in6``, padded to 128)::

        0   u16  sin6_family     host order
        2   u16  sin6_port       network order
        4   u32  sin6_flowinfo   zero; irrelevant to key matching
        8        sin6_addr[16]   network order
        24  u32  sin6_scope_id   host order; link-local interface index
        28       storage padding, zero

    :param addr: peer address as text, optionally with an IPv6 ``%zone``.
    :param port: TCP port, 0 to match any.
    :return: exactly 128 bytes.
    :raises ValueError: the address does not parse.
    """
    family, packed, scope = parse_addr(addr)
    buf = bytearray(SOCKADDR_STORAGE_LEN)
    # '=' is native byte order with standard sizes: no alignment padding is
    # inserted, which matters because these offsets are absolute.
    struct.pack_into('=H', buf, 0, family)
    struct.pack_into('!H', buf, 2, int(port) & 0xffff)
    if family == socket.AF_INET:
        buf[4:8] = packed
    else:
        buf[8:24] = packed
        struct.pack_into('=I', buf, 24, scope)
    return bytes(buf)


def _key_bytes(key, maxlen, what):
    """Normalise a key to bytes and refuse one the struct cannot hold.

    A key is text in the configuration and bytes to the kernel. UTF-8 is
    the encoding because the configuration document is JSON and round-trips
    through it; an IOS password is ASCII in practice, and ASCII is a subset,
    so nothing changes for the normal case.

    :param key: the key as text or bytes; None or empty means no key.
    :param maxlen: the field width in the kernel struct.
    :param what: label for the error message.
    :return: the key as bytes, possibly empty.
    :raises ValueError: the key is longer than the struct allows.
    """
    if key is None:
        return b''
    if not isinstance(key, bytes):
        key = _as_text(key).encode('utf-8')
    if len(key) > maxlen:
        # Truncating would be worse than failing: both ends would compute a
        # digest over different key material and the session would fail to
        # come up with no indication of why.
        raise ValueError('%s is %d bytes; the kernel field holds %d'
                         % (what, len(key), maxlen))
    return key


# --- TCP-MD5 (RFC 2385) -----------------------------------------------------


def pack_md5sig(addr, port, key, prefixlen=None):
    """Pack ``struct tcp_md5sig`` for one peer key.

    216 bytes on every Linux architecture, and the size is load-bearing:
    the kernel rejects anything shorter with EINVAL, which is what makes the
    short-buffer half of :func:`md5_supported` a valid test.

    Layout (include/uapi/linux/tcp.h)::

        0    struct __kernel_sockaddr_storage tcpm_addr   128 bytes
        128  __u8   tcpm_flags        TCP_MD5SIG_FLAG_PREFIX or 0
        129  __u8   tcpm_prefixlen    only read when the flag is set
        130  __u16  tcpm_keylen       host order
        132  __u32  __tcpm_pad        must be zero
        136  __u8   tcpm_key[80]      key material, trailing bytes zero
        216  end

    The tail is packed with ``'=BBHI'``: native order, standard sizes, no
    alignment padding inserted. Every field there happens to be naturally
    aligned at these offsets anyway, so ``'='`` and the C compiler agree.

    :param addr: peer address as text; IPv4 or IPv6.
    :param port: peer TCP port, or 0 to match the address regardless of
        port. BGP always has a port on one side and not the other, so both
        forms get used.
    :param key: the shared password, text or bytes; empty removes the key.
    :param prefixlen: install the key for a whole prefix rather than one
        address. Requires ``TCP_MD5SIG_EXT`` and sets
        ``TCP_MD5SIG_FLAG_PREFIX``; left None for ordinary per-neighbor
        keys, which is every key BGP installs today.
    :return: a 216-byte buffer ready for ``setsockopt``.
    :raises ValueError: the address does not parse, or the key is too long.
    """
    material = _key_bytes(key, TCP_MD5SIG_MAXKEYLEN, 'the MD5 password')
    flags = 0
    plen = 0
    if prefixlen is not None:
        flags = TCP_MD5SIG_FLAG_PREFIX
        plen = int(prefixlen)
    buf = bytearray(SIZEOF_TCP_MD5SIG)
    buf[0:SOCKADDR_STORAGE_LEN] = pack_sockaddr_storage(addr, port)
    struct.pack_into('=BBHI', buf, SOCKADDR_STORAGE_LEN,
                     flags, plen, len(material), 0)
    buf[136:136 + len(material)] = material
    return bytes(buf)


def set_md5(sock, addr, port, key):
    """Install a TCP-MD5 key for one peer on a socket.

    Must be called **before** the socket connects or accepts. The kernel
    signs the SYN itself, so a key installed afterwards signs nothing that
    matters and the handshake fails with no MD5 option on the wire.

    :param sock: the socket to install on; unconnected, or a listener.
    :param addr: peer address as text.
    :param port: peer port, or 0 for any.
    :param key: the shared password.
    :return: None.
    :raises OSError: the kernel refused it -- ENOPROTOOPT when TCP-MD5 is
        not compiled in, ENOMEM when the key table is full.
    :raises ValueError: the address or key is unusable.
    """
    blob = pack_md5sig(addr, port, key)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, blob)


def clear_md5(sock, addr, port):
    """Remove the TCP-MD5 key for one peer.

    A zero-length key is how the kernel is told to delete an entry; there
    is no separate remove option. That is worth knowing because it means
    removing a key and installing an empty one are the same call, and so
    "authenticate this peer with an empty password" is not expressible --
    which is why ``config.py`` rejects an empty password outright.

    :param sock: the socket holding the key, typically the listener.
    :param addr: peer address as text.
    :param port: peer port, or 0 for any.
    :return: None.
    :raises OSError: the kernel refused it. ENOENT means there was no such
        key, which a caller removing a peer can usually ignore.
    """
    blob = pack_md5sig(addr, port, b'')
    sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, blob)


def md5_supported():
    """Report whether this kernel implements TCP-MD5, by trying it.

    The probe is a throwaway socket and a dummy key for 127.0.0.1, which
    touches nothing and is discarded with the socket. Two calls are made,
    not one, and both results matter:

    * a correctly sized buffer must be **accepted**;
    * a four-byte buffer must be **rejected**, because Linux checks
      ``optlen < sizeof(struct tcp_md5sig)`` before it looks at anything
      else.

    The second call is what distinguishes TCP-MD5 from some other option
    that happens to live at number 14 on a platform we have not seen. A
    platform that accepts both is not implementing TCP-MD5 and is reported
    unsupported. On macOS both calls fail with ENOPROTOOPT and the answer
    is False with nothing raised, which is required: the engine imports and
    runs on the development host, it just cannot authenticate there.

    :return: True when TCP-MD5 keys can be installed.
    """
    global _md5_probe
    if _md5_probe is None:
        _md5_probe = _probe_md5()
        _log.debug('TCP-MD5 support probed: %s', _md5_probe)
    return _md5_probe


def _probe_md5():
    """Run the two-call TCP-MD5 probe once. See :func:`md5_supported`."""
    try:
        blob = pack_md5sig('127.0.0.1', 179, b'probe')
    except (ValueError, struct.error):
        return False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, blob)
        except OSError as exc:
            if exc.errno not in _UNSUPPORTED:
                # The option exists and refused this particular key --
                # ENOMEM on a full key table, EPERM in a restricted
                # container. Reporting "unsupported" for that would send
                # every authenticated peer to Idle for a reason that has
                # nothing to do with the kernel's capabilities.
                _log.debug('TCP_MD5SIG probe failed with errno %s; the '
                           'option is present, so MD5 is supported',
                           exc.errno)
                return True
            return False
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, b'\x00' * 4)
        except OSError:
            return True
        _log.debug('TCP_MD5SIG accepted a 4-byte argument; option %d is '
                   'not TCP-MD5 on this platform', TCP_MD5SIG)
        return False
    except (OSError, AttributeError, OverflowError):
        # AttributeError covers a socket object without setsockopt at all,
        # which only a test double produces, but the contract says this
        # function does not raise.
        return False
    finally:
        if sock is not None:
            sock.close()


# --- TCP-AO (RFC 5925) ------------------------------------------------------


def _ao_alg_name(alg):
    """Map a configured algorithm name to a Linux crypto API name.

    The configuration says ``cmac-aes-128``; the kernel wants
    ``cmac(aes128)`` and copies the string straight into a crypto lookup.
    An unrecognised name is passed through unchanged rather than rejected,
    so a kernel that grows a new algorithm can be used without this module
    being edited -- the kernel will return ENOENT if it cannot find it.

    :param alg: the configured name.
    :return: the name to put in ``alg_name[64]``.
    """
    if alg is None:
        alg = AO_ALG_DEFAULT
    text = _as_text(alg).strip()
    return _AO_ALG_ALIASES.get(text.lower(), text)


def pack_ao_add(addr, port, send_id, recv_id, key, alg=AO_ALG_DEFAULT,
                ifindex=0, prefixlen=None, maclen=0, set_current=False,
                set_rnext=False, keyflags=0):
    """Pack ``struct tcp_ao_add`` for ``setsockopt(TCP_AO_ADD_KEY)``.

    288 bytes. Layout as taken from the RFC 5925 Linux uapi
    (include/uapi/linux/tcp.h, ``struct tcp_ao_add``)::

        0    struct __kernel_sockaddr_storage addr     128 bytes
        128  char   alg_name[64]    NUL-padded crypto API name
        192  __s32  ifindex         L3 device index, for VRF; 0 for none
        196  __u32  bitfield        bit 0 set_current, bit 1 set_rnext,
                                    bits 2..31 reserved, must be zero
        200  __u16  reserved2       must be zero
        202  __u8   prefix          address prefix length
        203  __u8   sndid           SendID for outgoing segments
        204  __u8   rcvid           RecvID matched on incoming segments
        205  __u8   maclen          MAC length; 0 means the kernel default
        206  __u8   keyflags        TCP_AO_KEYF_*
        207  __u8   keylen          length of key
        208  __u8   key[80]         key material
        288  end

    **This layout is version-sensitive and it is the weakest thing in this
    module.** TCP-AO landed in Linux 6.7 and the structure carries reserved
    fields and a bitfield, and a bitfield's bit order is a property of the
    compiler and the endianness, not of the ABI document: bit 0 is the
    least significant bit on gcc/clang for little-endian targets, which is
    every target this engine is built for. If the structure is ever
    re-ordered upstream, this packing silently addresses the wrong bytes.
    That is exactly why :func:`ao_supported` gates every use of it and why
    :func:`resolve_auth` treats an unavailable AO as a reason to stay Idle
    rather than something to work around.

    :param addr: peer address as text.
    :param port: peer port, or 0 to match any.
    :param send_id: SendID, 0..255, from the key chain.
    :param recv_id: RecvID, 0..255, from the key chain.
    :param key: the master key, text or bytes, up to 80 bytes.
    :param alg: RFC 5926 algorithm; accepts ``cmac-aes-128`` or the
        kernel's own ``cmac(aes128)`` spelling.
    :param ifindex: L3 device index when the peer is in a VRF.
    :param prefixlen: prefix length for the key's address match; defaults
        to a host route (32 or 128), which is what a BGP neighbor is.
    :param maclen: truncated MAC length, or 0 for the kernel default of 12
        octets (RFC 5926's 96-bit MACs).
    :param set_current: make this the Current_key immediately.
    :param set_rnext: ask the peer for this key via RNextKeyID.
    :param keyflags: ``TCP_AO_KEYF_*`` bits, passed through.
    :return: a 288-byte buffer.
    :raises ValueError: an id is out of range, the address does not parse,
        the key or the algorithm name does not fit.
    """
    family, _packed, _scope = parse_addr(addr)
    material = _key_bytes(key, TCP_AO_MAXKEYLEN, 'the AO key')
    name = _ao_alg_name(alg).encode('ascii')
    if len(name) >= TCP_AO_ALG_NAMELEN:
        raise ValueError('AO algorithm name %r does not fit in %d bytes'
                         % (name, TCP_AO_ALG_NAMELEN))
    for label, value in (('send_id', send_id), ('recv_id', recv_id),
                         ('maclen', maclen), ('keyflags', keyflags)):
        if not 0 <= int(value) <= 255:
            raise ValueError('%s must be 0..255, got %r' % (label, value))
    if prefixlen is None:
        prefixlen = 32 if family == socket.AF_INET else 128
    bits = 0
    if set_current:
        bits |= 1
    if set_rnext:
        bits |= 2

    buf = bytearray(SIZEOF_TCP_AO_ADD)
    buf[0:SOCKADDR_STORAGE_LEN] = pack_sockaddr_storage(addr, port)
    buf[128:128 + len(name)] = name
    struct.pack_into('=iIHBBBBBB', buf, 192, int(ifindex), bits, 0,
                     int(prefixlen), int(send_id), int(recv_id),
                     int(maclen), int(keyflags), len(material))
    buf[208:208 + len(material)] = material
    return bytes(buf)


def pack_ao_del(addr, port, send_id, recv_id, ifindex=0, prefixlen=None,
                keyflags=0):
    """Pack ``struct tcp_ao_del`` for ``setsockopt(TCP_AO_DEL_KEY)``.

    144 bytes, and a different structure from :func:`pack_ao_add` rather
    than the same one with a flag, which is easy to get wrong::

        0    struct __kernel_sockaddr_storage addr     128 bytes
        128  __s32  ifindex
        132  __u32  bitfield        bit 0 set_current, bit 1 set_rnext,
                                    bit 2 del_async, rest reserved
        136  __u16  reserved2       must be zero
        138  __u8   prefix
        139  __u8   sndid
        140  __u8   rcvid
        141  __u8   current_key     only read when set_current is set
        142  __u8   rnext           only read when set_rnext is set
        143  __u8   keyflags
        144  end

    The same version-sensitivity warning as :func:`pack_ao_add` applies.

    :param addr: peer address as text.
    :param port: peer port, or 0.
    :param send_id: SendID of the key to remove.
    :param recv_id: RecvID of the key to remove.
    :param ifindex: L3 device index, when the peer is in a VRF.
    :param prefixlen: prefix length the key was installed with.
    :param keyflags: ``TCP_AO_KEYF_*`` bits the key was installed with.
    :return: a 144-byte buffer.
    :raises ValueError: an id is out of range or the address does not parse.
    """
    family, _packed, _scope = parse_addr(addr)
    for label, value in (('send_id', send_id), ('recv_id', recv_id),
                         ('keyflags', keyflags)):
        if not 0 <= int(value) <= 255:
            raise ValueError('%s must be 0..255, got %r' % (label, value))
    if prefixlen is None:
        prefixlen = 32 if family == socket.AF_INET else 128
    buf = bytearray(SIZEOF_TCP_AO_DEL)
    buf[0:SOCKADDR_STORAGE_LEN] = pack_sockaddr_storage(addr, port)
    struct.pack_into('=iIHBBBBBB', buf, 128, int(ifindex), 0, 0,
                     int(prefixlen), int(send_id), int(recv_id), 0, 0,
                     int(keyflags))
    return bytes(buf)


def set_ao(sock, addr, port, send_id, recv_id, key, alg=AO_ALG_DEFAULT,
           ifindex=0, prefixlen=None, set_current=True, set_rnext=True):
    """Install a TCP-AO key for one peer on a socket.

    Same ordering rule as :func:`set_md5`, and for a stronger reason: AO
    authenticates the SYN and the SYN-ACK, so a key installed after the
    handshake begins protects nothing at all.

    ``set_current`` and ``set_rnext`` default to True because the v1
    configuration carries one active key per neighbor. A real key chain
    with overlapping keys installs the others with both False and rolls
    over by re-issuing the current one; the parameters exist so that
    arrives as a caller change rather than an edit here.

    :param sock: the socket to install on; unconnected, or a listener.
    :param addr: peer address as text.
    :param port: peer port, or 0 for any.
    :param send_id: SendID from the key chain.
    :param recv_id: RecvID from the key chain.
    :param key: the master key.
    :param alg: RFC 5926 algorithm name.
    :param ifindex: L3 device index for a VRF peer.
    :param prefixlen: prefix length for the match; defaults to a host route.
    :param set_current: make it the Current_key at once.
    :param set_rnext: request it from the peer with RNextKeyID.
    :return: None.
    :raises OSError: the kernel refused it. ENOPROTOOPT means no TCP-AO,
        ENOENT usually means the named algorithm is not available.
    :raises ValueError: an argument does not fit the struct.
    """
    blob = pack_ao_add(addr, port, send_id, recv_id, key, alg=alg,
                       ifindex=ifindex, prefixlen=prefixlen,
                       set_current=set_current, set_rnext=set_rnext)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_AO_ADD_KEY, blob)


def del_ao(sock, addr, port, send_id, recv_id, ifindex=0, prefixlen=None):
    """Remove a TCP-AO key for one peer.

    Unlike MD5 there is a real delete option, so this is not a zero-length
    add. The key is identified by its ids, not by its material.

    :param sock: the socket holding the key.
    :param addr: peer address as text.
    :param port: peer port, or 0.
    :param send_id: SendID of the key to remove.
    :param recv_id: RecvID of the key to remove.
    :param ifindex: L3 device index the key was installed with.
    :param prefixlen: prefix length the key was installed with.
    :return: None.
    :raises OSError: the kernel refused it; ENOENT means no such key.
    :raises ValueError: an argument does not fit the struct.
    """
    blob = pack_ao_del(addr, port, send_id, recv_id, ifindex=ifindex,
                       prefixlen=prefixlen)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_AO_DEL_KEY, blob)


def ao_supported():
    """Report whether this kernel implements TCP-AO, by asking it.

    ``getsockopt(TCP_AO_INFO)`` is the probe, and the interesting result is
    a failure: a fresh socket has no AO state, so a kernel that implements
    AO answers **ENOENT** -- "no AO on this socket" -- while a kernel that
    does not answers ENOPROTOOPT. ENOENT is therefore the positive signal,
    which is the opposite of the usual reading and the reason this is not a
    one-line ``try``. A success is also accepted, in case a future kernel
    returns default info for a bare socket.

    Anything else, including EINVAL, is read as unsupported. That is the
    fail-closed direction: the cost of a false negative is a peer that
    stays Idle with a clear reason, and the cost of a false positive is a
    hand-packed 288-byte struct handed to an option that means something
    else.

    :return: True when TCP-AO keys can be installed.
    """
    global _ao_probe
    if _ao_probe is None:
        _ao_probe = _probe_ao()
        _log.debug('TCP-AO support probed: %s', _ao_probe)
    return _ao_probe


def _probe_ao():
    """Run the TCP_AO_INFO probe once. See :func:`ao_supported`."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.getsockopt(socket.IPPROTO_TCP, TCP_AO_INFO, 64)
            return True
        except OSError as exc:
            # ENOENT is the positive answer -- the option exists and this
            # socket merely has no AO keys yet -- and so is anything else
            # that is not "no such option".
            return exc.errno not in _UNSUPPORTED
    except (OSError, AttributeError, OverflowError):
        return False
    finally:
        if sock is not None:
            sock.close()


# --- the policy -------------------------------------------------------------


def resolve_auth(neighbor_cfg, ao_available=None, md5_available=None):
    """Decide how one neighbor authenticates, or that it must not come up.

    This is the fail-closed policy, and the single place it is expressed.
    Callers hand in the IOS-shaped neighbor dictionary and get back a
    triple; a falsy mode is the signal that the peer must stay Idle, with
    the reason carried in the third element for
    ``show ip bgp neighbors`` and for health to report ``degraded``.

    The rules, in order:

    * neither ``ao`` nor ``password`` -- ``(AUTH_NONE, None, None)``. An
      unauthenticated session is a legitimate configuration and is not
      second-guessed here.
    * ``password`` only, MD5 available -- ``(AUTH_MD5, password, None)``.
    * ``password`` only, MD5 unavailable -- ``(None, None,
      'md5-unsupported')``. The operator asked for authentication and the
      kernel cannot provide it; bringing the session up in the clear would
      substitute our judgement for theirs on a security control.
    * ``ao`` and AO available -- ``(AUTH_AO, <key chain name>, None)``. The
      key chain is returned by name: the material lives in the key chain
      and is fetched by the caller, so an AO key never passes through this
      return value and cannot end up in a log line that formats it.
    * ``ao``, AO unavailable, and no sanctioned fallback -- ``(None, None,
      'ao-unsupported')``. This is the rule the whole function exists for.
      "Sanctioned" is narrow on purpose: ``fallback-md5`` must be exactly
      ``True`` (not 1, not ``'yes'``, not truthy) *and* a non-empty
      ``password`` must be configured. A truthy string in a hand-edited
      configuration must not be able to authorise a downgrade.
    * ``ao``, AO unavailable, ``fallback-md5`` true, ``password`` set --
      ``(AUTH_MD5_AO_FALLBACK, password, 'ao-fallback')``, logged at
      WARNING. The operator authorised this, but a session the operator
      believes is AO while it is really MD5 is a security regression, so it
      is loud in the log and distinct in the shown auth mode.

    Note that an MD5 fallback is *not* re-checked against
    :func:`md5_supported` being false separately: it is checked, and a
    kernel with neither AO nor MD5 reports ``ao-unsupported`` because that
    is the configuration the operator will look at first.

    :param neighbor_cfg: the neighbor's configuration dict. ``password``
        (str) and ``ao`` (dict with ``key-chain`` and ``fallback-md5``) are
        the keys read; everything else is ignored.
    :param ao_available: override the AO probe. None means probe. Tests and
        a future ``debug`` knob are the reason this is a parameter.
    :param md5_available: override the MD5 probe. None means probe.
    :return: ``(mode, key_material, reason)``. ``mode`` is one of
        ``AUTH_MODES`` or None; None means the peer stays Idle.
    """
    cfg = neighbor_cfg or {}
    password = cfg.get('password')
    if isinstance(password, bytes):
        password = password.decode('utf-8', 'replace')
    ao_cfg = cfg.get('ao')

    if not ao_cfg and not password:
        return AUTH_NONE, None, None

    if not ao_cfg:
        if md5_available is None:
            md5_available = md5_supported()
        if md5_available:
            return AUTH_MD5, password, None
        _log.warning('neighbor has a password configured but this kernel '
                     'has no TCP-MD5 support; the peer stays Idle with '
                     'reason %s rather than peering unauthenticated',
                     REASON_MD5_UNSUPPORTED)
        return None, None, REASON_MD5_UNSUPPORTED

    if ao_available is None:
        ao_available = ao_supported()
    if ao_available:
        key_chain = None
        if isinstance(ao_cfg, dict):
            key_chain = ao_cfg.get('key-chain')
        return AUTH_AO, key_chain, None

    fallback = False
    if isinstance(ao_cfg, dict):
        # `is True` and not truthiness: this comparison is the authorisation
        # check for a security downgrade, and the schema already guarantees
        # a bool for a document that came through it. A document that did
        # not is exactly the case this protects against.
        fallback = ao_cfg.get('fallback-md5') is True
    if not (fallback and password):
        _log.warning('neighbor is configured for TCP-AO but this kernel '
                     'has no TCP-AO support and no MD5 fallback is '
                     'authorised; the peer stays Idle with reason %s',
                     REASON_AO_UNSUPPORTED)
        return None, None, REASON_AO_UNSUPPORTED

    _log.warning('neighbor is configured for TCP-AO but this kernel has no '
                 'TCP-AO support; falling back to TCP-MD5 as authorised by '
                 'ao.fallback-md5. This is a downgrade: the session will be '
                 'protected by RFC 2385 keyed MD5, not RFC 5925 AO, and is '
                 'shown as %r', AUTH_MD5_AO_FALLBACK)
    return AUTH_MD5_AO_FALLBACK, password, REASON_AO_FALLBACK


# --- GTSM (RFC 5082) and plain multihop TTL ---------------------------------


def gtsm_inbound_supported(family):
    """Report whether inbound TTL enforcement is available, by trying it.

    GTSM has two halves and they are not equally portable. Sending with
    TTL 255 works everywhere; *requiring* a high TTL on receipt needs
    ``IP_MINTTL`` (IPv4) or ``IPV6_MINHOPCOUNT`` (IPv6, Linux 2.6.35 and
    later), and only the inbound half is the actual security control. A
    platform with only the outbound half gets no protection whatsoever
    from GTSM, so ``config.py`` rejects ``ttl-security`` at config time on
    such a platform rather than accepting it and quietly providing nothing.
    That rejection is only defensible if this function is honest, so the
    probe verifies behaviour rather than the option number:

    1. set the option to 1 on a throwaway socket;
    2. read it back and require the value to be 1.

    Step 2 is not paranoia. The Linux number for ``IP_MINTTL`` is 21, and
    21 on Darwin is ``IP_IPSEC_POLICY`` and 66 on FreeBSD is where
    ``IP_MINTTL`` actually lives -- a successful ``setsockopt`` on an
    unknown platform does not mean we set a minimum TTL.

    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :return: True when the inbound minimum can be enforced.
    """
    cached = _gtsm_probe.get(family)
    if cached is None:
        cached = _probe_gtsm_inbound(family)
        _gtsm_probe[family] = cached
        _log.debug('GTSM inbound support for family %s probed: %s',
                   family, cached)
    return cached


def _probe_gtsm_inbound(family):
    """Run the set-then-read-back GTSM probe once."""
    if family == socket.AF_INET:
        level, option = socket.IPPROTO_IP, IP_MINTTL
    elif family == socket.AF_INET6:
        level, option = socket.IPPROTO_IPV6, IPV6_MINHOPCOUNT
    else:
        return False
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(level, option, 1)
        return sock.getsockopt(level, option) == 1
    except (OSError, AttributeError, OverflowError):
        return False
    finally:
        if sock is not None:
            sock.close()


def set_gtsm(sock, family, hops):
    """Apply GTSM to a socket: send at 255, refuse anything lower inbound.

    RFC 5082 in two ``setsockopt`` calls, and both are needed. Sending with
    the maximum TTL is what lets the receiver's check work; requiring a
    minimum on receipt is what actually stops an off-path spoofer, because
    a packet injected from more than ``hops`` routers away cannot arrive
    with a TTL that high. Setting only the first half is the failure this
    engine refuses to ship: it looks configured and protects nothing.

    The threshold is ``255 - hops + 1``. For a directly connected peer
    (``hops`` 1) that is 255: the peer's packet arrives undecremented or
    not at all.

    :param sock: the socket to apply it to, before connect or accept.
    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :param hops: the number of hops the peer is permitted to be away,
        1..254.
    :return: the inbound minimum TTL that was set.
    :raises ValueError: ``hops`` is out of range or the family is unknown.
    :raises OSError: the platform has no inbound option. Callers are
        expected to have asked :func:`gtsm_inbound_supported` at config
        time, so reaching this is a bug rather than a configuration error.
    """
    hops = int(hops)
    if not 1 <= hops <= 254:
        raise ValueError('ttl-security hops must be 1..254, got %d' % hops)
    minimum = GTSM_TTL - hops + 1
    if family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, GTSM_TTL)
        sock.setsockopt(socket.IPPROTO_IP, IP_MINTTL, minimum)
    elif family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS,
                        GTSM_TTL)
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_MINHOPCOUNT, minimum)
    else:
        raise ValueError('unknown address family %r' % (family,))
    return minimum


def set_ttl(sock, family, ttl):
    """Set the outbound TTL or hop limit, for ``ebgp-multihop``.

    Multihop and GTSM are different features and this is the non-secure
    one: it raises the TTL so a session to a peer several hops away is not
    dropped in transit, and it checks nothing on receipt. An operator who
    wants the check wants :func:`set_gtsm`.

    :param sock: the socket, before connect or accept.
    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :param ttl: 1..255.
    :return: None.
    :raises ValueError: ``ttl`` is out of range or the family is unknown.
    :raises OSError: the kernel refused the option.
    """
    ttl = int(ttl)
    if not 1 <= ttl <= 255:
        raise ValueError('ttl must be 1..255, got %d' % ttl)
    if family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    elif family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        raise ValueError('unknown address family %r' % (family,))
