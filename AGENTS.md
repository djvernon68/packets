# Packets Development Guide

## Compatibility

- Keep the supported baseline compatible with Python 3.6.8 and Cython 0.28.1.
  Do not use newer Python syntax or newer Cython-only features in shipping code.
- Treat the public `PKT` constructors, fields, `query_info()`, `get_field_val()`,
  `pkt2net()`, and Layer-7 registration behavior as compatibility contracts.
- Rebuild from clean generated artifacts after changing a `.pxd` file. Cython
  declaration changes can alter extension layouts and vtables even when an
  incremental build appears successful.
- Never edit generated `.c` files as the source of a fix. Change the `.pyx` or
  `.pxd` input and regenerate it.

## Protocol Module Layout

A compiled protocol normally has matching files under `packets/protos`:

- `<protocol>.pxd` declares public constants, extension fields, and C-level
  methods used by the implementation.
- `<protocol>.pyx` contains public construction, parsing, serialization, query
  support, and explanatory comments.
- `setup.py` contains an `Extension` entry for the `.pyx` module.
- Focused tests belong under `test` and should include both direct protocol
  construction and parsing through an enclosing transport packet.

Use the existing modules as complementary examples:

- `dns.pyx` demonstrates variable-length names, message-relative offsets,
  compression pointers, and structured child records.
- `dhcp.pyx` demonstrates fixed headers, generic TLV records, marker options,
  unknown-value preservation, and IPv4/IPv6 variants.
- `http.pyx` demonstrates byte-oriented text parsing, ordered duplicate fields,
  message framing, dispatcher classes, and bytes left for a later stream
  message.

## Public Construction and Ownership

Follow the established constructor shape:

```cython
def __init__(self, *args, **kwargs):
    # One raw positional buffer parses wire data.
    # Field keywords construct a new packet.
    pass
```

- Accept immutable `bytes` without copying when safe.
- Copy `bytearray`, `array('B')`, writable memoryviews, and other mutable input
  once at the public ownership boundary. A parsed packet must not change when
  its caller later mutates the source.
- Any public byte field retained after parsing should be independently owned or
  should retain an immutable owner with an explicit range. A detached child
  must remain valid after its parent is released.
- Do not expose borrowed libpcap storage outside the callback/read operation
  that owns it.

## Efficient Owner/Offset Layer-7 Parsing

Transport parsing can avoid an intermediate payload copy when a protocol opts
in with this private class method:

```cython
@classmethod
def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                dict l7_ports):
    ...
```

The method should:

1. Validate `0 <= start <= end <= len(owner)`.
2. Allocate with `cls.__new__(cls)` and initialize the same base metadata and
   collections as `__init__`.
3. Retain the exact `l7_ports` mapping supplied by the caller.
4. Create one typed view of `owner`, take a zero-copy view slice for the message,
   and parse using message-relative offsets.
5. Retain or copy only data that must outlive parsing.

This hook is private and optional. Downstream protocols without it continue to
receive an owned payload copy. Register downstream classes by passing the
imported `PKT` subclass object in `l7_ports`; do not depend on dynamic imports.

## Parsing Rules

- Check every fixed header and declared variable-length region before calling
  unchecked helpers such as `rd_u16`, `rd_u32`, or direct memoryview indexing.
- Use `need_bytes` for fixed minimums and explicit range arithmetic for TLVs,
  records, strings, options, and nested sections.
- Perform range arithmetic with `Py_ssize_t`. Validate before narrowing to an
  8-, 16-, or 32-bit wire field.
- Parse a variable-length list in one forward pass. Avoid slicing an
  `array.array` at each child boundary because each slice allocates and copies.
- Preserve unknown types and values whenever the wire format permits it. A new
  protocol value should normally remain round-trippable rather than becoming a
  parse failure.
- Define malformed and incomplete input behavior explicitly. Tests should pin
  boundary cases so optimization does not accidentally make parsing permissive
  or unsafe.
- Keep protocol scope visible in comments. For example, a packet parser should
  not silently claim TCP reassembly, TLS decryption, or application-server
  behavior.

## Serialization Rules

- Implement one C-level `_write(PktWriter, kwargs)` route for each serializable
  class and let `pkt2net()` call `_serialize`.
- Append fields with `w_u8`, `w_u16`, `w_u32`, `w_bytes`, and related helpers.
  Do not build every field or layer as a temporary `bytes` object and join them.
- Nested classes should write into the caller's `PktWriter` rather than call a
  child `pkt2net()` and copy the complete intermediate result.
- Validate field widths and declared lengths before writing. Make update flags
  explicit when a length, count, or checksum may be recomputed.
- Preserve parsed wire details that are public or semantically significant.
  When exact preservation conflicts with an edited field, document and test the
  deterministic canonical form used for the rewrite.

## Query Integration

Every queryable `PKT` subclass should provide:

```cython
@classmethod
def query_info(cls):
    return 123, ('protocol.field', ...)

cpdef object get_field_val(self, str field):
    ...
```

- Advertise only stable scalar values that callers can retrieve safely.
- Return `None` for a field that does not apply to a particular packet shape.
- Keep field names namespaced by protocol.
- If the protocol has conventional transport ports, a `default_ports()` class
  method may return them for caller convenience. Registration remains explicit.

## Test Expectations

For a new parser, cover at least:

- keyword construction and serialization;
- parse/serialize round trips using independent wire fixtures;
- minimum-length and each declared-length truncation boundary;
- unknown type/value preservation;
- mutable-source isolation;
- detached-child lifetime;
- direct parsing and Ethernet/IP/UDP or Ethernet/IP/TCP Layer-7 parsing;
- source/destination port selection where relevant;
- every advertised query field;
- byte-identical output for unchanged parsed packets, when promised.

A bug fix should add a reproducer that fails before the fix and passes after it.
Do not weaken, skip, or delete existing assertions to obtain a green suite.
After focused tests pass, run the complete suite and the golden correctness
benchmark. Performance-sensitive changes should also compare repeated direct
and representative nested parser measurements; treat small differences as
noise until repeated samples show otherwise.

## Commenting Protocol Examples

Example modules should explain decisions rather than restate syntax. In
particular, document:

- the ownership boundary and lifetime model;
- why the public representation is bytes, strings, tuples, or child objects;
- every bounds check that protects an unchecked read;
- how unknown values and trailing bytes are preserved;
- why the writer avoids intermediate allocations;
- how Layer-7 owner/offset parsing differs from direct construction;
- deliberate exclusions and the layer responsible for them.

Keep comments generic and useful to downstream developers. Do not put private
hosts, credentials, deployment paths, workstation details, or organization-only
procedures in this repository guide.
