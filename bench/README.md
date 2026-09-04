# packets benchmark suite

Tools for producing credible, repeatable performance numbers for the `packets`
library, both **version-over-version** and **against other Python packet
libraries** (impacket, scapy, dpkt) with a **C-level libpcap ceiling** as the
floor.

All builds and timed runs must happen on one consistent machine, and every test
in a comparison must use the **same toolchain** — otherwise the numbers are not
comparable. You are free to choose the toolchain (e.g. to test against a newer
python such as python3.14), as long as you apply it uniformly across every test.
A Riverbed FlowGateway 10.32 (release 218) device ships with a compatible
toolchain out of the box — Cython 0.28.1, gcc 8.5, libpcap-devel 1.9.1,
python3.6 (and python3.11) plus dpkt, impacket, and scapy will easily install 
via pip on that platform — so it can be used largely **as is** to perform 
these tests. Editing can be done anywhere; timing on a laptop (or any machine 
unlike the one used for the rest of the comparison) is not comparable.

## What's here

| script | purpose |
| --- | --- |
| `microbench.py` | per-op micro-benchmarks of the library hot paths (construct/build/parse/serialize/access/query). `--json` for machine-diffable output. |
| `compare_libs.py` | cross-library comparison (packets vs impacket/scapy/dpkt) plus the libpcap ceiling, over a pcap and an optional NetFlow capture. |
| `pcap_dispatch_bench.pyx` + `setup_dispatch.py` | the libpcap C-level ceiling (`pcap_open_offline` + `pcap_dispatch`) that `compare_libs.py --libs libpcap` measures. |
| `make_corpus.py` | generate the reproducible frames, NetFlow v9, and full-L7 protocol captures the streaming benchmarks need. |
| `regression.py` | build a baseline git tag and the working tree in isolation and diff timings + behavior. |
| `correctness.py` | deterministic golden JSON of parsed/serialized values; the behavior oracle `regression.py` diffs. |
| `proto_address_bench.py`, `query_*_bench.py`, `pcap_info_bench.py`, `reader_gil_bench.py`, `allocation_bench.py`, `example_protocols_bench.py` | focused micro-benchmarks for specific paths. |

## End-to-end workflow (on the appliance)

Assume the checkout is at `~/packets` (adjust to taste). Run everything
from the checkout root.

### 1. Build the library and the libpcap ceiling extension

```sh
cd ~/packets
python3 setup.py build_ext --inplace          # build the packets extensions
python3 bench/setup_dispatch.py build_ext --inplace   # build the libpcap ceiling
```

`setup_dispatch.py` drops `pcap_dispatch_bench*.so` into `bench/` (next to the
`.pyx`), which is where `compare_libs.py` imports it from. It is a standalone
build: it never rebuilds or disturbs the installed `packets` package.

If you skip this step, `compare_libs.py --libs libpcap` logs a clear
`not built -- build bench/pcap_dispatch_bench first ...` message instead of a
traceback, and simply omits the ceiling rows.

### 2. Generate the corpus

The streaming benchmarks measure *per-packet* cost, so they need a capture with
many packets; a tiny capture just measures file open/close. `make_corpus.py`
writes both captures deterministically from library code:

```sh
python3 bench/make_corpus.py \
    --frames /tmp/frames.pcap --count 50000 \
    --netflow /tmp/netflow.pcap --netflow-records 20000 \
    --l7 /tmp/l7.pcap --l7-count 49000
```

* `--frames` cycles deterministic TCP / UDP / IPv6 / 802.1Q VLAN / MPLS shapes
  across a range of payload sizes, so every layer the frame benchmarks touch
  appears. Field values are fixed, so the file is byte-for-byte reproducible.
  Its L4 ports are deliberately **opaque** so no library's eager L7 dissector
  runs on the synthetic payload — this capture is for the L2–L4 comparison.
* `--netflow` uses `NetflowV9Generator` with a fixed seed, so templates precede
  data and `nf_decode` resolves records reproducibly. Its collector port (2055)
  is one of `compare_libs.py`'s default `--netflow-ports`.
* `--l7` carries **valid** application-layer messages on **well-known** ports
  (DNS/53, HTTP/80, DHCP/67, DHCPv6/547, NetFlow v9/2055), so a full L7 decode
  is representative work. It is the input for the L7 comparison below.

### 3. Cross-library comparison

```sh
python3 bench/compare_libs.py \
    --pcap /tmp/frames.pcap \
    --netflow-pcap /tmp/netflow.pcap \
    --out /tmp/compare.json
```

Narrow the run with `--libs` (e.g. `--libs packets,libpcap`) — scapy alone is
roughly 70% of a full run. Each pcap operation samples for at least
`--pcap-seconds` and re-reads the whole capture as many times as fit, so a full
run takes minutes. Progress is logged to stderr; results (partial after every
operation) go to `--out` or stdout as JSON.

Add `--l7-pcap /tmp/l7.pcap` to also run the **full layer-7 decode comparison**:
one row per protocol (`l7_dns`, `l7_dns_tcp`, `l7_http`, `l7_dhcp`, `l7_dhcp6`,
`l7_netflow`), decoding the corpus all the way to L7. Each library is measured
only on the protocols it actually supports (packets: all; dpkt: DNS/HTTP/DHCP;
scapy: all but `l7_dns_tcp`; impacket: none — no pcap reader/decoders), and a
protocol a library cannot decode is recorded as `unsupported`. These timings are
**in-memory** (frames are read once, then decoded from bytes), so they are a
pure decode comparison unaffected by each library's pcap-reader speed.

### 4. Version-over-version regression

```sh
python3 bench/regression.py --baseline 2.1.5
```

This checks out `2.1.5` into a throwaway `git worktree`, builds it and the
working tree in place, then measures **both** with the current
`microbench.py --json` and `correctness.py` (via `PYTHONPATH`, so the harness is
identical and the system-installed `packets` is never imported). It prints:

* a per-row timing-delta table (baseline median ns/pkt, current median ns/pkt,
  and percent change — `+` means the working tree is slower), and
* a behavior diff of the two `correctness.py` golden JSON blobs. An empty diff
  means no behavior change; any entry is a real behavior difference.

The worktree is removed on exit, including on failure/interrupt (pass `--keep`
to retain it for inspection).

## Interpreting the output

* **`microbench.py`** reports median and best ns/packet plus packets/sec per
  label. `construct_*` is separate from `build_*` because construction is ~70%
  of build; `serialize_*` isolates the write path.
* **`compare_libs.py`** records, per library and operation, best/median
  µs/packet and packets/sec (`min`+`median`, gc disabled, warmed up).
* **`regression.py`** is a relative view: focus on the delta column and the
  behavior diff, not the absolute ns (which depend on the host).

## Methodology (consistent across the suite)

* **gc disabled** during every timed region.
* **warmup** before every measurement (`microbench.py`, `proto_address_bench.py`
  and `compare_libs.py` all warm up so the first timed pass is not charged
  one-time costs).
* **min + median** over repeated samples, reported per packet.
* **deterministic corpora** (fixed field values / fixed RNG seed) so runs are
  comparable across versions and libraries.

## Fairness notes

* **packets decodes L2–L4 eagerly and L7 lazily.** The `pcapdec_*` variants in
  `compare_libs.py` exist so each library is compared at equivalent work
  (raw read, construct-and-discard, raw-MAC access, formatted-MAC access,
  UDP-port access) rather than at a single decode depth that would flatter one
  library's laziness.
* **the dpkt `build` row presets wire lengths by hand** (`udp.ulen`, `ip.len`)
  because dpkt does not recompute them, whereas packets and scapy recompute
  lengths and checksums during serialization. dpkt's build number therefore
  reflects strictly less work — read the build comparison with that caveat.
* **the `libpcap dispatch` rows are the C-level ceiling**: `pcap_dispatch` hands
  frames to a C callback that only counts (and, for the `extract_*` rows,
  touches the six source-MAC bytes). No Python object is created per packet, so
  these numbers are the achievable floor every Python library sits above. They
  require the `pcap_dispatch_bench` extension (step 1).
* **the `l7_*` rows carry valid protocol payloads**, so a full decode is
  representative work for every library (no eager-dissector thrash on random
  bytes). `l7_dns_tcp` is packets-only: packets decodes DNS-over-TCP from the
  raw message while dpkt/scapy require the 2-byte length prefix, so one frame
  cannot feed both fairly — the shared DNS comparison is `l7_dns` over UDP.
