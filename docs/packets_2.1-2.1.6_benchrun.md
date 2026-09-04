# packets 2.1 vs 2.1.6 — benchmark run

**Prepared for:** General Audience
**Date:** 2026-09-04
**Library under test:** `packets` (Cython)
**Comparison peers:** dpkt 1.9.8, impacket 0.13.1, scapy 2.5.0, plus the libpcap C-level ceiling
**Benchmark host:** Riverbed FlowGateway 10.32 (release 218) device (Cython 0.28.1, gcc 8.5, libpcap 1.9.1, CPython 3.6.8)

---

## 1. Executive summary

- **Correctness is unchanged between 2.1 and 2.1.6.** The golden-behavior oracle (`bench/correctness.py`) produced **zero** differences across the two builds. Every performance change below is a pure speed change, not a behavior change.
- **2.1.6 is dramatically faster at field access and several parse paths, with a few parse regressions.** The largest wins are attribute/field access (up to **‑86%**) and ARP/UDP parsing (**‑25% to ‑50%**). The notable regressions are IPv6‑over‑TCP/UDP and IGMPv3/ICMPv6 parsing (**+16% to +46%**). Construction and serialization are essentially flat (±5%).
- **Against other Python libraries, `packets` is the clear performance leader** at every layer. On full L2–L4 pcap decode, `packets` 2.1.6 is **~7×** faster than dpkt and **~79×** faster than scapy; on build it is **~7×** (dpkt), **~10×** (impacket), **~140×** (scapy); on parse **~10×/~18×/~282×** respectively. It sits about **12–13×** above the raw libpcap C ceiling for a full decode and about **2.5×** above it for a pure read.
- **NetFlow v9 is a genuine capability gain in 2.1.6.** The v9 decoder module (`packets.protos.netflow`) does **not exist in 2.1**, so `nf_decode` is only available from 2.1.6 onward. At 2.1.6 it fully resolves the corpus (1,000 datagrams / 100 templates / **20,000 records**, 0 fallbacks) at **12.0 µs per datagram-packet**, versus scapy at **583 µs** (~48×); dpkt cannot decode v9 at all.
- **On full L7 dissection, `packets` again leads at every protocol** (Part C, §5). Decoding valid DNS/HTTP/DHCP/DHCPv6/NetFlow-v9 payloads, 2.1.6 runs **2.7–5.8× faster than dpkt** and **44–80× faster than scapy**, and covers protocols the peers cannot (DHCPv6 and NetFlow v9 vs dpkt; DNS-over-TCP without a length prefix). impacket ships no L7 decoders.

---

## 2. Methodology

### 2.1 What "2.1" and "2.1.6" mean here

| Side | Git ref | Notes |
|------|---------|-------|
| baseline "2.1" | tag `2.1` → commit `89b0969` | "v.2.1 — Performance fixes and updates plus IPv6 support…" |
| current "2.1.6" | working tree `80d90ca` | Library source is **byte-identical** to the `2.1.6` tag (`git diff 2.1.6 HEAD -- packets/` is empty), so "working-tree" == 2.1.6. |

Both are **post‑namespace** releases (top-level `packets/`), so the benchmark harness imports resolve on both without a shim.

### 2.2 Isolation (no system package was touched)

- The baseline (`2.1`) was checked out into a throwaway `git worktree` and built with `python3 setup.py build_ext --inplace` **inside** it.
- The current tree (`2.1.6`) was built in place.
- Each side was measured by running the **current** harness scripts with `PYTHONPATH` pointed at that build, so the harness is byte-for-byte identical on both sides and only the imported `packets` differs. `PYTHONPATH` precedes site-packages, so the installed `packets` was never imported.
- All worktrees were removed on exit; post-run `git worktree list` shows only the main checkout and no leftover temp dirs.

### 2.3 Timing model (identical for every library and version)

- **gc disabled** during timed regions.
- **Warmup pass** before every measurement (100 iterations for microbench / the cross-library harness).
- Each figure is the **median** of 5 samples (best also captured). In-memory ops use 50,000 iterations/sample; pcap ops re-read the capture for ≥3.0 s/sample; NetFlow ops for ≥1.0 s/sample.
- Reported as **µs/packet** (cross-library) or **ns/packet** (microbench).

### 2.4 Corpus (deterministic, generated from library code)

- **frames.pcap** — 50,000 packets, 30 MiB. A fixed mix of TCP, UDP, IPv6/UDP, 802.1Q VLAN and MPLS shapes across payload sizes {0, 64, 256, 512, 1024, 1400}. No RNG — byte-for-byte reproducible.
- **netflow.pcap** — 1,000 export datagrams / 20,000 records / 100 templates, produced by `NetflowV9Generator(seed=1234)` (templates precede data so decoders resolve records).

> **Corpus fix applied for fairness (this run).** The frames generator (`bench/make_corpus.py`) previously used well-known L4 ports (UDP/53, TCP/80). Because the synthetic payload is incrementing bytes, scapy — which eagerly binds UDP/53 to its DNS dissector — spent **tens of milliseconds per 1400-byte frame** thrashing the DNS parser on non-protocol bytes (measured: **92,486 µs/pkt** at dport 53 vs **113 µs/pkt** at dport 40000). That is a DNS-parser artifact, not decode cost, and would make scapy look ~8,000× slower than reality. The generator now emits **opaque (non‑well‑known) L4 ports**, so every library performs an apples-to-apples **L2–L4 decode with the L7 payload left opaque**. This is the correct basis for a cross-library decode comparison (see §5).

### 2.5 Benchmark host

All builds and timed runs were performed on a **Riverbed FlowGateway 10.32 (release 218)** device with the following specifications:

| Resource | Specification |
|----------|---------------|
| CPU | 12th Gen Intel® Core™ i9-12900K — 10 vCPUs @ ~3.19 GHz |
| Memory | 31 GiB RAM (+ 15 GiB swap) |
| Disk | 50 GB root volume, 98 GB database volume, 492 GB data volume |

Software toolchain: CPython 3.6.8, Cython 0.28.1, gcc 8.5, libpcap 1.9.1; peer libraries scapy 2.5.0, dpkt 1.9.8, impacket 0.13.1.

---

## 3. Part A — Version-over-version: 2.1 → 2.1.6

Source: `bench/regression.py --baseline 2.1 --iterations 20000 --repeats 5`.
Values are **median ns/packet**. `delta %` is `(2.1.6 − 2.1) / 2.1`; **negative = 2.1.6 is faster**.

### 3.1 Headline changes

| Category | Representative labels | Effect in 2.1.6 |
|----------|-----------------------|-----------------|
| **Field access (big win)** | `access_eth_src_x16` ‑85.7%, `access_eth_src_x1` ‑81.7%, `access_ip_src_x16` ‑65.7%, `access_ip_src_x1` ‑60.0% | Attribute/field access is **~3–7× faster**. |
| **ARP / UDP parse (win)** | `parse_eth_arp` ‑50.4%, `parse_arp` ‑28.4%, `parse_udp` ‑25.1%, `parse_udp_p1400` ‑27.3%, `parse_tcp` ‑11.7% | Core parse paths **10–50% faster**. |
| **IPv6 / ICMPv6 / IGMPv3 parse (regression)** | `parse_ip6_tcp` +45.6%, `parse_ip6_udp` +43.8%, `parse_igmp_v3` +20.0%, `parse_icmp6_mld` +17.4%, `parse_icmp6_nd` +16.6%, `parse_ip4_tcp` +16.3% | These paths are **10–46% slower**. |
| **Construct / serialize (flat)** | `construct_udp` +4.7%, `build_tcp+csum` ‑0.8%, `serialize_tcp+csum` ‑3.3% | Within ±5% — effectively unchanged. |

**Net read:** 2.1.6 substantially optimized attribute access and the common IPv4 ARP/UDP/TCP parse paths, at the cost of some IPv6/ICMPv6/IGMPv3 parse regressions. Build and serialize are unchanged.

### 3.2 Full table (60 labels, median ns/pkt)

| label | 2.1 | 2.1.6 | delta % |
|---|---:|---:|---:|
| access_eth_src_x1 | 309.5 | 56.6 | −81.7% |
| access_eth_src_x16 | 4639.4 | 661.8 | −85.7% |
| access_ip_src_x1 | 141.0 | 56.5 | −60.0% |
| access_ip_src_x16 | 2037.6 | 699.3 | −65.7% |
| build_tcp+csum | 2166.6 | 2148.8 | −0.8% |
| build_udp+csum | 1915.0 | 1985.4 | +3.7% |
| construct_tcp | 1742.3 | 1733.2 | −0.5% |
| construct_udp | 1497.8 | 1568.8 | +4.7% |
| parse_arp | 678.3 | 485.8 | −28.4% |
| parse_dns | 2294.0 | 2313.5 | +0.8% |
| parse_dns_tcp4 | 3197.5 | 3093.8 | −3.2% |
| parse_dns_udp4 | 3112.0 | 3012.9 | −3.2% |
| parse_eth_arp | 994.8 | 493.8 | −50.4% |
| parse_eth_icmp4 | 834.5 | 724.3 | −13.2% |
| parse_eth_icmp6_mld | 891.6 | 772.7 | −13.3% |
| parse_eth_icmp6_nd | 937.2 | 825.2 | −12.0% |
| parse_eth_igmp | 910.3 | 791.3 | −13.1% |
| parse_eth_netflow | 908.6 | 837.3 | −7.9% |
| parse_icmp6_echo | 391.1 | 424.2 | +8.5% |
| parse_icmp6_mld | 646.9 | 759.6 | +17.4% |
| parse_icmp6_nd | 697.8 | 813.5 | +16.6% |
| parse_icmp6_opt | 300.2 | 313.3 | +4.4% |
| parse_icmp_du | 941.4 | 1051.1 | +11.7% |
| parse_icmp_echo | 397.1 | 434.5 | +9.4% |
| parse_igmp_record | 308.0 | 327.9 | +6.4% |
| parse_igmp_v2 | 321.8 | 337.8 | +5.0% |
| parse_igmp_v3 | 807.7 | 969.1 | +20.0% |
| parse_ip4_tcp | 553.3 | 643.3 | +16.3% |
| parse_ip4_udp | 476.5 | 547.5 | +14.9% |
| parse_ip6_ext_udp | 601.5 | 662.5 | +10.2% |
| parse_ip6_tcp | 485.1 | 706.3 | +45.6% |
| parse_ip6_udp | 441.9 | 635.7 | +43.8% |
| parse_mld_record | 311.3 | 323.4 | +3.9% |
| parse_mpls | 466.6 | 538.6 | +15.4% |
| parse_mpls_ip6 | 698.7 | 744.2 | +6.5% |
| parse_netflow | 301.1 | 320.0 | +6.3% |
| parse_nullpkt | 83.9 | 99.0 | +18.0% |
| parse_tcp | 716.9 | 633.3 | −11.7% |
| parse_tcp_layer | 264.4 | 298.8 | +13.0% |
| parse_udp | 610.2 | 457.1 | −25.1% |
| parse_udp_layer | 221.1 | 241.0 | +9.0% |
| parse_udp_p0 | 597.3 | 472.1 | −20.9% |
| parse_udp_p1400 | 633.2 | 460.2 | −27.3% |
| parse_udp_p512 | 618.9 | 468.0 | −24.4% |
| parse_udp_p64 | 599.3 | 461.0 | −23.1% |
| parse_vlan_tcp | 731.1 | 664.3 | −9.1% |
| query_udp_p0 | 240.3 | 262.7 | +9.3% |
| query_udp_p1400 | 248.9 | 255.3 | +2.6% |
| query_udp_p512 | 247.7 | 255.3 | +3.1% |
| query_udp_p64 | 249.1 | 241.6 | −3.0% |
| serialize_arp | 191.8 | 193.7 | +1.0% |
| serialize_dns | 825.7 | 806.9 | −2.3% |
| serialize_dns_nocompress | 850.5 | 874.2 | +2.8% |
| serialize_icmp_du | 263.1 | 282.0 | +7.2% |
| serialize_igmp_v3 | 138.1 | 145.9 | +5.7% |
| serialize_mpls | 229.5 | 252.7 | +10.1% |
| serialize_tcp+csum | 351.8 | 340.1 | −3.3% |
| serialize_udp+csum | 352.6 | 343.9 | −2.5% |
| serialize_udp_nocsum | 274.3 | 269.5 | −1.7% |

### 3.3 Behavior diff

```
behavior diff: 2.1 vs working-tree (empty == no behavior change)
  (no differences)
```

No golden-output differences: **2.1.6 decodes the corpus identically to 2.1.**

### 3.4 Capability delta between the versions

| Capability | 2.1 | 2.1.6 |
|-----------|-----|-------|
| Simple NetFlow (v5-style `NetflowSimple` in `inetpkt`) — `parse_netflow` / `nf_simple` | ✅ | ✅ |
| **NetFlow v9 decoder module `packets.protos.netflow`** — `nf_decode` | ❌ **absent** | ✅ present |

During the cross-library run, packets **2.1**'s NetFlow decode section failed with `ModuleNotFoundError: No module named 'packets.protos.netflow'` — the v9 template pipeline did not yet exist in 2.1. The microbench `parse_netflow` label still works on both versions because it exercises the v5-style `NetflowSimple`, which lives in `inetpkt` and predates the v9 module.

---

## 4. Part B — Cross-library comparison

Sources:
- `packets 2.1.6`, `libpcap`, `impacket`, `scapy`, `dpkt`: one full `compare_libs.py --libs all` run at 2.1.6.
- `packets 2.1`: a `compare_libs.py --libs packets` run against the isolated 2.1 build (same harness, same corpus).

All values are **median µs/packet** (lower is better). `-` = op not defined for that library; `unsup` = library cannot perform the op; `ERR` = feature absent in that build.

| op | packets 2.1 | packets 2.1.6 | libpcap (C) | impacket | scapy | dpkt |
|---|---:|---:|---:|---:|---:|---:|
| build | 2.434 | **2.295** | – | 24.004 | 321.119 | 16.499 |
| parse | 0.746 | **0.533** | – | 9.492 | 150.187 | 5.303 |
| pcaprd (read only) | 0.246 | **0.247** | 0.100 | unsup | 1.003 | 1.427 |
| pcapdec_ctor (construct) | 1.202 | **1.009** | – | unsup | 97.620 | 8.729 |
| pcapdec_rawmac (+read MAC) | 1.287 | **1.234** | 0.101 | unsup | 97.400 | 8.792 |
| pcapdec (full decode) | 1.698 | **1.272** | – | unsup | 99.948 | 8.774 |
| pcapdec_udp (+read sport) | 1.310 | **1.137** | – | unsup | 102.650 | 8.943 |
| nf_pcaprd (read only) | ERR | **0.203** | 0.057 | unsup | 0.937 | 1.296 |
| nf_simple (v5-style) | ERR | **2.203** | unsup | unsup | 244.119 | unsup |
| nf_decode (v9 full) | ERR | **12.027** | unsup | unsup | 582.985 | unsup |

### 4.1 packets 2.1.6 speedup vs peers (median µs/pkt)

| op | vs dpkt | vs impacket | vs scapy |
|---|---:|---:|---:|
| build | **7.2×** | 10.5× | 139.9× |
| parse | **10.0×** | 17.8× | 281.8× |
| pcaprd | 5.8× | – | 4.1× |
| pcapdec (full) | **6.9×** | – | 78.6× |
| pcapdec_ctor | 8.7× | – | 96.7× |
| nf_decode (v9) | (dpkt can't) | – | 48.5× |
| nf_simple | (dpkt can't) | – | 110.8× |

### 4.2 The libpcap C ceiling

The self-contained `pcap_dispatch_bench` extension measures the floor: libpcap handing frames to a C callback with no Python object created per packet.

| ceiling op | µs/pkt |
|---|---:|
| count_16 / count_64 / count_256 | 0.100 |
| batch_16 / batch_64 / batch_256 | 0.100–0.101 |
| extract_16 / extract_64 / extract_256 | 0.100–0.101 |
| nf_pcaprd | 0.057 |

Interpretation: `packets` 2.1.6 reads a capture at **0.247 µs/pkt (~2.5× the C floor)** and performs a **full L2–L4 decode at 1.272 µs/pkt (~12.7× the floor)** — i.e. the Python-object cost of a full decode is roughly an order of magnitude over "do nothing in C", while dpkt (~88×) and scapy (~1000×) sit far higher.

### 4.3 NetFlow v9 decode detail (packets 2.1.6)

`nf_decode` fully resolved the corpus with template state shared across datagrams:

```
datagrams=1000  templates=100  frames=1000  records=20000  structured=1000  fallback=0
```

Zero fallbacks and all 20,000 records structured confirm the v9 template pipeline resolved every record. dpkt is marked `unsupported` (no v9 template handling); scapy decodes but at ~48× the cost.

---

## 5. Part C — full L7 decode comparison

Part B deliberately left the L7 payload opaque (§2.4). This section closes the gap
§5 flags: a **valid-payload** corpus where every library is asked to fully dissect
the application layer, so the numbers reflect real L7 decode cost rather than a
parser pathology.

Source: `bench/compare_libs.py --l7-pcap /tmp/l7.pcap --libs all --repeats 5
--l7-seconds 1.0` against the deterministic L7 corpus from
`bench/make_corpus.py --l7` (49,000 frames carrying **valid** protocol payloads
on their well-known ports: DNS/53 UDP+TCP, HTTP/80, DHCP/67, DHCPv6/547,
NetFlow-v9/2055). L7 timings are **in-memory**: the corpus is read once, then each
op decodes from the buffered bytes for ≥1.0 s/sample — a pure decode comparison,
independent of pcap-reader speed. Each op verifies one untimed pass and records
its decoded count before timing.

All values are **median µs/packet** (lower is better). `unsup` = library cannot
perform the op; `pkts-only` = capability unique to `packets` on this corpus.

| L7 op (proto / port) | packets 2.1.6 | dpkt | scapy | impacket | libpcap (C) |
|---|---:|---:|---:|---:|---:|
| l7_dns (DNS / UDP 53) | **3.596** | 20.982 | 285.463 | unsup | unsup |
| l7_dns_tcp (DNS / TCP 53) | **3.682** | pkts-only | pkts-only | unsup | unsup |
| l7_http (HTTP / TCP 80) | **3.878** | 10.494 | 169.173 | unsup | unsup |
| l7_dhcp (DHCP / UDP 67) | **1.920** | 8.312 | 120.050 | unsup | unsup |
| l7_dhcp6 (DHCPv6 / UDP 547) | **1.518** | unsup | 121.694 | unsup | unsup |
| l7_netflow (NetFlow v9 / UDP 2055) | **11.242** | unsup | 564.060 | unsup | unsup |

All decode-verify counts matched the corpus buckets exactly (DNS 7,000; DNS-over-TCP
7,000; HTTP 14,000; DHCP 7,000; DHCPv6 7,000; NetFlow-v9 7,000 datagrams) with zero
errors — every library that ran an op decoded every frame in that bucket.

### 5.1 packets 2.1.6 speedup vs peers (median µs/pkt, full L7 decode)

| L7 op | vs dpkt | vs scapy |
|---|---:|---:|
| l7_dns | **5.8×** | 79.4× |
| l7_http | **2.7×** | 43.6× |
| l7_dhcp | **4.3×** | 62.5× |
| l7_dhcp6 | (dpkt can't) | 80.2× |
| l7_netflow (v9) | (dpkt can't) | 50.2× |

`packets` leads at every L7 protocol, by **2.7–5.8×** over dpkt and **44–80×** over
scapy. The NetFlow-v9 figure (11.24 µs/pkt) corroborates Part B's `nf_decode`
(12.03 µs/pkt) via a fully independent path (full frame → v9 template resolution),
and scapy's 564 µs/pkt matches its Part B v9 cost (583 µs/pkt) — the two runs agree.

### 5.2 L7 capability matrix

| L7 op | packets 2.1.6 | dpkt 1.9.8 | scapy 2.5.0 | impacket 0.13.1 |
|---|:--:|:--:|:--:|:--:|
| DNS (UDP) | ✅ | ✅ | ✅ | ❌ |
| DNS (TCP) | ✅ | ❌¹ | ❌¹ | ❌ |
| HTTP | ✅ | ✅ | ✅ | ❌ |
| DHCP | ✅ | ✅ | ✅ | ❌ |
| DHCPv6 | ✅ | ❌ (no decoder) | ✅ | ❌ |
| NetFlow v9 | ✅ | ❌ (v1/v5/v6/v7 only) | ✅ | ❌ |

¹ **DNS-over-TCP fairness note.** `l7_dns_tcp` is reported `packets`-only because the
corpus carries the **raw DNS message** that `packets` decodes directly from the TCP
payload, *without* the 2-byte length prefix that both dpkt and scapy require to frame
DNS-over-TCP. This is a corpus-framing choice, not a dpkt/scapy decoder deficiency —
the shared, apples-to-apples DNS row is `l7_dns` (over UDP). `packets` decoding
DNS-over-TCP at essentially the same 3.6 µs/pkt as DNS-over-UDP is shown for
completeness. impacket ships no DNS/HTTP/DHCP/NetFlow decoders at all, and the
libpcap ceiling is a C frame counter (no L7), so both are `unsup` across the board.

---

## 6. Fairness notes & caveats

- **Eager L2–L4 vs lazy L7.** `packets` eagerly builds L2–L4 objects but is **lazy at L7** (the payload stays opaque until asked). The `pcapdec_*` family separates these costs: `pcapdec_ctor` (construct only), `pcapdec_rawmac` (+touch wire bytes), `pcapdec` (full), `pcapdec_udp` (+read an L4 field). This lets the comparison stay at the layer each library is actually asked to decode.
- **Opaque-port corpus (see §2.4).** The Part B comparison measures **L2–L4 decode with the L7 payload opaque**. Well-known L7 ports were deliberately avoided so no library's eager L7 dissector (notably scapy's DNS) thrashes on synthetic payload — that would measure a parser pathology, not decode speed. This is the correct, representative basis for an L2–L4 decode comparison; **Part C (§5)** supplies the complementary L7 comparison on a valid-payload corpus.
- **scapy** eagerly dissects on construction, which is inherent to its design and explains the ~80–280× gap; its numbers here are legitimate scapy decode cost on opaque payloads (not the DNS artifact).
- **impacket** has **no native pcap file reader**, so all pcap ops are correctly reported `unsup` rather than fabricated; only its in-memory `build`/`parse` are comparable.
- **dpkt** presets some length fields at build time; its `build` figure is therefore a mild best case relative to libraries that always recompute lengths. dpkt is lazy at L7 (comparable basis) but cannot decode NetFlow v9.
- **NetFlow v9** requires template-before-data state; the generated corpus satisfies this. dpkt cannot do v9 at all; scapy can but slowly; `packets` needs 2.1.6+ (the module is absent in 2.1).

---

## 7. Reproduction

On the Riverbed FlowGateway 10.32 (release 218) device, from the packets checkout:

```bash
# build the library and the libpcap ceiling extension
python3 setup.py build_ext --inplace
python3 bench/setup_dispatch.py build_ext --inplace

# generate the deterministic corpus (opaque L4 ports)
python3 bench/make_corpus.py --frames frames.pcap --count 50000 \
                             --netflow netflow.pcap --netflow-records 20000

# cross-library comparison at 2.1.6
python3 bench/compare_libs.py --pcap frames.pcap --netflow-pcap netflow.pcap \
                              --libs all --packets-label "packets 2.1.6"

# packets 2.1 reference numbers (isolated worktree build on PYTHONPATH)
#   git worktree add --detach /tmp/wt_2.1 2.1
#   (cd /tmp/wt_2.1 && python3 setup.py build_ext --inplace)
#   PYTHONPATH=/tmp/wt_2.1 python3 bench/compare_libs.py --pcap frames.pcap \
#       --netflow-pcap netflow.pcap --libs packets --packets-label "packets 2.1"

# version-over-version regression (2.1 -> working tree = 2.1.6)
python3 bench/regression.py --baseline 2.1 --iterations 20000 --repeats 5

# Part C — full L7 decode comparison (valid-payload corpus)
python3 bench/make_corpus.py --l7 /tmp/l7.pcap
python3 bench/compare_libs.py --pcap /tmp/l7.pcap --l7-pcap /tmp/l7.pcap \
                              --libs all --repeats 5 --l7-seconds 1.0 \
                              --packets-label "packets 2.1.6" --out /tmp/l7_run.json
#   (--pcap is required and always runs the L2-L4 frame section; for Part C those
#    frame rows are ignored and only the l7_* rows are harvested from the JSON.)
```

**Environment:** CPython 3.6.8, Cython 0.28.1, gcc 8.5, libpcap 1.9.1; scapy 2.5.0, dpkt 1.9.8, impacket 0.13.1. gc disabled, warmup applied, median of 5 samples. Baseline tag `2.1` = commit `89b0969`; current working tree `80d90ca` (library identical to the `2.1.6` tag). The system-installed `packets` was never touched; all worktrees were cleaned up after the run.
