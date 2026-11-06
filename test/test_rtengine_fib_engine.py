# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Stage 4 of the 2.3 fixes: the forwarding plane and the engine around it.

Each test names the review item it pins (``L-6``, ``E-3`` ...). They run
everywhere: the engine-built netlink sink is driven through the fake
transport from ``test_rtengine_netlink`` with the host's capabilities
pinned, so nothing here opens a real netlink socket -- the kernel half is
in ``test_rtengine_netlink.LinuxKernelTestCase`` and in the live re-test.
"""

import errno
import logging
import struct
import threading
import time
import unittest
from unittest import mock

import rtengine_rawspeaker as raw
import test_rtengine_session_notify as notify
from test_rtengine_engine import FLAT_SCHEMA, RecordingPlugin
from test_rtengine_netlink import SPARE_TABLE, FakeTransport, open_sink

from packets.routing.rtengine import ApplyError, ConfigError, \
    ConflictError, Engine, ProtocolPlugin, UnavailableError
from packets.routing.rtengine import engine as engine_mod
from packets.routing.rtengine import events as EV
from packets.routing.rtengine.events import EventBus
from packets.routing.rtengine.fib import factory, netlink
from packets.routing.rtengine.fib.netlink import NetlinkSink
from packets.routing.rtengine.fib.sink import NullSink
from packets.routing.rtengine.health import DEGRADED, DOWN, OK, \
    SUSTAIN_PROBES, HealthMonitor
from packets.routing.rtengine.loop import new_loop
from packets.routing.rtengine.plugins.bgp import fsm as fsm_mod
from packets.routing.rtengine.plugins.bgp import plugin as bgp_plugin
from packets.routing.rtengine.rib import table as T
from packets.routing.rtengine.rib.prefix import AFI_IP, parse_prefix

NH = b'\xc0\x00\x02\x01'
OTHER_TABLE = 191

_quiet = ('packets.rtengine.engine', 'packets.rtengine.fib.netlink')


def setUpModule():
    # Several tests make the kernel (or the selection pass) fail on
    # purpose; their warnings are the behaviour under test, not noise for
    # the console.
    global _levels
    _levels = [(name, logging.getLogger(name).level) for name in _quiet]
    for name in _quiet:
        logging.getLogger(name).setLevel(logging.CRITICAL)


def tearDownModule():
    for name, level in _levels:
        logging.getLogger(name).setLevel(level)


def _route(text, source=None, metric=0):
    return T.Route(parse_prefix(text), T.PROTO_BGP, 20, metric, NH,
                   source or object(), 100.0)


def _caps(supported=True, privileged=True):
    return {'supported': supported, 'privileged': supported and privileged,
            'reason': 'pinned by the test', 'platform': 'test', 'euid': -1}


def _unopened_sink(errno_for=None, **kwargs):
    """A netlink sink on a fake transport, for injection, not yet open.

    Not ``open_sink()`` followed by ``close()``: closing drops the
    transport, and the engine reopening it would then reach for the real
    socket factory.
    """
    transport = FakeTransport(errno_for=errno_for)
    params = {'table': SPARE_TABLE, 'transport': transport, 'timeout': 0.2}
    params.update(kwargs)
    return NetlinkSink(**params), transport


def _wait(predicate, what, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('%s did not happen within %.0fs' % (what, timeout))


class FakeKernel(object):
    """Pins the host as netlink-capable and hands out fake transports.

    :ivar transports: every transport the engine opened, in order.
    :ivar refuse: an OSError the next open raises instead, for E-3.
    """

    def __init__(self, test):
        self.transports = []
        self.refuse = None
        for patcher in (
                mock.patch.object(netlink, 'capabilities',
                                  return_value=_caps()),
                mock.patch.object(netlink, 'supported', return_value=True),
                mock.patch.object(netlink.NetlinkTransport, 'open',
                                  side_effect=self._open)):
            patcher.start()
            test.addCleanup(patcher.stop)

    def _open(self, *args, **kwargs):
        if self.refuse is not None:
            raise self.refuse
        transport = FakeTransport()
        self.transports.append(transport)
        return transport

    @staticmethod
    def requests(transport, msg_type):
        return [r for r in transport.sent if r['type'] == msg_type]


class EngineFixture(unittest.TestCase):

    def make_engine(self, **kwargs):
        engine = Engine(**kwargs)
        self.addCleanup(engine.stop)
        return engine

    def offer(self, engine, *routes):
        """Offer routes from the loop thread and ask for selection."""
        def go():
            for r in routes:
                engine.global_rib.offer(r)
            engine.schedule_select()
        engine.submit(go).result(5)


# --- L-6: which sink a section asks for -------------------------------------


class FactoryTestCase(unittest.TestCase):
    """L-6: ``fib/factory.py``."""

    def test_install_off_is_a_null_sink_and_never_probes_the_host(self):
        with mock.patch.object(netlink, 'capabilities',
                               side_effect=AssertionError('probed')):
            for cfg in (None, {}, {'install': False, 'table': 100}):
                self.assertIsNone(factory.sink_spec(cfg))
                factory.check_installable(cfg)
                self.assertIsInstance(factory.make_sink(cfg), NullSink)

    def test_install_on_is_an_unopened_netlink_sink_built_from_the_section(
            self):
        cfg = {'install': True, 'table': 100, 'protocol': 190,
               'priority': {'ebgp': 21, 'ibgp': 201}}
        sink = factory.make_sink(cfg)
        self.assertIsInstance(sink, NetlinkSink)
        self.assertFalse(sink.is_open())
        self.assertEqual((sink.table, sink.protocol, sink.priority_ebgp,
                          sink.priority_ibgp), (100, 190, 21, 201))
        self.assertEqual(factory.sink_spec(cfg),
                         ('netlink', 100, 190, 21, 201))

    def test_only_keying_fields_change_the_spec(self):
        base = {'install': True, 'table': 100}
        self.assertEqual(
            factory.sink_spec(base),
            factory.sink_spec(dict(base, **{'retain-on-shutdown': True})))
        self.assertNotEqual(factory.sink_spec(base),
                            factory.sink_spec(dict(base, table=101)))

    def test_install_on_an_unsupported_host_is_a_config_error(self):
        with self.assertRaises(ConfigError) as caught:
            factory.check_installable({'install': True},
                                      capabilities=_caps(supported=False))
        self.assertEqual(caught.exception.as_dict()['path'],
                         'ip.route.install')

    def test_install_without_cap_net_admin_is_a_config_error(self):
        with self.assertRaises(ConfigError) as caught:
            factory.check_installable({'install': True},
                                      capabilities=_caps(privileged=False))
        self.assertIn('CAP_NET_ADMIN', str(caught.exception))

    def test_the_kernels_own_tables_are_refused(self):
        for table in (0, 255):
            with self.assertRaises(ConfigError) as caught:
                factory.check_installable({'install': True, 'table': table},
                                          capabilities=_caps())
            self.assertEqual(caught.exception.as_dict()['path'],
                             'ip.route.table')


# --- L-6 / E-3: the engine owns its sink -------------------------------------


class EngineOwnedSinkTestCase(EngineFixture):
    """L-6: ``ip route install`` from configuration alone, no injection."""

    def setUp(self):
        self.kernel = FakeKernel(self)

    def test_construction_never_opens_a_socket(self):
        # What makes `rtengine --check` and a stopped engine side-effect
        # free: the sink is built, and only a running engine opens it.
        engine = self.make_engine(config={'ip': {'route': {
            'install': True, 'table': SPARE_TABLE}}})
        self.assertEqual(engine.sink.name, 'netlink')
        self.assertFalse(engine.sink.is_open())
        self.assertEqual(self.kernel.transports, [])
        engine.start()
        self.assertTrue(engine.sink.is_open())
        self.assertEqual(len(self.kernel.transports), 1)

    def test_turning_install_on_at_runtime_installs_what_is_already_best(
            self):
        engine = self.make_engine()
        engine.start()
        self.offer(engine, _route('198.51.100.0/24'))
        _wait(lambda: engine.sink.stats()['present'] == 1,
              'selection reaching the null sink')
        self.assertEqual(self.kernel.transports, [])

        engine.configure(('ip', 'route', 'table'), SPARE_TABLE)
        self.assertEqual(self.kernel.transports, [])
        engine.configure(('ip', 'route', 'install'), True)
        self.assertEqual(engine.sink.name, 'netlink')
        self.assertEqual(engine.sink.table, SPARE_TABLE)
        transport = self.kernel.transports[0]
        _wait(lambda: self.kernel.requests(transport, netlink.RTM_NEWROUTE),
              'the existing best route being installed')
        best = engine.submit(lambda: engine.global_rib.routes(AFI_IP)) \
            .result(5)
        _wait(lambda: best[0].fib_state == T.FIB_STATE_INSTALLED,
              'the ack being applied')

    def test_a_table_change_empties_the_old_table_and_fills_the_new(self):
        engine = self.make_engine(config={'ip': {'route': {
            'install': True, 'table': SPARE_TABLE}}})
        engine.start()
        self.offer(engine, _route('198.51.100.0/24'))
        first = self.kernel.transports[0]
        _wait(lambda: self.kernel.requests(first, netlink.RTM_NEWROUTE),
              'the first install')

        engine.configure(('ip', 'route', 'table'), OTHER_TABLE)
        self.assertEqual(engine.sink.table, OTHER_TABLE)
        deletes = self.kernel.requests(first, netlink.RTM_DELROUTE)
        self.assertEqual([d['table'] for d in deletes], [SPARE_TABLE])
        self.assertTrue(first.closed)
        second = self.kernel.transports[-1]
        _wait(lambda: self.kernel.requests(second, netlink.RTM_NEWROUTE),
              'the install into the new table')
        self.assertEqual(
            self.kernel.requests(second, netlink.RTM_NEWROUTE)[0]['table'],
            OTHER_TABLE)

    def test_turning_install_off_empties_the_table_at_once(self):
        engine = self.make_engine(config={'ip': {'route': {
            'install': True, 'table': SPARE_TABLE}}})
        engine.start()
        self.offer(engine, _route('198.51.100.0/24'))
        transport = self.kernel.transports[0]
        _wait(lambda: self.kernel.requests(transport, netlink.RTM_NEWROUTE),
              'the install')
        engine.configure(('ip', 'route', 'install'), False)
        self.assertEqual(engine.sink.name, 'null')
        self.assertEqual(
            len(self.kernel.requests(transport, netlink.RTM_DELROUTE)), 1)
        self.assertTrue(transport.closed)

    def test_an_injected_sink_is_never_replaced(self):
        sink, _transport = _unopened_sink()
        engine = self.make_engine(sink=sink)
        engine.start()
        engine.configure(('ip', 'route', 'install'), True)
        engine.configure(('ip', 'route', 'table'), OTHER_TABLE)
        self.assertIs(engine.sink, sink)
        self.assertEqual(self.kernel.transports, [])

    def test_an_injected_sink_that_cannot_write_is_a_conflict(self):
        engine = self.make_engine(sink=NullSink())
        with self.assertRaises(ConflictError):
            engine.configure(('ip', 'route', 'install'), True)
        self.assertEqual(engine.revision, 0)


class TransactionalApplyTestCase(EngineFixture):
    """E-3: core, plugins and the store commit together or not at all."""

    def setUp(self):
        self.kernel = FakeKernel(self)

    def test_a_kernel_refusal_rolls_back_the_plugin_and_the_store(self):
        plugin = RecordingPlugin(name='alpha', section=('router', 'alpha'),
                                 schema=FLAT_SCHEMA)
        engine = self.make_engine(plugins=[plugin])
        engine.start()
        engine.configure(('router', 'alpha', 'v'), 1)
        revision = engine.revision
        before = engine.running_config()
        committed = len(plugin.committed)

        self.kernel.refuse = OSError(errno.EPERM, 'Operation not permitted')
        with self.assertRaises(ApplyError) as caught:
            engine.replace_config({'router': {'alpha': {'v': 2}},
                                   'ip': {'route': {'install': True,
                                                    'table': SPARE_TABLE}}})
        self.assertTrue(caught.exception.rolled_back)
        self.assertIn('core configuration', str(caught.exception))
        self.assertEqual(engine.revision, revision)
        self.assertEqual(engine.running_config(), before)
        self.assertEqual(engine.sink.name, 'null')
        # The plugin committed v=2 and was then handed the inverse.
        self.assertEqual(len(plugin.committed), committed + 2)

    def test_a_rejected_commit_leaves_a_working_sink_in_place(self):
        engine = self.make_engine(config={'ip': {'route': {
            'install': True, 'table': SPARE_TABLE}}})
        engine.start()
        old = engine.sink
        self.kernel.refuse = OSError(errno.ENOBUFS, 'No buffer space')
        with self.assertRaises(ApplyError):
            engine.configure(('ip', 'route', 'table'), OTHER_TABLE)
        self.assertIs(engine.sink, old)
        self.assertTrue(old.is_open())
        self.assertEqual(engine.sink.table, SPARE_TABLE)


# --- E-1: the FIB pump -------------------------------------------------------


class FibPumpTestCase(EngineFixture):
    """E-1: everything selected reaches the sink without another event."""

    def test_a_backlog_far_larger_than_one_batch_drains_by_itself(self):
        sink, _transport = _unopened_sink(batch=64)
        engine = self.make_engine(sink=sink)
        engine.configure(('ip', 'route', 'install'), True)
        engine.start()
        routes = [_route('10.%d.%d.0/24' % (i // 256, i % 256))
                  for i in range(3000)]
        self.offer(engine, *routes)
        _wait(lambda: sink.stats()['installed'] == len(routes),
              'all %d routes being installed (%d were)'
              % (len(routes), sink.stats()['installed']), timeout=20.0)
        self.assertEqual(sink.queued_count(), 0)
        self.assertEqual(sink.pending_count(), 0)

    def test_a_retry_is_flushed_when_its_backoff_expires(self):
        failures = []

        def refuse_once(request):
            if request['type'] == netlink.RTM_NEWROUTE and not failures:
                failures.append(request)
                return errno.ENETUNREACH
            return 0

        sink, _transport = _unopened_sink(errno_for=refuse_once)
        engine = self.make_engine(sink=sink)
        engine.configure(('ip', 'route', 'install'), True)
        with mock.patch.object(netlink, 'RETRY_MIN_S', 0.1), \
                mock.patch.object(netlink, 'backoff_delay',
                                  return_value=0.1):
            engine.start()
            self.offer(engine, _route('198.51.100.0/24'))
            _wait(lambda: sink.stats()['installed'] == 1,
                  'the retried install')
        self.assertEqual(len(failures), 1)
        self.assertEqual(sink.retries + sink.recovered >= 1, True)


class SelectRetryTestCase(EngineFixture):
    """E-5: a selection pass that raises is retried, not forgotten."""

    def test_a_failed_pass_is_retried(self):
        engine = self.make_engine()
        rib = engine.global_rib
        real = rib.drain
        calls = []

        async def flaky(batcher):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('injected selection failure')
            return await real(batcher)

        rib.drain = flaky
        with mock.patch.object(engine_mod, 'SELECT_RETRY_S', 0.05):
            engine.start()
            self.offer(engine, _route('198.51.100.0/24'))
            _wait(lambda: engine.sink.stats()['present'] == 1,
                  'the retried selection pass')
        self.assertGreaterEqual(len(calls), 2)


# --- E-6: start is all or nothing -------------------------------------------


class _Starting(ProtocolPlugin):
    name = 'starting'

    def __init__(self, fail=False):
        ProtocolPlugin.__init__(self)
        self.fail = fail
        self.started = 0
        self.stopped = 0

    def start(self, engine):
        if self.fail:
            raise RuntimeError('this plugin will not start')
        self.started += 1

    def stop(self):
        self.stopped += 1


class StartOrderingTestCase(EngineFixture):
    """E-6: running only once everything started; undone if anything fails."""

    def test_a_plugin_that_fails_to_start_leaves_nothing_running(self):
        good = _Starting()
        bad = _Starting(fail=True)
        bad.name = 'failing'
        engine = Engine(plugins=[good, bad], name='half-started')
        with self.assertRaises(RuntimeError):
            engine.start()
        self.assertFalse(engine.is_running())
        self.assertEqual((good.started, good.stopped), (1, 1))
        self.assertNotIn('half-started',
                         [t.name for t in threading.enumerate()])
        with self.assertRaises(UnavailableError):
            engine.submit(lambda: None)

    def test_a_plugin_starting_up_may_already_ask_for_selection(self):
        engine = self.make_engine()

        class Eager(_Starting):
            name = 'eager'

            def start(self, eng):
                eng.global_rib.offer(_route('198.51.100.0/24'))
                eng.schedule_select()

        engine.register_plugin(Eager())
        engine.start()
        _wait(lambda: engine.sink.stats()['present'] == 1,
              'selection asked for during start')


# --- E-4 / E-8: health ------------------------------------------------------


class HealthProbeTestCase(unittest.TestCase):
    """E-4 and E-8, on a monitor with no engine."""

    def setUp(self):
        self.loop = new_loop()
        self.addCleanup(self.loop.close)

    def test_a_probe_after_stop_does_not_rearm(self):
        # E-4: the probe used to reschedule itself whenever it had a loop.
        monitor = HealthMonitor(interval=10.0)
        monitor.start(self.loop)
        monitor.stop()
        monitor._probe()
        self.assertIsNone(monitor._handle)
        self.assertEqual(monitor.probes, 0)

    def _lagging_probe(self, monitor, lag_s):
        monitor._due = time.monotonic() - lag_s
        monitor._probe()

    def test_sustained_severe_lag_is_down_and_one_spike_is_not(self):
        monitor = HealthMonitor(interval=10.0, lag_threshold_ms=10.0)
        monitor._active = True
        self._lagging_probe(monitor, 0.2)
        self.assertEqual(monitor.loop_status(), DEGRADED)
        for _ in range(SUSTAIN_PROBES - 1):
            self._lagging_probe(monitor, 0.2)
        self.assertEqual(monitor.loop_status(), DOWN)
        self.assertEqual(monitor.document()['status'], DOWN)
        self._lagging_probe(monitor, 0.0)
        self.assertEqual(monitor.loop_status(), OK)

    def test_moderate_lag_on_every_probe_stays_degraded(self):
        monitor = HealthMonitor(interval=10.0, lag_threshold_ms=10.0)
        monitor._active = True
        for _ in range(SUSTAIN_PROBES * 3):
            self._lagging_probe(monitor, 0.05)
        self.assertEqual(monitor.loop_status(), DEGRADED)

    def test_a_loop_that_stopped_running_callbacks_is_down(self):
        monitor = HealthMonitor(interval=0.1, lag_threshold_ms=10.0)
        monitor._active = True
        monitor._due = time.monotonic() - 5.0
        self.assertEqual(monitor.loop_status(), DOWN)
        self.assertGreater(monitor.document()['loop']['stalled_ms'], 4000)

    def test_a_stopped_monitor_is_never_stalled(self):
        monitor = HealthMonitor(interval=0.1)
        monitor._due = time.monotonic() - 5.0
        self.assertEqual(monitor.stalled_ms(), 0.0)
        self.assertEqual(monitor.loop_status(), OK)


# --- E-9 / E-10 --------------------------------------------------------------


class CallbackSnapshotTestCase(unittest.TestCase):
    """E-9: a callback unregistering itself does not skip the next one."""

    def test_every_callback_runs_once_even_if_one_unregisters(self):
        bus = EventBus()
        calls = []

        def first(event, payload):
            calls.append('first')
            bus.off(EV.CONFIG_CHANGE, first)

        def second(event, payload):
            calls.append('second')

        bus.on(EV.CONFIG_CHANGE, first)
        bus.on(EV.CONFIG_CHANGE, second)
        bus.publish(EV.CONFIG_CHANGE, {})
        self.assertEqual(calls, ['first', 'second'])
        bus.publish(EV.CONFIG_CHANGE, {})
        self.assertEqual(calls, ['first', 'second', 'second'])

    def test_a_callback_registered_during_publish_waits_for_the_next(self):
        bus = EventBus()
        calls = []

        def late(event, payload):
            calls.append('late')

        def registrar(event, payload):
            calls.append('registrar')
            bus.on(EV.CONFIG_CHANGE, late)

        bus.on(EV.CONFIG_CHANGE, registrar)
        bus.publish(EV.CONFIG_CHANGE, {})
        self.assertEqual(calls, ['registrar'])


class CommandDepthTestCase(unittest.TestCase):
    """E-10: a hand-over that fails is not counted as queued."""

    def test_a_closed_loop_refuses_without_inflating_the_depth(self):
        loop = new_loop()
        loop.close()
        engine = Engine(loop=loop)
        with self.assertRaises(UnavailableError):
            engine._submit_to_loop(lambda: 1)
        self.assertEqual(engine.command_depth(), 0)


# --- E-7: extended ack -------------------------------------------------------


def _ext_ack(seq, code, text):
    """An NLMSG_ERROR carrying an NLMSGERR_ATTR_MSG, request capped."""
    payload = text.encode('ascii') + b'\0'
    attr_len = 4 + len(payload)
    attr = struct.pack('=HH', attr_len, netlink.NLMSGERR_ATTR_MSG) + \
        payload + b'\0' * (netlink.rta_align(attr_len) - attr_len)
    echoed = struct.pack('=IHHII', 64, netlink.RTM_NEWROUTE, 0, seq, 0)
    body = struct.pack('=i', -code) + echoed + attr
    flags = netlink.NLM_F_CAPPED | netlink.NLM_F_ACK_TLVS
    return struct.pack('=IHHII', 16 + len(body), netlink.NLMSG_ERROR, flags,
                       seq, 0) + body


class ExtendedAckTestCase(unittest.TestCase):
    """E-7: the kernel's reason travels with the errno."""

    def test_the_message_is_parsed_from_a_capped_error(self):
        data = _ext_ack(7, errno.ENETUNREACH, 'Nexthop has invalid gateway')
        (_t, flags, _s, _p, body), = list(netlink.parse_messages(data))
        self.assertEqual(netlink.parse_ext_ack(body, flags),
                         'Nexthop has invalid gateway')

    def test_a_plain_error_has_no_message(self):
        body = struct.pack('=i', -errno.EINVAL) + b'\0' * 16
        self.assertIsNone(netlink.parse_ext_ack(body, 0))

    def test_a_lying_attribute_is_not_read_past_the_buffer(self):
        data = bytearray(_ext_ack(7, errno.EINVAL, 'x' * 40))
        struct.pack_into('=H', data, 16 + 4 + 16, 4000)
        (_t, flags, _s, _p, body), = list(netlink.parse_messages(bytes(data)))
        self.assertIsNone(netlink.parse_ext_ack(body, flags))

    def test_the_sink_records_and_reports_the_reason(self):
        sink, transport = open_sink(auto_ack=False)
        r = _route('198.51.100.0/24')
        sink.install(r)
        sink.flush()
        seq = transport.sent[-1]['seq']
        transport.queue_raw(_ext_ack(seq, errno.ENETUNREACH,
                                     'Nexthop has invalid gateway'))
        sink.flush()
        self.assertEqual(r.fib_state, T.FIB_STATE_ERROR)
        self.assertEqual(r.fib_errno, errno.ENETUNREACH)
        last = sink.stats()['last-error']
        self.assertEqual(last['message'], 'Nexthop has invalid gateway')
        self.assertEqual(last['errno'], errno.ENETUNREACH)


# --- B-1 ---------------------------------------------------------------------


class MaximumPathsTestCase(unittest.TestCase):
    """B-1: ECMP is refused until it can be installed."""

    def _section(self, **af):
        return {'65000': {'router-id': '10.0.0.1',
                          'address-family': {'ipv4': {'unicast': af}}}}

    def test_more_than_one_path_is_refused(self):
        for key in ('maximum-paths', 'maximum-paths-ibgp'):
            with self.assertRaises(ConfigError) as caught:
                bgp_plugin.BGPPlugin().prepare_config(
                    self._section(**{key: 4}), None)
            self.assertIn(key, caught.exception.as_dict()['path'])
            self.assertIn('ECMP', str(caught.exception))

    def test_one_path_is_accepted(self):
        bgp_plugin.BGPPlugin().prepare_config(
            self._section(**{'maximum-paths': 1}), None)


# --- L-7, live ---------------------------------------------------------------


class LocalNetworkTestCase(notify.LiveFixture):
    """L-7: a ``network`` statement is advertised, never installed."""

    def test_only_learned_routes_reach_the_core_and_health_stays_ok(self):
        instance = {'address-family': {'ipv4': {'unicast': {
            'network': {'203.0.113.0/24': {}}}}}}
        self.start_engine(instance_extra=instance, neighbor_extra={
            'address-family': {'ipv4': {'unicast': {'activate': True}}}})
        s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        s.handshake(hold=90)
        self.wait_state(fsm_mod.ESTABLISHED)
        s.send(raw.update(attrs=raw.origin_igp() +
                          raw.as_path(notify.SPEAKER_AS) +
                          raw.next_hop(notify.LOOPBACK),
                          nlri=b'\x18\xc6\x33\x64'))

        def core_prefixes():
            return self.engine.submit(lambda: sorted(
                r.prefix.to_str()
                for r in self.engine.global_rib.routes(AFI_IP))).result(5)

        self.wait_until(lambda: core_prefixes() == ['198.51.100.0/24'],
                        'the learned route reaching the core (it has %s)'
                        % core_prefixes())
        locrib = self.engine.submit(
            lambda: self.engine.plugin('bgp').health()).result(5)
        self.assertNotIn('203.0.113.0/24', core_prefixes())
        self.assertIn('local-unoffered', repr(locrib))
        self.assertEqual(self.engine.health()['status'], OK)


if __name__ == '__main__':
    unittest.main()
