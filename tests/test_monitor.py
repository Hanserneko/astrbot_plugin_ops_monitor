from __future__ import annotations

import asyncio
import contextlib
import io
import json
import ssl
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

import aiohttp
import asyncssh
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core.alerts import AlertEngine, StateStore
from core.config import ALERT_TEMPLATE, parse_settings
from core.probes import Observation, Prober, metrics_script
from core.service import MonitorService


def http_target(**overrides):
    raw = {"__template_key": "http", "id": "web", "url": "http://127.0.0.1", **overrides}
    settings = parse_settings({"recipients": ["group-a", "group-b"], "monitors": [raw]})
    if settings.errors:
        raise AssertionError(settings.errors)
    return settings.targets[0]


def ssh_target(**overrides):
    raw = {
        "__template_key": "ssh",
        "id": "host",
        "host": "127.0.0.1",
        "username": "monitor",
        "password": "test-only",
        **overrides,
    }
    settings = parse_settings({"monitors": [raw]})
    if settings.errors:
        raise AssertionError(settings.errors)
    return settings.targets[0]


def observation(bad=True, key="availability"):
    return Observation(key, "服务可用性", bad, "异常" if bad else "正常")


class ConfigTests(unittest.TestCase):
    def test_schema_defaults_and_inheritance(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "_conf_schema.json").read_text(encoding="utf-8"))
        defaults = {key: value["default"] for key, value in schema["defaults"]["items"].items()}
        defaults["trigger_times"] = 7
        defaults["alert_template"] = "业务：{name} {count}"
        defaults["notify_recovery"] = False
        monitors = []
        for kind, template in schema["monitors"]["templates"].items():
            raw = {key: value["default"] for key, value in template["items"].items()}
            raw.update(
                id=kind,
                __template_key=kind,
                host="localhost",
                username="monitor",
                url="http://localhost",
            )
            monitors.append(raw)
        settings = parse_settings({"defaults": defaults, "monitors": monitors})
        self.assertFalse(settings.errors)
        for target in settings.targets:
            self.assertEqual(target.policy.trigger_times, 7)
            self.assertEqual(target.policy.alert_template, "业务：{name} {count}")
            self.assertFalse(target.policy.notify_recovery)

    def test_isolate_invalid_monitors(self):
        bad = [
            {"id": "dup", "kind": "http", "url": "http://localhost"},
            {"id": "dup", "kind": "http", "url": "http://localhost"},
            {"id": "bad", "kind": "http", "url": "file:///etc/passwd"},
            {
                "id": "bad2",
                "kind": "http",
                "url": "http://localhost",
                "alert_template": "{name.__class__}",
            },
            {"id": "bad3", "kind": "http", "url": "http://localhost", "trigger_times": 2.5},
            {"id": "bad4", "kind": "http", "url": "http://localhost", "timeout": float("nan")},
            {
                "id": "bad5",
                "kind": "http",
                "url": "http://localhost",
                "count_mode": "window",
                "trigger_times": 6,
                "window_size": 5,
            },
        ]
        settings = parse_settings({"monitors": bad})
        self.assertEqual(len(settings.targets), 1)
        self.assertEqual(len(settings.errors), 6)

    def test_example_configuration(self):
        root = Path(__file__).resolve().parents[1]
        settings = parse_settings(
            json.loads((root / "config.example.json").read_text(encoding="utf-8"))
        )
        self.assertEqual(len(settings.targets), 2)
        self.assertFalse(settings.errors)
        self.assertIn("运维", ALERT_TEMPLATE)


class AlertTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.messages = []
        self.fail = set()

        async def sender(recipient, text):
            if recipient in self.fail:
                raise RuntimeError("offline")
            self.messages.append((recipient, text))

        self.sender = sender
        self.store = StateStore(Path(self.temp.name) / "state.json")

    def engine(self, target):
        return AlertEngine([target], self.sender, self.store)

    async def test_consecutive_recovery_and_new_incident(self):
        target = http_target(trigger_times=3, recovery_times=2, repeat_interval=0)
        engine = self.engine(target)
        for now, bad in enumerate([True, True, False, True, True], 1):
            await engine.observe(target, observation(bad), now)
        self.assertFalse(self.messages)
        await engine.observe(target, observation(), 6)
        self.assertEqual(len(self.messages), 2)
        await engine.observe(target, observation(), 7)
        self.assertEqual(len(self.messages), 2)
        await engine.observe(target, observation(False), 8)
        self.assertEqual(len(self.messages), 2)
        await engine.observe(target, observation(False), 9)
        self.assertEqual(len(self.messages), 4)
        self.assertIn("恢复", self.messages[-1][1])
        for now in [10, 11, 12]:
            await engine.observe(target, observation(), now)
        self.assertEqual(len(self.messages), 6)

    async def test_window_count(self):
        target = http_target(count_mode="window", window_size=5, trigger_times=3, recovery_times=3)
        engine = self.engine(target)
        for now, bad in enumerate([True, False, True, False], 1):
            await engine.observe(target, observation(bad), now)
        self.assertFalse(self.messages)
        await engine.observe(target, observation(True), 5)
        self.assertEqual(len(self.messages), 2)

    async def test_window_duration_starts_at_first_bad_sample(self):
        target = http_target(
            count_mode="window",
            window_size=5,
            trigger_times=2,
            recovery_times=3,
            alert_template="{duration}",
        )
        engine = self.engine(target)
        await engine.observe(target, observation(False), 100)
        await engine.observe(target, observation(), 101)
        await engine.observe(target, observation(), 102)
        self.assertEqual(self.messages[0][1], "1")

    async def test_independent_metrics_and_missing_samples(self):
        target = http_target(trigger_times=2)
        engine = self.engine(target)
        await engine.observe(target, observation(True, "cpu"), 1)
        await engine.observe(target, observation(True, "memory"), 2)
        self.assertFalse(self.messages)
        await engine.observe(target, observation(True, "cpu"), 3)
        self.assertEqual(len(self.messages), 2)
        await engine.observe(target, observation(True, "availability"), 4)
        self.assertTrue(engine.states["web:cpu"]["active"])

    async def test_partial_delivery_retries_and_recovery_retries(self):
        target = http_target(trigger_times=1, recovery_times=1, repeat_interval=0)
        engine = self.engine(target)
        self.fail.add("group-b")
        await engine.observe(target, observation(), 1)
        self.assertEqual([r for r, _ in self.messages], ["group-a"])
        self.fail.clear()
        await engine.observe(target, observation(), 2)
        self.assertEqual([r for r, _ in self.messages], ["group-a", "group-b"])
        self.fail.add("group-b")
        await engine.observe(target, observation(False), 3)
        self.fail.clear()
        await engine.observe(target, observation(False), 4)
        self.assertEqual(
            [r for r, _ in self.messages], ["group-a", "group-b", "group-a", "group-b"]
        )

    async def test_restart_keeps_count_and_recipient_ack(self):
        target = http_target(trigger_times=2, repeat_interval=0)
        engine = self.engine(target)
        await engine.observe(target, observation(), 1)
        engine = self.engine(target)
        await engine.observe(target, observation(), 2)
        self.assertEqual(len(self.messages), 2)
        engine = self.engine(target)
        await engine.observe(target, observation(), 3)
        self.assertEqual(len(self.messages), 2)

    async def test_repeat_interval_and_duration(self):
        target = http_target(
            trigger_times=1,
            recovery_times=2,
            repeat_interval=10,
            alert_template="{name}:{duration}",
        )
        engine = self.engine(target)
        await engine.observe(target, observation(), 100)
        await engine.observe(target, observation(False), 101)
        await engine.observe(target, observation(), 109)
        self.assertEqual(len(self.messages), 2)
        await engine.observe(target, observation(), 110)
        self.assertEqual(len(self.messages), 4)
        self.assertTrue(self.messages[-1][1].endswith(":10"))

    async def test_recovery_only_to_notified_groups(self):
        target = http_target(trigger_times=1, recovery_times=1)
        engine = self.engine(target)
        self.fail.add("group-b")
        await engine.observe(target, observation(), 1)
        self.fail.clear()
        await engine.observe(target, observation(False), 2)
        self.assertEqual([r for r, _ in self.messages], ["group-a", "group-a"])

    async def test_configuration_change_resets_only_that_target(self):
        target = http_target(trigger_times=2)
        await self.engine(target).observe(target, observation(), 1)
        changed = http_target(trigger_times=3)
        self.assertEqual(self.engine(changed).states, {})

    async def test_cancellation_keeps_successful_recipient_ack(self):
        target = http_target(trigger_times=1, repeat_interval=0)
        entered = asyncio.Event()

        async def sender(recipient, text):
            if recipient == "group-b":
                entered.set()
                await asyncio.Event().wait()
            self.messages.append((recipient, text))

        engine = AlertEngine([target], sender, self.store)
        task = asyncio.create_task(engine.observe(target, observation(), 1))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        engine = self.engine(target)
        await engine.observe(target, observation(), 2)
        self.assertEqual([r for r, _ in self.messages], ["group-a", "group-b"])


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.session = aiohttp.ClientSession()
        self.addAsyncCleanup(self.session.close)
        self.prober = Prober(self.session)

    async def http_server(self, handler, tls=False):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        context = None
        if tls:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(UTC)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            root = Path(self.temp.name)
            (root / "key.pem").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            (root / "cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / "cert.pem", root / "key.pem")
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"{'https' if tls else 'http'}://127.0.0.1:{port}"

    async def test_http_headers_status_body_and_latency(self):
        async def handler(request):
            self.assertEqual(request.headers["Authorization"], "Bearer test-only")
            return web.Response(text="healthy", status=201)

        url = await self.http_server(handler)
        result = await self.prober.run(
            http_target(
                url=url,
                expected_status="200,201",
                body_contains="healthy",
                headers_json='{"Authorization":"Bearer test-only"}',
                latency_threshold_ms=0.001,
            )
        )
        self.assertTrue(result.ok)
        self.assertTrue(result.observations[-1].bad)
        self.assertNotIn("Bearer", repr(result))

    async def test_http_status_and_body_failure(self):
        async def handler(request):
            return web.Response(text="no keyword", status=503)

        url = await self.http_server(handler)
        self.assertFalse((await self.prober.run(http_target(url=url))).ok)
        result = await self.prober.run(
            http_target(url=url, expected_status="503", body_contains="healthy")
        )
        self.assertFalse(result.ok)

    async def test_https_certificate_verification(self):
        async def handler(request):
            return web.Response(text="ok")

        url = await self.http_server(handler, tls=True)
        self.assertFalse((await self.prober.run(http_target(url=url))).ok)
        self.assertTrue((await self.prober.run(http_target(url=url, verify_tls=False))).ok)

    async def test_redirect_and_timeout(self):
        async def handler(request):
            if request.path == "/slow":
                await asyncio.sleep(1.2)
            if request.path == "/redirect":
                raise web.HTTPFound("/healthy")
            return web.Response(text="ok")

        url = await self.http_server(handler)
        self.assertTrue((await self.prober.run(http_target(url=url + "/redirect"))).ok)
        self.assertFalse(
            (await self.prober.run(http_target(url=url + "/redirect", follow_redirects=False))).ok
        )
        result = await self.prober.run(http_target(url=url + "/slow?token=private", timeout=1))
        self.assertFalse(result.ok)
        self.assertIn("超时", result.detail)
        self.assertNotIn("private", repr(result))

    async def test_http_stream_body_limit(self):
        async def handler(request):
            return web.Response(body=b"a" * 65536 + b"outside-limit")

        url = await self.http_server(handler)
        self.assertFalse(
            (await self.prober.run(http_target(url=url, body_contains="outside-limit"))).ok
        )

    async def ssh_server(self, output="", exit_status=0, delay=0):
        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return username == "monitor" and password == "test-only"

        async def process_handler(process):
            self.assertEqual(process.command, "python3 -")
            script = await process.stdin.read()
            self.assertIn("/proc/stat", script)
            await asyncio.sleep(delay)
            process.stdout.write(output)
            process.exit(exit_status)

        host_key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=process_handler
        )
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        # addCleanup 与 addAsyncCleanup 逆序执行，先关闭 listener 再等待。
        port = server.get_port()
        known_hosts = Path(self.temp.name) / "known_hosts"
        known_hosts.write_text(
            f"[127.0.0.1]:{port} " + host_key.export_public_key().decode(), encoding="utf-8"
        )
        return port, str(known_hosts)

    async def test_ssh_real_login_and_metric_thresholds(self):
        data = {
            "cpu_percent": 91,
            "memory_percent": 92,
            "load1": 2,
            "uptime_seconds": 100,
            "rx_bytes": 1000,
            "tx_bytes": 500,
            "disks": [{"path": "/", "percent": 95}],
        }
        port, hosts = await self.ssh_server(json.dumps(data))
        result = await self.prober.run(ssh_target(port=port, known_hosts=hosts))
        self.assertTrue(result.ok)
        self.assertEqual(result.metrics["cpu_percent"], 91)
        self.assertEqual(
            {o.key for o in result.observations if o.bad},
            {"cpu_percent", "memory_percent", "disk:/"},
        )

    async def test_ssh_bad_credentials_and_host_key(self):
        port, hosts = await self.ssh_server()
        result = await self.prober.run(
            ssh_target(port=port, known_hosts=hosts, password="wrong", collect_metrics=False)
        )
        self.assertFalse(result.ok)
        self.assertIn("认证失败", result.detail)
        empty = Path(self.temp.name) / "empty_hosts"
        empty.touch()
        result = await self.prober.run(
            ssh_target(port=port, known_hosts=str(empty), collect_metrics=False)
        )
        self.assertFalse(result.ok)
        self.assertIn("主机密钥", result.detail)
        result = await self.prober.run(
            ssh_target(port=port, verify_host_key=False, collect_metrics=False)
        )
        self.assertTrue(result.ok)

    async def test_ssh_collection_failure_is_not_offline(self):
        port, hosts = await self.ssh_server("not JSON", exit_status=127)
        result = await self.prober.run(ssh_target(port=port, known_hosts=hosts))
        self.assertTrue(result.ok)
        self.assertEqual([o.key for o in result.observations if o.bad], ["collection"])
        self.assertFalse(result.metrics)

    async def test_service_manual_check_does_not_count_and_stop_closes(self):
        async def handler(request):
            return web.Response(status=503)

        url = await self.http_server(handler)
        settings = parse_settings({"monitors": [{"id": "web", "kind": "http", "url": url}]})

        async def sender(recipient, text):
            raise AssertionError("should not send")

        service = MonitorService(settings, sender, Path(self.temp.name))
        # 使用同样的真实客户端但不启动后台轮询，手动检查不进入告警引擎。
        service.prober = self.prober
        result = await service.sample(settings.targets[0], evaluate=False)
        self.assertFalse(result.ok)
        self.assertFalse(service.engine.states)
        service.prober = None
        await service.start()
        await asyncio.sleep(0.1)
        self.assertEqual(service.engine.states["web:availability"]["count"], 1)
        session = service.session
        await service.stop()
        self.assertTrue(session.closed)
        self.assertFalse(service.tasks)


class CollectionScriptTests(unittest.TestCase):
    def test_remote_script_calculation_and_quoted_paths(self):
        path = "/data/a'\";echo never-executed"
        script = metrics_script((path,))
        compile(script, "remote", "exec")
        cpu = iter(["cpu 10 0 0 90 0 0 0 0\n", "cpu 20 0 0 90 0 0 0 0\n"])

        def fake_open(name, *args, **kwargs):
            data = {
                "/proc/meminfo": "MemTotal: 100 kB\nMemAvailable: 20 kB\n",
                "/proc/uptime": "123.4 0",
                "/proc/net/dev": "eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n",
            }
            return io.StringIO(next(cpu) if name == "/proc/stat" else data[name])

        class Stat:
            f_blocks = 100
            f_bfree = 20
            f_bavail = 10
            f_frsize = 4096

        output = io.StringIO()
        with (
            patch("builtins.open", side_effect=fake_open),
            patch("os.statvfs", return_value=Stat(), create=True) as stat,
            patch("os.getloadavg", return_value=(2, 1, 1), create=True),
            patch("time.sleep"),
            contextlib.redirect_stdout(output),
        ):
            exec(script, {})
        data = json.loads(output.getvalue())
        self.assertEqual(data["cpu_percent"], 100)
        self.assertEqual(data["memory_percent"], 80)
        self.assertAlmostEqual(data["disks"][0]["percent"], 88.89)
        self.assertEqual(data["rx_bytes"], 100)
        stat.assert_called_once_with(path)


if __name__ == "__main__":
    unittest.main()
