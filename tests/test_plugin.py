"""聊天适配层测试；用接口替身隔离 AstrBot 及平台依赖。"""

from __future__ import annotations

import importlib.util
import logging
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


class Config(dict):
    def save_config(self):
        self.saved = True


class Chain:
    def message(self, text):
        self.text = text
        return self


class Context:
    def __init__(self):
        self.messages = []
        self.accept = True

    async def send_message(self, recipient, chain):
        self.messages.append((recipient, chain.text))
        return self.accept


class Star:
    def __init__(self, context):
        self.context = context


class Event:
    unified_msg_origin = "platform:GroupMessage:123"

    def get_group_id(self):
        return "123"


def load_plugin(data_dir):
    def decorator(*args):
        return lambda function: function

    def permission(*args):
        def decorate(function):
            function.admin_filter = True
            return function

        return decorate

    modules = {
        name: ModuleType(name)
        for name in (
            "astrbot",
            "astrbot.api",
            "astrbot.api.event",
            "astrbot.api.star",
            "astrbot.core",
            "astrbot.core.utils",
            "astrbot.core.utils.astrbot_path",
        )
    }
    modules["astrbot.api"].AstrBotConfig = Config
    modules["astrbot.api"].logger = logging.getLogger("plugin-test")
    modules["astrbot.api.event"].AstrMessageEvent = Event
    modules["astrbot.api.event"].MessageChain = Chain
    modules["astrbot.api.event"].filter = SimpleNamespace(
        command=decorator, permission_type=permission, PermissionType=SimpleNamespace(ADMIN="admin")
    )
    modules["astrbot.api.star"].Context = Context
    modules["astrbot.api.star"].Star = Star
    modules["astrbot.api.star"].register = decorator
    modules["astrbot.core.utils.astrbot_path"].get_astrbot_plugin_data_path = lambda: data_dir
    path = Path(__file__).resolve().parents[1] / "main.py"
    package = ModuleType("astrbot_plugin_ops_monitor")
    package.__path__ = [str(path.parent)]
    modules[package.__name__] = package
    spec = importlib.util.spec_from_file_location("astrbot_plugin_ops_monitor._test_entry", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module.OpsMonitorPlugin


class PluginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        plugin_class = load_plugin(self.temp.name)
        self.config = Config(
            enabled=False,
            recipients=[],
            monitors=[{"id": "website", "kind": "http", "url": "http://localhost"}],
        )
        self.context = Context()
        self.plugin = plugin_class(self.context, self.config)
        await self.plugin.initialize()
        self.addAsyncCleanup(self.plugin.terminate)

    async def test_group_binding_is_persisted_and_deduplicated(self):
        await self.plugin._command(Event(), "bind", "")
        await self.plugin._command(Event(), "bind", "")
        self.assertEqual(self.config["recipients"], [Event.unified_msg_origin])
        self.assertTrue(self.config.saved)
        self.assertEqual(
            self.plugin.service.settings.targets[0].recipients, (Event.unified_msg_origin,)
        )
        await self.plugin._command(Event(), "unbind", "")
        self.assertEqual(self.config["recipients"], [])

    async def test_target_group_binding_overrides_global(self):
        self.config["recipients"] = ["global:GroupMessage:456"]
        await self.plugin._command(Event(), "bind", "website")
        self.assertEqual(
            self.plugin.service.settings.targets[0].recipients, (Event.unified_msg_origin,)
        )
        await self.plugin._command(Event(), "unbind", "website")
        self.assertEqual(
            self.plugin.service.settings.targets[0].recipients, ("global:GroupMessage:456",)
        )

    async def test_private_chat_binding_test_and_unbind(self):
        event = Event()
        event.get_group_id = lambda: ""
        event.unified_msg_origin = "platform:FriendMessage:789"
        response = await self.plugin._command(event, "bind", "")
        self.assertIn("已绑定", response)
        self.assertEqual(self.config["recipients"], [event.unified_msg_origin])
        self.assertTrue(self.config.saved)
        await self.plugin._command(event, "bind", "")
        self.assertEqual(self.config["recipients"], [event.unified_msg_origin])
        response = await self.plugin._command(event, "umo", "")
        self.assertIn(event.unified_msg_origin, response)
        response = await self.plugin._command(event, "test", "")
        self.assertIn("成功 1", response)
        self.assertEqual(self.context.messages[0][0], event.unified_msg_origin)
        await self.plugin._command(event, "unbind", "")
        self.assertEqual(self.config["recipients"], [])

    async def test_group_and_private_recipients_can_coexist(self):
        private = Event()
        private.get_group_id = lambda: ""
        private.unified_msg_origin = "platform:FriendMessage:789"
        await self.plugin._command(Event(), "bind", "")
        await self.plugin._command(private, "bind", "")
        response = await self.plugin._command(private, "test", "")
        self.assertIn("成功 2", response)
        self.assertEqual(
            {r for r, _ in self.context.messages},
            {Event.unified_msg_origin, private.unified_msg_origin},
        )
        await self.plugin._command(private, "unbind", "")
        self.assertEqual(self.config["recipients"], [Event.unified_msg_origin])

    async def test_private_target_binding_overrides_and_restores_global(self):
        private = Event()
        private.get_group_id = lambda: ""
        private.unified_msg_origin = "platform:FriendMessage:789"
        await self.plugin._command(Event(), "bind", "")
        await self.plugin._command(private, "bind", "website")
        self.assertEqual(
            self.plugin.service.settings.targets[0].recipients, (private.unified_msg_origin,)
        )
        await self.plugin._command(private, "test", "website")
        self.assertEqual(self.context.messages[0][0], private.unified_msg_origin)
        await self.plugin._command(private, "unbind", "website")
        self.assertEqual(
            self.plugin.service.settings.targets[0].recipients, (Event.unified_msg_origin,)
        )

    async def test_platform_false_is_a_failure(self):
        self.context.accept = False
        with self.assertRaises(RuntimeError):
            await self.plugin._send("missing:GroupMessage:123", "test")

    async def test_test_command_and_admin_filter_registration(self):
        await self.plugin._command(Event(), "bind", "")
        response = await self.plugin._command(Event(), "test", "")
        self.assertIn("成功 1", response)
        self.assertEqual(self.context.messages[0][0], Event.unified_msg_origin)
        self.assertTrue(self.plugin.ops.admin_filter)

    async def test_mute_commands_status_and_reload(self):
        started = time.time()
        response = await self.plugin._command(Event(), "mute", "")
        self.assertIn("已屏蔽全局", response)
        deadline = self.plugin.service.engine.silences["*"]
        self.assertGreaterEqual(deadline, started + 7200)
        self.assertLessEqual(deadline, time.time() + 7200)
        self.assertIn("全局", await self.plugin._command(Event(), "muted", ""))
        self.assertIn("告警已屏蔽", self.plugin.service.status_text())
        await self.plugin._command(Event(), "reload", "")
        self.assertEqual(self.plugin.service.engine.silences["*"], deadline)
        await self.plugin._command(Event(), "unmute", "")
        self.assertIn("没有临时屏蔽", await self.plugin._command(Event(), "muted", ""))

    async def test_target_mute_and_manual_test(self):
        await self.plugin._command(Event(), "bind", "")
        response = await self.plugin._command(Event(), "mute", "2h", "website")
        self.assertIn("监控项 website", response)
        self.assertNotIn("*", self.plugin.service.engine.silences)
        response = await self.plugin._command(Event(), "test", "website")
        self.assertIn("成功 1", response)
        await self.plugin._command(Event(), "unmute", "website")
        self.assertFalse(self.plugin.service.engine.active_mutes())

    async def test_invalid_mute_input_does_not_change_state(self):
        for duration, ident in (("-2h", ""), ("0", ""), ("forever", ""), ("30m", "missing")):
            response = await self.plugin._command(Event(), "mute", duration, ident)
            self.assertNotIn("已屏蔽", response)
            self.assertFalse(self.plugin.service.engine.silences)
