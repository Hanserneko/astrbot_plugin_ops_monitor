from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.alerts import AlertEngine, StateStore
from core.config import parse_settings
from core.probes import Observation
from core.silence import parse_mute_duration


class DurationTests(unittest.TestCase):
    def test_supported_durations(self):
        for value, seconds in (
            ("30m", 1800),
            ("2H", 7200),
            ("1d", 86400),
            ("1h30m", 5400),
            ("30", 1800),
            ("1s", 1),
            ("30d", 2592000),
        ):
            with self.subTest(value=value):
                self.assertEqual(parse_mute_duration(value), seconds)

    def test_invalid_durations(self):
        for value in ("", "0", "-5m", "1.5h", "31d", "1h garbage", "forever", "1h 30m", "１２m"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_mute_duration(value)


class SilenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        settings = parse_settings(
            {
                "recipients": ["platform:GroupMessage:1", "platform:FriendMessage:2"],
                "defaults": {"trigger_times": 2, "recovery_times": 1, "repeat_interval": 0},
                "monitors": [
                    {"id": ident, "kind": "http", "url": "http://localhost"}
                    for ident in ("one", "two")
                ],
            }
        )
        self.targets = settings.targets
        self.messages = []
        self.store = StateStore(Path(self.temp.name) / "state.json")
        self.engine = AlertEngine(self.targets, self.sender, self.store)

    async def sender(self, recipient, text):
        self.messages.append((recipient, text))

    async def sample(self, bad, now, target=0):
        await self.engine.observe(
            self.targets[target],
            Observation("availability", "可用性", bad, "异常" if bad else "正常"),
            now,
        )

    async def test_global_mute_keeps_count_and_expires_without_restart(self):
        self.engine.mute("", 10, now=100)
        await self.sample(True, 101)
        await self.sample(True, 102)
        self.assertFalse(self.messages)
        self.assertEqual(self.engine.states["one:availability"]["count"], 2)
        self.assertTrue(self.engine.states["one:availability"]["active"])
        await self.sample(True, 110)
        self.assertEqual(len(self.messages), 2)
        await self.sample(True, 111)
        self.assertEqual(len(self.messages), 2)
        self.assertEqual(self.engine.active_mutes(now=110), {})

    async def test_target_mute_does_not_suppress_other_target(self):
        self.engine.mute("one", 10, now=100)
        for now in (101, 102):
            await self.sample(True, now)
            await self.sample(True, now, target=1)
        self.assertEqual(len(self.messages), 2)
        self.assertTrue(all("two" in text for _, text in self.messages))

    async def test_previously_alerted_incident_is_announced_again_after_mute(self):
        await self.sample(True, 98)
        await self.sample(True, 99)
        self.assertEqual(len(self.messages), 2)
        self.engine.mute("one", 10, now=100)
        await self.sample(True, 101)
        await self.sample(True, 110)
        self.assertEqual(len(self.messages), 4)

    async def test_recovery_during_mute_is_not_replayed(self):
        await self.sample(True, 98)
        await self.sample(True, 99)
        self.engine.mute("", 10, now=100)
        await self.sample(False, 101)
        self.assertFalse(self.engine.states["one:availability"]["active"])
        await self.sample(False, 110)
        self.assertEqual(len(self.messages), 2)
        await self.sample(True, 111)
        self.assertEqual(len(self.messages), 2)
        await self.sample(True, 112)
        self.assertEqual(len(self.messages), 4)

    async def test_restart_keeps_mute_and_count(self):
        self.engine.mute("one", 10, now=100)
        await self.sample(True, 101)
        self.engine = AlertEngine(self.targets, self.sender, self.store)
        self.assertEqual(self.engine.muted_until("one", now=102), 110)
        await self.sample(True, 102)
        self.assertFalse(self.messages)
        self.engine = AlertEngine(self.targets, self.sender, self.store)
        await self.sample(True, 110)
        self.assertEqual(len(self.messages), 2)

    async def test_overlapping_mutes_and_early_unmute(self):
        self.engine.mute("", 10, now=100)
        self.engine.mute("one", 20, now=100)
        self.engine.unmute()
        self.assertEqual(self.engine.muted_until("one", now=101), 120)
        self.assertEqual(self.engine.muted_until("two", now=101), 0)
        await self.sample(True, 101)
        await self.sample(True, 102)
        self.engine.unmute("one")
        await self.sample(True, 103)
        self.assertEqual(len(self.messages), 2)

    async def test_mute_between_recipient_deliveries_stops_next_send(self):
        async def sender(recipient, text):
            self.messages.append((recipient, text))
            self.engine.mute("one", 10, now=100)

        self.engine.sender = sender
        await self.sample(True, 100)
        await self.sample(True, 101)
        self.assertEqual(len(self.messages), 1)

    async def test_old_state_file_without_silences_is_compatible(self):
        await self.sample(True, 100)
        saved = self.store.load()
        saved.pop("silences")
        self.store.save(saved)
        self.engine = AlertEngine(self.targets, self.sender, self.store)
        await self.sample(True, 101)
        self.assertEqual(len(self.messages), 2)

    async def test_mute_during_recovery_delivery_cancels_remaining_recipients(self):
        await self.sample(True, 98)
        await self.sample(True, 99)

        async def sender(recipient, text):
            self.messages.append((recipient, text))
            self.engine.mute("one", 10, now=100)

        self.engine.sender = sender
        await self.sample(False, 100)
        self.assertEqual(len(self.messages), 3)
        self.assertFalse(self.engine.states["one:availability"]["pending_recovery"])
        await self.sample(False, 110)
        self.assertEqual(len(self.messages), 3)

    async def test_unknown_target_and_invalid_duration_are_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.mute("missing", 10)
        for seconds in (0, -1, 2592001, True, 1.5):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                self.engine.mute("", seconds)
        self.assertFalse(self.engine.silences)
