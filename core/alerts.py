from __future__ import annotations

import json
import logging
import math
import os
import time
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Target
from .probes import Observation
from .silence import MAX_MUTE_SECONDS

log = logging.getLogger(__name__)


class StateStore:
    """单个事件循环内写入；临时文件 + 替换，避免留下半个 JSON。"""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1 or not isinstance(data.get("states"), dict):
                raise ValueError("状态版本不兼容")
            return data
        except (OSError, ValueError, AttributeError) as exc:
            # 损坏状态应显式报告，不能让监控悄悄停用。
            log.error("运维告警状态读取失败，将重新计数：%s", type(exc).__name__)
            return {}

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, allow_nan=False)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(self.path)


def new_state() -> dict:
    return {
        "count": 0,
        "samples": [],
        "healthy": 0,
        "active": False,
        "started": 0,
        "last_sent": {},
        "pending_recovery": [],
    }


class AlertEngine:
    def __init__(
        self,
        targets: list[Target],
        sender: Callable[[str, str], Awaitable[None]],
        store: StateStore,
    ):
        self.sender = sender
        self.store = store
        self.timezone = timezone(timedelta(hours=8), "CST")
        self.states: dict[str, dict] = {}
        self.fingerprints = {target.id: target.fingerprint for target in targets}
        self.history = deque(maxlen=100)
        saved = store.load()
        self.silences: dict[str, float] = {}
        silences = saved.get("silences", {})
        if isinstance(silences, dict):
            for scope, deadline in silences.items():
                if (
                    (scope == "*" or scope in self.fingerprints)
                    and isinstance(deadline, (int, float))
                    and not isinstance(deadline, bool)
                    and math.isfinite(deadline)
                ):
                    self.silences[scope] = deadline
        previous = saved.get("fingerprints", {})
        for key, state in saved.get("states", {}).items():
            ident = key.split(":", 1)[0]
            if ident not in self.fingerprints or previous.get(ident) != self.fingerprints[ident]:
                continue
            if isinstance(state, dict) and all(k in state for k in new_state()):
                self.states[key] = state
        self.history.extend(saved.get("history", [])[-100:])

    def persist(self, strict: bool = False) -> None:
        try:
            self.store.save(
                {
                    "version": 1,
                    "fingerprints": self.fingerprints,
                    "states": self.states,
                    "history": list(self.history),
                    "silences": self.silences,
                }
            )
        except (OSError, ValueError) as exc:
            log.error("运维告警状态保存失败：%s", type(exc).__name__)
            if strict:
                raise

    def mute(self, ident: str, seconds: int, now: float | None = None) -> float:
        if ident and ident not in self.fingerprints:
            raise ValueError(f"未找到监控项：{ident}")
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, int)
            or not 1 <= seconds <= MAX_MUTE_SECONDS
        ):
            raise ValueError("屏蔽时长必须在 1 秒到 30 天之间")
        deadline = (time.time() if now is None else now) + seconds
        self.silences[ident or "*"] = deadline
        for key, state in self.states.items():
            if not ident or key.split(":", 1)[0] == ident:
                state["resend_after_mute"] = True
                # 已恢复但尚未发出的消息不在屏蔽结束后补发。
                state["pending_recovery"] = []
        self.persist(strict=True)
        return deadline

    def unmute(self, ident: str = "") -> None:
        self.silences.pop(ident or "*", None)
        self.persist(strict=True)

    def active_mutes(self, now: float | None = None) -> dict[str, float]:
        now = time.time() if now is None else now
        return {scope: deadline for scope, deadline in self.silences.items() if deadline > now}

    def muted_until(self, ident: str, now: float | None = None) -> float:
        active = self.active_mutes(now)
        return max(active.get("*", 0), active.get(ident, 0))

    async def _deliver(
        self,
        target: Target,
        observation: Observation,
        state: dict,
        recipient: str,
        recovery: bool,
        now: float,
    ) -> bool:
        values = {
            "id": target.id,
            "name": target.name,
            "kind": target.kind,
            "event": observation.event,
            "event_key": observation.key,
            "detail": observation.detail,
            "value": observation.value,
            "threshold": observation.threshold,
            "count": state["count"],
            "trigger_times": target.policy.trigger_times,
            "time": datetime.fromtimestamp(now, self.timezone).strftime("%Y-%m-%d %H:%M:%S %Z"),
            "duration": max(0, int(now - state["started"])),
            "status": "恢复" if recovery else "告警",
        }
        template = target.policy.recovery_template if recovery else target.policy.alert_template
        try:
            await self.sender(recipient, template.format_map(values))
        except Exception as exc:
            log.warning(
                "运维通知发送失败：target=%s event=%s error=%s",
                target.id,
                observation.key,
                type(exc).__name__,
            )
            self.history.append(
                {
                    "time": now,
                    "target": target.id,
                    "event": observation.key,
                    "status": "发送失败",
                    "recipient": recipient,
                }
            )
            return False
        self.history.append(
            {
                "time": now,
                "target": target.id,
                "event": observation.key,
                "status": values["status"],
                "recipient": recipient,
            }
        )
        return True

    async def observe(self, target: Target, observation: Observation, now: float) -> None:
        state = self.states.setdefault(f"{target.id}:{observation.key}", new_state())
        policy = target.policy
        recipients = target.recipients
        muted = bool(self.muted_until(target.id, now))
        if muted:
            state["resend_after_mute"] = True
        elif observation.bad and state.pop("resend_after_mute", False):
            # 屏蔽后仍异常，下一次满足阈值的采样重新通知，包含仅首次告警策略。
            state["last_sent"] = {}
        state["last_sent"] = {k: v for k, v in state["last_sent"].items() if k in recipients}
        state["pending_recovery"] = [k for k in state["pending_recovery"] if k in recipients]

        if observation.bad:
            if not state["active"] and not state["count"]:
                state["started"] = now
            state["healthy"] = 0
            if policy.count_mode == "consecutive":
                state["count"] = min(1000000, state["count"] + 1)
            else:
                state["samples"] = (state["samples"] + [True])[-policy.window_size :]
                state["count"] = sum(state["samples"])
            if state["count"] >= policy.trigger_times:
                state["active"] = True
            # 新故障开始时，尚未送达的旧恢复消息已过时。
            state["pending_recovery"] = []
            if state["active"] and not muted:
                for recipient in recipients:
                    if self.muted_until(target.id, now):
                        break
                    last = state["last_sent"].get(recipient)
                    if last is None or (
                        policy.repeat_interval > 0 and now - last >= policy.repeat_interval
                    ):
                        if await self._deliver(target, observation, state, recipient, False, now):
                            state["last_sent"][recipient] = now
                            self.persist()
        else:
            state["healthy"] = min(policy.recovery_times, state["healthy"] + 1)
            if policy.count_mode == "window":
                state["samples"] = (state["samples"] + [False])[-policy.window_size :]
                state["count"] = sum(state["samples"])
            else:
                state["count"] = 0
            if state["healthy"] >= policy.recovery_times:
                if state["active"]:
                    state["active"] = False
                    if policy.notify_recovery and not muted:
                        state["pending_recovery"] = list(state["last_sent"])
                    state["last_sent"] = {}
                state["samples"] = []
                state["count"] = 0
                if muted:
                    state["pending_recovery"] = []
                for recipient in list(state["pending_recovery"]):
                    if self.muted_until(target.id, now):
                        state["pending_recovery"] = []
                        break
                    if await self._deliver(target, observation, state, recipient, True, now):
                        # 等待平台发送期间，管理员可能已开始屏蔽并清空待发恢复通知。
                        if recipient in state["pending_recovery"]:
                            state["pending_recovery"].remove(recipient)
                        self.persist()
        # 每个事件确认后落盘，部分群发送失败时不会重复通知已成功的群。
        self.persist()
