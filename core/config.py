from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from string import Formatter
from typing import Any
from urllib.parse import urlsplit

ALERT_TEMPLATE = "🔴 运维告警｜{name}\n事件：{event}\n详情：{detail}\n触发：{count}/{trigger_times} 次\n时间：{time}"
RECOVERY_TEMPLATE = (
    "🟢 运维恢复｜{name}\n事件：{event}\n详情：{detail}\n持续：{duration} 秒\n时间：{time}"
)
FIELDS = {
    "id",
    "name",
    "kind",
    "event",
    "event_key",
    "detail",
    "value",
    "threshold",
    "count",
    "trigger_times",
    "time",
    "duration",
    "status",
}


def number(raw: Any, key: str, default: float, lo: float, hi: float) -> float:
    value = float(raw.get(key, default))
    if not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError(f"{key} 必须在 {lo}~{hi} 之间")
    return value


def integer(raw: Any, key: str, default: int, lo: int, hi: int) -> int:
    value = number(raw, key, default, lo, hi)
    if not value.is_integer():
        raise ValueError(f"{key} 必须为整数")
    return int(value)


def strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(v, str) for v in value):
        raise ValueError("接收会话、磁盘路径等列表必须使用字符串数组")
    return tuple(dict.fromkeys(v.strip() for v in value if v.strip()))


def validate_template(template: str) -> str:
    for _, key, spec, conversion in Formatter().parse(template):
        if key is not None and (key not in FIELDS or spec or conversion):
            raise ValueError(f"不支持的消息占位符：{key}；仅支持 {{name}} 这样的简单占位符")
    return template


@dataclass(frozen=True)
class Policy:
    trigger_times: int = 3
    count_mode: str = "consecutive"
    window_size: int = 5
    recovery_times: int = 2
    repeat_interval: int = 1800
    notify_recovery: bool = True
    alert_template: str = ALERT_TEMPLATE
    recovery_template: str = RECOVERY_TEMPLATE

    @classmethod
    def parse(cls, raw: dict) -> Policy:
        mode = raw.get("count_mode", "consecutive")
        if mode not in {"consecutive", "window"}:
            raise ValueError("count_mode 仅支持 consecutive / window")
        trigger = integer(raw, "trigger_times", 3, 1, 1000)
        window = integer(raw, "window_size", 5, 1, 1000)
        if mode == "window" and window < trigger:
            raise ValueError("窗口大小不能小于触发次数")
        return cls(
            trigger,
            mode,
            window,
            integer(raw, "recovery_times", 2, 1, 1000),
            integer(raw, "repeat_interval", 1800, 0, 604800),
            bool(raw.get("notify_recovery", True)),
            validate_template(str(raw.get("alert_template") or ALERT_TEMPLATE)),
            validate_template(str(raw.get("recovery_template") or RECOVERY_TEMPLATE)),
        )


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    kind: str
    interval: float
    timeout: float
    recipients: tuple[str, ...]
    policy: Policy
    options: dict = field(repr=False)
    fingerprint: str = ""


@dataclass
class Settings:
    enabled: bool
    max_concurrency: int
    targets: list[Target]
    errors: list[str]


def parse_settings(config: dict) -> Settings:
    defaults = config.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ValueError("defaults 必须是对象")
    Policy.parse(defaults)
    global_recipients = strings(config.get("recipients", []))
    settings = Settings(
        bool(config.get("enabled", True)), integer(config, "max_concurrency", 5, 1, 50), [], []
    )
    seen = set()
    for index, raw in enumerate(config.get("monitors") or []):
        label = f"监控项 #{index + 1}"
        try:
            if not isinstance(raw, dict):
                raise ValueError("监控项必须是对象")
            if not raw.get("enabled", True):
                continue
            ident = str(raw.get("id", "")).strip()
            if not ident or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in ident
            ):
                raise ValueError("id 只能包含字母、数字、下划线和短横线，且不能为空")
            label = ident
            if ident in seen:
                raise ValueError("id 重复")
            seen.add(ident)
            kind = raw.get("__template_key") or raw.get("kind") or raw.get("template")
            if kind not in {"ssh", "http"}:
                raise ValueError("类型必须为 ssh 或 http")
            overrides = {k: v for k, v in raw.items() if v is not None}
            for key in ("trigger_times", "window_size", "recovery_times"):
                if overrides.get(key) == 0:
                    overrides.pop(key)
            if overrides.get("repeat_interval") == -1:
                overrides.pop("repeat_interval")
            if overrides.get("count_mode") == "inherit":
                overrides.pop("count_mode")
            for key in ("alert_template", "recovery_template"):
                if not overrides.get(key):
                    overrides.pop(key, None)
            notification = overrides.get("notify_recovery", "inherit")
            if notification == "inherit":
                overrides.pop("notify_recovery", None)
            elif notification in {"on", "off"}:
                overrides["notify_recovery"] = notification == "on"
            merged = {**defaults, **overrides}
            policy = Policy.parse(merged)
            options = dict(raw)
            if kind == "http":
                url = urlsplit(str(raw.get("url", "")))
                if (
                    url.scheme not in {"http", "https"}
                    or not url.hostname
                    or url.username
                    or url.password
                ):
                    raise ValueError("必须填写 HTTP/HTTPS URL，认证请使用 headers_json")
                _ = url.port
                method = str(raw.get("method", "GET")).upper()
                if method not in {"GET", "HEAD"}:
                    raise ValueError("HTTP 方法仅支持 GET / HEAD")
                options["method"] = method
                codes = {int(c.strip()) for c in str(raw.get("expected_status", "200")).split(",")}
                if not codes or any(not 100 <= c <= 599 for c in codes):
                    raise ValueError("expected_status 请填写逗号分隔的状态码")
                options["codes"] = codes
                headers = json.loads(raw.get("headers_json") or "{}")
                if not isinstance(headers, dict) or any(
                    not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
                ):
                    raise ValueError("headers_json 必须是字符串键值对象")
                if method == "HEAD" and raw.get("body_contains"):
                    raise ValueError("检查响应内容时必须使用 GET")
                options["headers"] = headers
            else:
                if not str(raw.get("host", "")).strip() or not str(raw.get("username", "")).strip():
                    raise ValueError("SSH host 和 username 不能为空")
                options["port"] = integer(raw, "port", 22, 1, 65535)
                paths = strings(raw.get("disk_paths", ["/"]))
                if raw.get("collect_metrics", True) and not paths:
                    raise ValueError("采集磁盘路径不能为空")
                options["disk_paths"] = paths
                for key, default in (
                    ("cpu_threshold", 85),
                    ("memory_threshold", 90),
                    ("disk_threshold", 90),
                ):
                    options[key] = number(raw, key, default, 0, 100)
                options["load_threshold"] = number(raw, "load_threshold", 0, 0, 100000)
            options["latency_threshold_ms"] = number(raw, "latency_threshold_ms", 0, 0, 3600000)
            own_recipients = strings(raw.get("recipients", []))
            fingerprint = hashlib.sha256(
                json.dumps(
                    {"raw": raw, "defaults": defaults}, sort_keys=True, ensure_ascii=False
                ).encode()
            ).hexdigest()
            settings.targets.append(
                Target(
                    ident,
                    str(raw.get("name") or ident),
                    kind,
                    number(raw, "interval", 60, 5, 86400),
                    number(raw, "timeout", 10, 1, 300),
                    own_recipients or global_recipients,
                    policy,
                    options,
                    fingerprint,
                )
            )
        except (ValueError, TypeError, OverflowError) as exc:
            settings.errors.append(f"{label}：{exc}")
    return settings
