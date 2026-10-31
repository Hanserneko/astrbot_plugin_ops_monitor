from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass, field

import aiohttp
import asyncssh

from .config import Target


@dataclass
class Observation:
    key: str
    event: str
    bad: bool
    detail: str
    value: str = ""
    threshold: str = ""


@dataclass
class ProbeResult:
    ok: bool
    detail: str
    latency_ms: float
    observations: list[Observation] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)


def safe_error(exc: Exception, target: Target) -> str:
    # HTTP 异常经常携带完整 URL / 查询令牌，群聊与持久化中仅保留错误类型。
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return f"请求超时（{target.timeout:g} 秒）"
    if isinstance(exc, asyncssh.PermissionDenied):
        return "SSH 认证失败"
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return "SSH 主机密钥未通过校验，请配置 known_hosts"
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return "HTTPS 证书校验失败"
    return f"探测失败（{type(exc).__name__}）"


# 仅使用 Linux /proc 和 Python 标准库，无需安装 agent 或 psutil。
METRICS_SCRIPT = r"""
import json, os, time

def cpu():
    with open('/proc/stat') as f:
        values = list(map(int, f.readline().split()[1:9]))
    return sum(values), values[3] + values[4]

a, idle_a = cpu()
time.sleep(0.25)
b, idle_b = cpu()
cpu_percent = 100 * (1 - (idle_b - idle_a) / max(1, b - a))
mem = {}
with open('/proc/meminfo') as f:
    for line in f:
        key, value = line.split(':', 1)
        mem[key] = int(value.split()[0]) * 1024
total = mem['MemTotal']
available = mem.get('MemAvailable', mem.get('MemFree', 0) + mem.get('Buffers', 0) + mem.get('Cached', 0))
disks = []
for path in DISK_PATHS:
    stat = os.statvfs(path)
    used = stat.f_blocks - stat.f_bfree
    denominator = used + stat.f_bavail
    disks.append({'path': path, 'percent': round(100 * used / max(1, denominator), 2),
                  'total_bytes': stat.f_blocks * stat.f_frsize,
                  'available_bytes': stat.f_bavail * stat.f_frsize})
with open('/proc/uptime') as f:
    uptime = float(f.read().split()[0])
rx = tx = 0
with open('/proc/net/dev') as f:
    for line in f:
        if ':' not in line:
            continue
        name, values = line.split(':', 1)
        if name.strip() == 'lo':
            continue
        fields = values.split()
        rx += int(fields[0])
        tx += int(fields[8])
print(json.dumps({'cpu_percent': round(max(0, min(100, cpu_percent)), 2),
                  'memory_percent': round(100 * (total - available) / total, 2),
                  'memory_total_bytes': total, 'memory_available_bytes': available,
                  'load1': os.getloadavg()[0], 'cpu_count': os.cpu_count() or 1,
                  'uptime_seconds': uptime, 'disks': disks,
                  'rx_bytes': rx, 'tx_bytes': tx}))
"""


def metrics_script(paths: tuple[str, ...]) -> str:
    # JSON 文本成为 Python 字符串字面量，经 stdin 传递，不拼接 shell 参数。
    return (
        "import json\nDISK_PATHS = json.loads(" + repr(json.dumps(paths)) + ")\n" + METRICS_SCRIPT
    )


def validate_metrics(data: object, paths: tuple[str, ...]) -> dict:
    if not isinstance(data, dict):
        raise ValueError("采集输出不是对象")
    for key in ("cpu_percent", "memory_percent", "load1", "uptime_seconds", "rx_bytes", "tx_bytes"):
        value = data.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(f"无效指标 {key}")
    if any(data[key] > 100 for key in ("cpu_percent", "memory_percent")):
        raise ValueError("使用率超过 100%")
    disks = data.get("disks")
    if not isinstance(disks, list) or len(disks) != len(paths):
        raise ValueError("磁盘采集不完整")
    for path, disk in zip(paths, disks):
        if not isinstance(disk, dict) or disk.get("path") != path:
            raise ValueError("磁盘采集路径不符")
        value = disk.get("percent")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 100
        ):
            raise ValueError("无效磁盘使用率")
    return data


def metric_observations(data: dict, target: Target) -> list[Observation]:
    out = []
    for key, name, option in (
        ("cpu_percent", "CPU 使用率", "cpu_threshold"),
        ("memory_percent", "内存使用率", "memory_threshold"),
        ("load1", "1 分钟负载", "load_threshold"),
    ):
        threshold = target.options[option]
        if threshold > 0:
            value = data[key]
            unit = "" if key == "load1" else "%"
            out.append(
                Observation(
                    key,
                    name,
                    value >= threshold,
                    f"{name} {value:g}{unit}，阈值 {threshold:g}{unit}",
                    f"{value:g}",
                    f"{threshold:g}",
                )
            )
    threshold = target.options["disk_threshold"]
    if threshold > 0:
        for disk in data["disks"]:
            value, path = disk["percent"], disk["path"]
            out.append(
                Observation(
                    f"disk:{path}",
                    f"磁盘使用率 {path}",
                    value >= threshold,
                    f"磁盘 {path} 使用率 {value:g}%，阈值 {threshold:g}%",
                    str(value),
                    str(threshold),
                )
            )
    return out


class Prober:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def run(self, target: Target) -> ProbeResult:
        started = time.monotonic()
        try:
            budget = (
                target.timeout
                * (2 if target.kind == "ssh" and target.options.get("collect_metrics", True) else 1)
                + 1
            )
            async with asyncio.timeout(budget):
                result = await (self._http(target) if target.kind == "http" else self._ssh(target))
        except Exception as exc:
            detail = safe_error(exc, target)
            result = ProbeResult(
                False, detail, 0, [Observation("availability", "服务可用性", True, detail)]
            )
        result.latency_ms = round((time.monotonic() - started) * 1000, 1)
        threshold = target.options["latency_threshold_ms"]
        if result.ok and threshold:
            value = result.latency_ms
            result.observations.append(
                Observation(
                    "latency",
                    "响应延迟",
                    value >= threshold,
                    f"响应 {value:g} ms，阈值 {threshold:g} ms",
                    str(value),
                    str(threshold),
                )
            )
        return result

    async def _http(self, target: Target) -> ProbeResult:
        options = target.options
        async with self.session.request(
            options["method"],
            options["url"],
            headers=options["headers"],
            ssl=None if options.get("verify_tls", True) else False,
            allow_redirects=bool(options.get("follow_redirects", True)),
            timeout=aiohttp.ClientTimeout(total=target.timeout),
        ) as response:
            ok = response.status in options["codes"]
            detail = f"HTTP {response.status}，期望 " + ",".join(map(str, sorted(options["codes"])))
            keyword = str(options.get("body_contains") or "")
            if ok and keyword:
                # 分块读取上限，避免大响应占用无限内存。
                body = bytearray()
                async for chunk in response.content.iter_chunked(8192):
                    body.extend(chunk[: 65536 - len(body)])
                    if len(body) >= 65536:
                        break
                encoding = response.charset or "utf-8"
                try:
                    text = body.decode(encoding, errors="replace")
                except LookupError:
                    text = body.decode("utf-8", errors="replace")
                ok = keyword in text
                detail += "；内容校验通过" if ok else "；响应前 64 KiB 未包含预期文本"
            return ProbeResult(
                ok,
                detail,
                0,
                [
                    Observation(
                        "availability",
                        "服务可用性",
                        not ok,
                        detail,
                        str(response.status),
                        ",".join(map(str, sorted(options["codes"]))),
                    )
                ],
            )

    async def _ssh(self, target: Target) -> ProbeResult:
        options = target.options
        kwargs = {
            "host": options["host"],
            "port": options["port"],
            "username": options["username"],
            "config": None,
            "agent_path": None,
            "connect_timeout": target.timeout,
            "login_timeout": target.timeout,
        }
        if options.get("key_path"):
            kwargs["client_keys"] = [options["key_path"]]
            if options.get("key_passphrase"):
                kwargs["passphrase"] = options["key_passphrase"]
        else:
            kwargs["client_keys"] = []
            if options.get("password"):
                kwargs["password"] = options["password"]
        if not options.get("verify_host_key", True):
            kwargs["known_hosts"] = None
        elif options.get("known_hosts"):
            kwargs["known_hosts"] = options["known_hosts"]
        async with asyncssh.connect(**kwargs) as conn:
            observations = [Observation("availability", "SSH 可用性", False, "SSH 登录成功")]
            result = ProbeResult(True, "SSH 登录成功", 0, observations)
            if options.get("collect_metrics", True):
                try:
                    process = await conn.run(
                        "python3 -",
                        input=metrics_script(options["disk_paths"]),
                        check=True,
                        timeout=target.timeout,
                    )
                    data = validate_metrics(json.loads(process.stdout), options["disk_paths"])
                    result.metrics = data
                    observations.append(
                        Observation("collection", "状态采集", False, "Linux 状态采集成功")
                    )
                    observations.extend(metric_observations(data, target))
                except Exception as exc:
                    # 已登录的 SSH 服务仍在线，采集失败单独告警，不将旧指标标记为恢复。
                    detail = f"SSH 在线，状态采集失败（{type(exc).__name__}）；检查 Linux、python3 与采集路径"
                    result.detail = detail
                    observations.append(Observation("collection", "状态采集", True, detail))
            return result
