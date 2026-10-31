from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

import aiohttp

from .alerts import AlertEngine, StateStore
from .config import Settings, Target
from .probes import Prober, ProbeResult

log = logging.getLogger(__name__)


class MonitorService:
    def __init__(
        self, settings: Settings, sender: Callable[[str, str], Awaitable[None]], data_dir: Path
    ):
        self.settings = settings
        self.engine = AlertEngine(
            settings.targets, sender, StateStore(data_dir / "alert_state.json")
        )
        self.latest: dict[str, ProbeResult] = {}
        self.tasks: list[asyncio.Task] = []
        self.session: aiohttp.ClientSession | None = None
        self.prober: Prober | None = None
        self.semaphore = asyncio.Semaphore(settings.max_concurrency)
        self.locks = {target.id: asyncio.Lock() for target in settings.targets}
        self.stopping = False

    async def start(self) -> None:
        if self.session is not None or not self.settings.enabled:
            return
        self.stopping = False
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.settings.max_concurrency)
        )
        self.prober = Prober(self.session)
        self.tasks = [
            asyncio.create_task(self._loop(target), name=f"ops-monitor-{target.id}")
            for target in self.settings.targets
        ]

    async def stop(self) -> None:
        self.stopping = True
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()
        if self.session is not None:
            await self.session.close()
            self.session = None
        self.prober = None
        self.engine.persist()

    async def _loop(self, target: Target) -> None:
        while not self.stopping:
            started = time.monotonic()
            try:
                await self.sample(target)
            except Exception:
                log.exception("运维监控轮次失败：%s", target.id)
            await asyncio.sleep(max(1, target.interval - (time.monotonic() - started)))

    async def sample(self, target: Target, evaluate: bool = True) -> ProbeResult:
        if self.prober is None:
            raise RuntimeError("监控未启用")
        async with self.locks[target.id]:
            async with self.semaphore:
                result = await self.prober.run(target)
            self.latest[target.id] = result
            if evaluate:
                for observation in result.observations:
                    await self.engine.observe(target, observation, result.checked_at)
            return result

    def status_text(self, ident: str = "") -> str:
        lines = ["运维监控：" + ("运行中" if self.settings.enabled else "已停用")]
        now = time.time()
        for scope, deadline in self.engine.active_mutes(now).items():
            if not ident or scope in {"*", ident}:
                lines.append(
                    f"🔕 {'全局' if scope == '*' else scope}告警已屏蔽，剩余 {max(1, int(deadline - now))} 秒"
                )
        selected = [t for t in self.settings.targets if not ident or t.id == ident]
        if not selected:
            lines.append("没有匹配的监控项，请在插件配置中添加 SSH / HTTP 监控。")
        for target in selected:
            result = self.latest.get(target.id)
            if result is None:
                lines.append(f"⏳ {target.name} [{target.id}]：等待采样")
                continue
            bad = [o for o in result.observations if o.bad]
            age = max(0, int(time.time() - result.checked_at))
            lines.append(
                f"{'🔴' if bad else '🟢'} {target.name} [{target.id}]：{result.detail}，{result.latency_ms:g} ms（{age} 秒前）"
            )
            for observation in bad:
                state = self.engine.states.get(f"{target.id}:{observation.key}", {})
                lines.append(
                    f"  {observation.detail}｜计数 {state.get('count', 0)}/{target.policy.trigger_times}"
                    + ("｜告警中" if state.get("active") else "")
                )
            if ident and result.metrics:
                data = result.metrics
                lines.append(
                    f"CPU {data['cpu_percent']:g}%｜内存 {data['memory_percent']:g}%｜负载 {data['load1']:g}"
                    f"｜运行 {int(data['uptime_seconds'])} 秒"
                )
                lines.extend(f"磁盘 {d['path']}：{d['percent']:g}%" for d in data["disks"])
                lines.append(
                    f"累计网络：接收 {data['rx_bytes'] / 1048576:.1f} MiB / 发送 {data['tx_bytes'] / 1048576:.1f} MiB"
                )
        if self.settings.errors:
            lines.append("配置错误（以下监控项未运行）：\n" + "\n".join(self.settings.errors))
        return "\n".join(lines)
