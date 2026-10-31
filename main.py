from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

from .core.config import parse_settings
from .core.service import MonitorService
from .core.silence import parse_mute_duration

HELP = """运维监控（仅 AstrBot 管理员可用）
/ops status [id]：状态概览 / 机器详情
/ops bind [id]：当前会话接收全局 / 指定监控告警（群聊或私聊）
/ops unbind [id]：解除当前会话绑定
/ops umo：显示当前会话的完整标识
/ops test [id]：向已配置的接收会话发送测试消息
/ops check <id>：立即检查，不增加告警次数
/ops history：最近 10 次通知结果
/ops mute [时长=2h] [id]：临时屏蔽全局 / 指定监控的自动通知
/ops unmute [id]：提前解除全局 / 指定监控的屏蔽
/ops muted：查看当前屏蔽及到期时间
/ops reload：重新加载配置
在插件配置页添加监控；修改配置后重载插件或执行 /ops reload。"""


@register(
    "astrbot_plugin_ops_monitor", "hanser_no_neko", "SSH / HTTP 运维监控与群聊、私聊告警", "0.1.2"
)
class OpsMonitorPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.service: MonitorService | None = None
        self.command_lock = asyncio.Lock()

    async def initialize(self):
        await self._reload()

    async def _reload(self):
        # 先校验新配置，再停止旧服务，避免配置错误导致运行中的监控消失。
        settings = parse_settings(self.config)
        if self.service is not None:
            await self.service.stop()
        data_dir = Path(get_astrbot_plugin_data_path()) / "astrbot_plugin_ops_monitor"
        self.service = MonitorService(settings, self._send, data_dir)
        await self.service.start()
        for error in settings.errors:
            logger.error(f"[ops_monitor] {error}")
        if not self.config.get("recipients") and any(not t.recipients for t in settings.targets):
            logger.warning("[ops_monitor] 部分监控未配置接收会话，请在目标群聊或私聊执行 /ops bind")
        logger.info(f"[ops_monitor] 已加载 {len(settings.targets)} 个监控项")

    async def _send(self, recipient: str, text: str):
        result = await asyncio.wait_for(
            self.context.send_message(recipient, MessageChain().message(text)), timeout=15
        )
        if result is False:
            raise RuntimeError("平台未接受消息")

    async def terminate(self):
        async with self.command_lock:
            if self.service is not None:
                await self.service.stop()
                self.service = None

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ops")
    async def ops(
        self, event: AstrMessageEvent, action: str = "status", ident: str = "", extra: str = ""
    ):
        async with self.command_lock:
            try:
                response = await self._command(event, action.lower(), ident, extra)
            except Exception as exc:
                logger.error(f"[ops_monitor] 指令失败：{type(exc).__name__}")
                response = "操作失败，请检查插件配置与 AstrBot 日志。"
        yield event.plain_result(response)

    async def _command(
        self, event: AstrMessageEvent, action: str, ident: str, extra: str = ""
    ) -> str:
        if extra and action != "mute":
            return "参数过多，请使用 /ops help 查看用法。"
        if action == "help":
            return HELP
        if action == "reload":
            await self._reload()
            return "配置已重载。\n" + self.service.status_text()
        if self.service is None:
            return "监控服务尚未初始化，请检查日志。"
        targets = self.service.settings.targets
        engine = self.service.engine
        if action == "mute":
            if extra and not any(target.id == extra for target in targets):
                return f"未找到监控项：{extra}"
            try:
                seconds = parse_mute_duration(ident or "2h")
            except ValueError as exc:
                return f"{exc}\n用法：/ops mute 2h [id]"
            deadline = engine.mute(extra, seconds)
            return f"已屏蔽{'监控项 ' + extra if extra else '全局'}的自动告警与恢复通知，直到 {self._format_time(deadline)}。\n期间继续采样、计数，到期自动恢复。"
        if action == "muted":
            if ident:
                return "用法：/ops muted"
            active = engine.active_mutes()
            if not active:
                return "当前没有临时屏蔽。"
            return "当前屏蔽（北京时间）：\n" + "\n".join(
                f"{'全局' if scope == '*' else scope}：直到 {self._format_time(deadline)}"
                for scope, deadline in active.items()
            )
        selected = next((t for t in targets if t.id == ident), None)
        if ident and selected is None:
            return f"未找到监控项：{ident}"
        if action == "status":
            return self.service.status_text(ident)
        if action == "unmute":
            engine.unmute(ident)
            suffix = "其他范围的屏蔽仍然有效，可用 /ops muted 查看。"
            return f"已解除{'监控项 ' + ident if ident else '全局'}临时屏蔽；持续异常将在后续采样中按策略通知。\n{suffix}"
        if action in {"bind", "unbind", "umo"}:
            umo = event.unified_msg_origin
            if action == "umo":
                return f"当前会话标识：\n{umo}"
            container = self.config
            if ident:
                container = next(item for item in self.config["monitors"] if item["id"] == ident)
            recipients = list(container.get("recipients") or [])
            if action == "bind" and umo not in recipients:
                recipients.append(umo)
            if action == "unbind" and umo in recipients:
                recipients.remove(umo)
            container["recipients"] = recipients
            self.config.save_config()
            await self._reload()
            scope = ident or "全局"
            suffix = "；此项接收列表为空时将继承全局接收会话" if ident and not recipients else ""
            return f"已{'绑定' if action == 'bind' else '解除绑定'} {scope} 告警接收会话{suffix}。"
        if action == "check":
            if selected is None:
                return "用法：/ops check <id>"
            await self.service.sample(selected, evaluate=False)
            return self.service.status_text(ident) + "\n本次手动检查未增加告警次数。"
        if action == "test":
            recipients = (
                selected.recipients
                if selected
                else tuple(dict.fromkeys(r for t in targets for r in t.recipients))
            )
            if not recipients:
                recipients = tuple(self.config.get("recipients") or [])
            if not recipients:
                return "尚未配置接收会话，请先在目标群聊或私聊执行 /ops bind。"
            succeeded = 0
            for recipient in recipients:
                try:
                    await self._send(recipient, "🔔 运维监控测试：告警推送通道正常。")
                    succeeded += 1
                except Exception as exc:
                    logger.warning(f"[ops_monitor] 测试消息发送失败：{type(exc).__name__}")
            return f"测试消息已发送：成功 {succeeded}，失败 {len(recipients) - succeeded}。"
        if action == "history":
            entries = list(self.service.engine.history)[-10:]
            if not entries:
                return "暂无通知记录。"
            return "最近通知（时间为北京时间）：\n" + "\n".join(
                f"{datetime.fromtimestamp(item['time'], timezone(timedelta(hours=8))):%m-%d %H:%M:%S} "
                f"{item['target']} / {item['event']}：{item['status']}"
                for item in reversed(entries)
            )
        return HELP

    @staticmethod
    def _format_time(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, timezone(timedelta(hours=8))).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
