"""生成 AstrBot 配置界面与示例；修改后运行此脚本。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.config import ALERT_TEMPLATE, RECOVERY_TEMPLATE  # noqa: E402


def field(description, kind, default, hint=None, options=None, secret=False):
    value = dict(description=description, type=kind, default=default)
    if hint:
        value["hint"] = hint
    if options:
        value["options"] = options
    if secret:
        value["secret"] = True
    return value


def policy(inherit=False):
    return {
        "trigger_times": field(
            "触发次数（0 继承全局）" if inherit else "触发次数", "int", 0 if inherit else 3
        ),
        "count_mode": field(
            "计数方式",
            "string",
            "inherit" if inherit else "consecutive",
            "consecutive：连续异常；window：最近 N 次采样中异常 X 次",
            ["inherit", "consecutive", "window"] if inherit else ["consecutive", "window"],
        ),
        "window_size": field(
            "窗口采样数（0 继承全局）" if inherit else "窗口采样数", "int", 0 if inherit else 5
        ),
        "recovery_times": field(
            "连续正常次数后恢复（0 继承全局）" if inherit else "连续正常次数后恢复",
            "int",
            0 if inherit else 2,
        ),
        "repeat_interval": field(
            "重复告警间隔秒（-1 继承；0 仅首次）" if inherit else "重复告警间隔秒（0 仅首次）",
            "int",
            -1 if inherit else 1800,
        ),
        "notify_recovery": field(
            "恢复通知",
            "string" if inherit else "bool",
            "inherit" if inherit else True,
            options=["inherit", "on", "off"] if inherit else None,
        ),
        "alert_template": field(
            "告警消息模板（空白继承全局）" if inherit else "告警消息模板",
            "text",
            "" if inherit else ALERT_TEMPLATE,
            "支持 {name} {id} {event} {detail} {value} {threshold} {count} {trigger_times} {time} {duration} {status} {kind} {event_key}",
        ),
        "recovery_template": field(
            "恢复消息模板（空白继承全局）" if inherit else "恢复消息模板",
            "text",
            "" if inherit else RECOVERY_TEMPLATE,
        ),
    }


def common():
    return {
        "id": field("唯一 ID", "string", "", "字母、数字、下划线、短横线；修改 ID 会重新计数"),
        "name": field("显示名称", "string", ""),
        "enabled": field("启用此监控", "bool", True),
        "interval": field("探测间隔（秒）", "int", 60),
        "timeout": field("超时（秒）", "int", 10, "SSH 连接与状态采集各有独立超时"),
        "recipients": field(
            "此项接收会话 UMO（群聊 / 私聊）",
            "list",
            [],
            "空列表继承全局；在目标群聊或私聊 /ops umo 获取，或 /ops bind <id> 绑定",
        ),
        "latency_threshold_ms": field(
            "延迟告警阈值（毫秒，0 禁用）", "int", 0, "包含登录与采集的完整耗时"
        ),
    }


def generate():
    http = (
        common()
        | {
            "url": field("HTTP/HTTPS URL", "string", ""),
            "method": field("请求方法", "string", "GET", options=["GET", "HEAD"]),
            "expected_status": field(
                "期望状态码", "string", "200", "多个状态码用英文逗号分隔，如 200,204"
            ),
            "headers_json": field(
                "请求头 JSON",
                "string",
                "{}",
                '例如 {"Authorization":"Bearer ..."}；不会把请求头或 URL 写入通知',
                secret=True,
            ),
            "body_contains": field(
                "响应必须包含的文本", "string", "", "空白不检查；仅检查响应前 64 KiB，需使用 GET"
            ),
            "verify_tls": field("校验 HTTPS 证书", "bool", True),
            "follow_redirects": field("跟随重定向", "bool", True),
        }
        | policy(True)
    )
    ssh = (
        common()
        | {
            "host": field("SSH 主机", "string", ""),
            "port": field("SSH 端口", "int", 22),
            "username": field("SSH 用户", "string", ""),
            "password": field("SSH 密码", "string", "", "与私钥二选一，私钥优先", secret=True),
            "key_path": field("私钥文件路径", "string", "", "AstrBot 宿主机或容器内的路径"),
            "key_passphrase": field("私钥口令", "string", "", secret=True),
            "verify_host_key": field("校验 SSH 主机密钥", "bool", True),
            "known_hosts": field(
                "known_hosts 文件路径",
                "string",
                "",
                "留空使用 AstrBot 运行用户的 ~/.ssh/known_hosts",
            ),
            "collect_metrics": field(
                "采集 Linux 状态", "bool", True, "远程需要 Linux 与 python3；关闭后仅验证 SSH 登录"
            ),
            "disk_paths": field("采集磁盘路径", "list", ["/"]),
            "cpu_threshold": field("CPU 使用率告警阈值（%，0 禁用）", "int", 85),
            "memory_threshold": field("内存使用率告警阈值（%，0 禁用）", "int", 90),
            "disk_threshold": field("磁盘使用率告警阈值（%，0 禁用）", "int", 90),
            "load_threshold": field("1 分钟负载阈值（绝对值，0 禁用）", "float", 0),
        }
        | policy(True)
    )
    schema = {
        "enabled": field("启用监控", "bool", True),
        "max_concurrency": field("最大并发探测数", "int", 5),
        "recipients": field(
            "全局接收会话 UMO（群聊 / 私聊）",
            "list",
            [],
            "由管理员在目标群聊或私聊执行 /ops bind 自动填写，可同时绑定多个群和个人",
        ),
        "defaults": {"description": "全局告警策略", "type": "object", "items": policy()},
        "monitors": {
            "description": "监控项",
            "type": "template_list",
            "default": [],
            "templates": {
                "ssh": {"name": "SSH 探活 / Linux 状态", "display_item": "name", "items": ssh},
                "http": {"name": "HTTP / HTTPS 探活", "display_item": "name", "items": http},
            },
        },
    }
    example = {
        "enabled": True,
        "max_concurrency": 5,
        "recipients": [],
        "defaults": {key: value["default"] for key, value in policy().items()},
        "monitors": [
            {
                "__template_key": "http",
                "id": "website",
                "name": "业务网站",
                "url": "https://example.com/health",
                "expected_status": "200,204",
                "interval": 30,
                "timeout": 10,
                "trigger_times": 3,
                "alert_template": "🔴 {name} 连续异常 {count} 次，请检查业务。\n{detail}\n{time}",
            },
            {
                "__template_key": "ssh",
                "id": "server01",
                "name": "生产服务器",
                "host": "192.0.2.10",
                "port": 22,
                "username": "monitor",
                "key_path": "/app/data/keys/monitor_ed25519",
                "known_hosts": "/app/data/keys/known_hosts",
                "collect_metrics": True,
                "disk_paths": ["/", "/var"],
                "cpu_threshold": 85,
                "memory_threshold": 90,
                "disk_threshold": 90,
                "interval": 60,
                "trigger_times": 3,
            },
        ],
    }
    for name, data in (("_conf_schema.json", schema), ("config.example.json", example)):
        (ROOT / name).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    generate()
