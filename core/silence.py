"""临时屏蔽告警的时长解析。"""

import re

MAX_MUTE_SECONDS = 30 * 86400


def parse_mute_duration(value: str) -> int:
    """支持 30m、2h、1d、1h30m；不写单位时按分钟。"""
    value = value.strip().lower()
    if value.isascii() and value.isdigit():
        value += "m"
    parts = re.findall(r"([0-9]+)([smhd])", value)
    if not parts or "".join(number + unit for number, unit in parts) != value:
        raise ValueError("时长请填写 30m、2h、1d 或 1h30m；不写单位时按分钟")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    seconds = sum(int(number) * units[unit] for number, unit in parts)
    if not 1 <= seconds <= MAX_MUTE_SECONDS:
        raise ValueError("屏蔽时长必须在 1 秒到 30 天之间")
    return seconds
