"""构建可在 AstrBot 插件管理页上传的 ZIP。"""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_NAME = "astrbot_plugin_ops_monitor"
OUTPUT = ROOT / "dist" / f"{PLUGIN_NAME}-0.1.2.zip"
FILES = [
    "__init__.py",
    "main.py",
    "metadata.yaml",
    "requirements.txt",
    "_conf_schema.json",
    "README.md",
    "config.example.json",
]


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    files = [ROOT / name for name in FILES] + sorted((ROOT / "core").glob("*.py"))
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED) as archive:
        for file in files:
            archive.write(file, PLUGIN_NAME + "/" + file.relative_to(ROOT).as_posix())
    print(OUTPUT)


if __name__ == "__main__":
    build()
