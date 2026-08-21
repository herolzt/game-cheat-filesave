#!/usr/bin/env python3
"""将编辑后的 JSON 转换回 RebirthPub 的 saveDataXX.bin 存档。"""

# 允许使用延迟解析的类型注解。
from __future__ import annotations

# 导入命令行、压缩、JSON、备份和错误输出相关功能。
import argparse
import gzip
import json
import shutil
import sys
# 用于生成带时间戳的备份文件名。
from datetime import datetime
# 使用 Path 跨平台处理文件路径。
from pathlib import Path
# 使用 Any 表示 JSON 中可能出现的任意类型。
from typing import Any

try:
    # MessagePack 用于生成游戏所需的二进制序列化数据。
    import msgpack
    # cryptography 用于执行 AES 加密和 PKCS7 填充。
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError as exc:
    # 依赖缺失时给出安装命令，并终止程序。
    raise SystemExit(
        "Missing dependency. Install it with:\n"
        "  python -m pip install msgpack cryptography"
    ) from exc


# 游戏存档使用的 AES 密钥，必须与解密脚本和游戏端一致。
KEY = b"(H+MbQeThWmZq4t7"

# 这些字段在游戏中以“JSON 字符串”嵌套保存；写回二进制前需要重新压回字符串。
NESTED_JSON_KEYS = {
    "playerData",
    "checkPointData",
    "heroineData",
    "heroineInteractData",
    "deptData",
    "warlockQuestData",
    "timeData",
    "spotData",
    "shopData",
    "npcData",
    "costData",
    "itemData",
    "relicData",
    "relicProductData",
    "exploreSkillData",
    "ExploreData",
    "pubInfoData",
    "pubFoodData",
    "eventData",
    "contentData",
    "trainingData",
    "blessingData",
    "herbfindData",
    "FishingData",
    "ClownFindBallData",
    "exploreSearchData",
    "costumeData",
}

# 存档能够被游戏识别所需的最基本顶层字段。
REQUIRED_KEYS = {"playerData", "timeData", "version", "saveTime"}


def collapse_nested_json(data: dict[str, Any]) -> dict[str, Any]:
    # 创建转换后的副本，避免直接修改调用方传入的数据。
    collapsed: dict[str, Any] = {}
    # 遍历所有顶层字段，恢复游戏原本的嵌套字符串格式。
    for key, value in data.items():
        # 仅处理指定字段，并把对象或数组紧凑序列化为 JSON 字符串。
        if key in NESTED_JSON_KEYS and isinstance(value, (dict, list)):
            collapsed[key] = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        else:
            # 其他字段或已经是字符串的字段保持原样。
            collapsed[key] = value
    # 返回适合重新打包的存档数据。
    return collapsed


def validate_save(data: Any) -> dict[str, Any]:
    # 确认 JSON 顶层是对象，而不是数组、字符串或其他基本类型。
    if not isinstance(data, dict):
        raise TypeError("The JSON root must be an object.")

    # 计算并检查所有必需字段是否存在。
    missing = sorted(REQUIRED_KEYS - data.keys())
    if missing:
        raise ValueError(f"Required top-level fields are missing: {', '.join(missing)}")

    # 检查出现的嵌套字段是否使用允许的数据类型。
    for key in NESTED_JSON_KEYS & data.keys():
        value = data[key]
        if not isinstance(value, (dict, list, str)):
            raise TypeError(
                f"Field {key!r} must be an object, array, or raw nested JSON string."
            )
        if isinstance(value, str):
            # 接受 raw 模式导出的原始字符串，但拒绝格式错误的嵌套 JSON。
            json.loads(value)
    # 返回通过校验的字典，供后续加密使用。
    return data


def encrypt_save(data: dict[str, Any]) -> bytes:
    # 将可编辑形式的嵌套对象/数组恢复为游戏需要的 JSON 字符串。
    collapsed = collapse_nested_json(data)
    # 将整个存档对象序列化为紧凑的 UTF-8 JSON 文本。
    json_text = json.dumps(
        collapsed,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    # 将 JSON 文本编码为 MessagePack 二进制格式。
    packed = msgpack.packb(json_text, use_bin_type=True)
    # 使用最高压缩级别压缩，并固定时间戳以便结果稳定可复现。
    compressed = gzip.compress(packed, compresslevel=9, mtime=0)

    # 按 AES 分组大小（128 bit）进行 PKCS7 填充。
    padder = PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()

    # 按游戏使用的 ECB 模式创建 AES 加密器。
    encryptor = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    # 加密填充后的数据，并完成加密器的收尾操作。
    return encryptor.update(padded) + encryptor.finalize()


def make_backup(path: Path) -> Path:
    # 生成精确到秒的时间戳，避免覆盖已有备份文件。
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # 在原文件名后追加时间戳和 .bak 扩展名。
    backup = path.with_name(f"{path.name}.{timestamp}.bak")
    # 复制文件内容及元数据，创建可恢复的备份。
    shutil.copy2(path, backup)
    # 返回备份文件路径，供主流程提示用户。
    return backup


def parse_args() -> argparse.Namespace:
    # 创建命令行参数解析器，并说明脚本用途。
    parser = argparse.ArgumentParser(
        description="Convert edited save JSON back to an encrypted .bin save."
    )
    parser.add_argument(
        # 可选的输入 JSON 路径，未提供时使用默认文件名。
        "input",
        nargs="?",
        type=Path,
        default="saveData/saveData04.json",
        help="Edited JSON file"
    )
    parser.add_argument(
        # 可选的输出二进制存档路径。
        "-o",
        "--output",
        type=Path,
        # 不指定时由 main() 根据输入 JSON 文件名自动生成输出路径。
        default=None,
        help="Output .bin path (default: <JSON stem>_modified.bin)",
    )
    parser.add_argument(
        # 允许覆盖已有输出文件；覆盖前会先创建备份。
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing output; a timestamped backup is created",
    )
    # 解析命令行，并返回参数对象。
    return parser.parse_args()


def main() -> int:
    # 读取命令行参数并确定输入、输出路径。
    args = parse_args()
    input_path: Path = args.input
    output_path: Path = args.output or input_path.with_name(
        f"{input_path.stem}_modified.bin"
    )

    # 确认输入 JSON 文件存在且是普通文件。
    if not input_path.is_file():
        print(f"Error: input file does not exist: {input_path}", file=sys.stderr)
        return 1
    # 默认禁止覆盖已有输出，避免用户无意中丢失文件。
    if output_path.exists() and not args.overwrite:
        print(
            f"Error: output already exists: {output_path}\n"
            "Use --overwrite to replace it and create a backup.",
            file=sys.stderr,
        )
        return 1

    try:
        # 读取 JSON，兼容带 UTF-8 BOM 的文件。
        data = json.loads(input_path.read_text(encoding="utf-8-sig"))
        # 检查存档结构和关键字段。
        validated = validate_save(data)
        # 执行嵌套 JSON 压回、MessagePack 编码、GZip 压缩和 AES 加密。
        encrypted = encrypt_save(validated)

        # 若目标文件已存在，则先备份再写入新存档。
        backup = make_backup(output_path) if output_path.exists() else None
        # 确保输出目录存在，并写入二进制存档内容。
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(encrypted)
    except Exception as exc:
        # 捕获转换过程中的错误，输出类型和详细信息，并返回失败状态码。
        print(f"Conversion failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # 如果发生覆盖，提示用户备份文件的位置。
    if backup:
        print(f"Existing output backed up to: {backup}")
    # 输出成功信息和替换游戏存档前的安全提示。
    print(f"Converted successfully: {input_path} -> {output_path}")
    print("Close the game, back up its original save, then replace it with this file.")
    return 0


if __name__ == "__main__":
    # 仅在直接运行脚本时执行主函数；被导入时不自动转换文件。
    raise SystemExit(main())
