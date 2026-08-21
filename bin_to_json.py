#!/usr/bin/env python3
"""将 RebirthPub 的 saveDataXX.bin 存档解密为可编辑的 JSON。

The format was verified from Assembly-CSharp.dll:
AES/Rijndael ECB + PKCS7 -> GZip -> MessagePack string -> JSON.
"""

# 允许在较新的 Python 版本中使用延迟解析的类型注解。
from __future__ import annotations

# 导入命令行参数解析、压缩解压、JSON 处理和错误输出所需的标准库。
import argparse
import gzip
import json
import sys
# 使用 Path 跨平台处理文件路径。
from pathlib import Path
# 使用 Any 表示解密后 JSON 中可能出现的任意类型。
from typing import Any

try:
    # MessagePack 用于读取游戏存储的二进制序列化数据。
    import msgpack
    # cryptography 用于执行 AES 解密和 PKCS7 去填充。
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError as exc:
    # 依赖缺失时给出安装命令，并终止程序。
    raise SystemExit(
        "Missing dependency. Install it with:\n"
        "  python -m pip install msgpack cryptography"
    ) from exc


# 游戏存档使用的 AES 密钥；必须与游戏端保持一致。
KEY = b"(H+MbQeThWmZq4t7"


def decrypt_save(encrypted: bytes) -> dict[str, Any]:
    # AES 的分组大小为 16 字节，输入必须非空且长度为 16 的整数倍。
    if not encrypted or len(encrypted) % 16 != 0:
        raise ValueError("The input size is invalid for this game's AES save format.")

    # 按游戏使用的 ECB 模式创建 AES 解密器。
    decryptor = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
    # 解密全部密文，并完成解密器的收尾操作。
    padded = decryptor.update(encrypted) + decryptor.finalize()

    # 创建 PKCS7 去填充器，移除 AES 加密前补齐的填充字节。
    unpadder = PKCS7(128).unpadder()
    # 得到压缩后的 GZip 数据。
    compressed = unpadder.update(padded) + unpadder.finalize()

    # 解压 GZip 数据，还原 MessagePack 负载。
    packed = gzip.decompress(compressed)
    # 将 MessagePack 负载解码为 Python 对象，并把二进制字符串转成文本。
    json_text = msgpack.unpackb(packed, raw=False)
    # 游戏存储的 MessagePack 顶层内容应当是 JSON 字符串。
    if not isinstance(json_text, str):
        raise TypeError("The MessagePack payload is not a JSON string.")

    # 解析 JSON 字符串，并确认存档顶层结构是对象（字典）。
    data = json.loads(json_text)
    if not isinstance(data, dict):
        raise TypeError("The save JSON root is not an object.")
    return data


def expand_nested_json(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """展开顶层中以 JSON 字符串形式保存的嵌套数据，方便人工编辑。"""
    # 保存展开后的数据，以及实际发生展开的字段名。
    expanded: dict[str, Any] = {}
    expanded_keys: list[str] = []

    # 逐个检查存档顶层字段。
    for key, value in data.items():
        # 只有字符串值可能是被再次序列化的 JSON。
        if isinstance(value, str):
            try:
                # 尝试把字符串解析为 JSON。
                nested = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                # 解析失败时保留原始字符串，避免误改普通文本字段。
                expanded[key] = value
            else:
                # 仅展开对象和数组；JSON 基本值仍按原字符串保留。
                if isinstance(nested, (dict, list)):
                    expanded[key] = nested
                    expanded_keys.append(key)
                else:
                    expanded[key] = value
        else:
            # 非字符串字段无需处理，直接保留原值。
            expanded[key] = value
    # 返回展开后的数据和字段名列表。
    return expanded, expanded_keys


def parse_args() -> argparse.Namespace:
    # 创建命令行参数解析器，并说明脚本用途。
    parser = argparse.ArgumentParser(
        description="Convert an encrypted saveDataXX.bin file to editable JSON."
    )
    parser.add_argument(
        # 可选的输入存档路径，未提供时使用默认存档名。
        "input",
        nargs="?",
        type=Path,
        default="saveData/saveData04.bin",
        help="Input saveDataXX.bin file")
    parser.add_argument(
        # 可选的输出 JSON 路径。
        "-o",
        "--output",
        type=Path,
        default="saveData/saveData04.json",
        help="Output JSON path (default: input filename with .json)",
    )
    parser.add_argument(
        # --raw 用于保留游戏原始的嵌套 JSON 字符串格式。
        "--raw",
        action="store_true",
        help="Keep the game's nested JSON strings instead of expanding them",
    )
    # 解析命令行，并返回参数对象。
    return parser.parse_args()


def main() -> int:
    # 读取命令行参数并确定输入、输出路径。
    args = parse_args()
    input_path: Path = args.input
    output_path: Path = args.output or input_path.with_suffix(".json")

    # 在开始转换前确认输入文件确实存在且是普通文件。
    if not input_path.is_file():
        print(f"Error: input file does not exist: {input_path}", file=sys.stderr)
        return 1

    try:
        # 读取二进制存档并执行 AES 解密、解压和 JSON 解析。
        data = decrypt_save(input_path.read_bytes())
        # 记录展开字段；raw 模式下不展开任何嵌套 JSON。
        expanded_keys: list[str] = []
        if not args.raw:
            data, expanded_keys = expand_nested_json(data)

        # 确保输出目录存在，然后以 UTF-8 和缩进格式写出 JSON。
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        # 捕获转换过程中的错误，输出类型和详细信息，并返回失败状态码。
        print(f"Conversion failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # 输出转换成功信息和展开字段数量，帮助用户确认结果。
    print(f"Converted successfully: {input_path} -> {output_path}")
    if expanded_keys:
        print(f"Expanded {len(expanded_keys)} nested data sections for easy editing.")
    print("Keep the original .bin file as a backup before replacing a game save.")
    return 0


if __name__ == "__main__":
    # 仅在直接运行脚本时执行主函数；被导入时不自动转换文件。
    raise SystemExit(main())
