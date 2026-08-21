#!/usr/bin/env python3
"""分析 Unity 的 Assembly-CSharp.dll，并生成便于阅读的分析结果。

脚本的工作流程如下：
1. 尝试调用 ilspycmd，将 .NET 程序集反编译为 C# 源码。
2. 从反编译结果和 DLL 原始字节中搜索加密相关关键词。
3. 输出命中的文件、行号和上下文，方便定位存档加密实现。

说明：Assembly-CSharp.dll 通常是 Mono/.NET 程序集，真正的完整反编译
需要 ILSpy 等专用反编译器；本脚本负责自动化调用和分析，而不是重新实现
一个完整的 .NET 反编译器。
"""

from __future__ import annotations

# 导入命令行解析、正则匹配、外部程序调用和文件处理功能。
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


# 默认的 Unity C# 程序集路径。
DEFAULT_DLL = Path("GAME_Data") / "Managed" / "Assembly-CSharp.dll"

# 默认的分析输出目录。
DEFAULT_OUTPUT = Path("assembly_analysis")

# 用于定位加密、压缩、序列化和存档处理逻辑的关键词。
SEARCH_TERMS = (
    "(H+MbQeThWmZq4t7",
    "KEY",
    "AES",
    "Rijndael",
    "ECB",
    "CBC",
    "PKCS7",
    "PaddingMode",
    "GZip",
    "GZipStream",
    "MessagePack",
    "saveData",
    "encrypt",
    "decrypt",
    "加密",
    "解密",
)

# 将关键词转换为不区分大小写的正则表达式，避免每次搜索时重复构造。
SEARCH_PATTERN = re.compile(
    "|".join(re.escape(term) for term in SEARCH_TERMS),
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""

    # 创建命令行参数解析器，并说明脚本用途。
    parser = argparse.ArgumentParser(
        description="Analyze a Unity Assembly-CSharp.dll for readable encryption clues."
    )
    parser.add_argument(
        # 允许用户指定 DLL；未指定时使用 Unity 项目的常见目录结构。
        "dll",
        nargs="?",
        type=Path,
        default=DEFAULT_DLL,
        help="Path to Assembly-CSharp.dll",
    )
    parser.add_argument(
        # 指定反编译和报告文件的输出目录。
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Analysis output directory",
    )
    parser.add_argument(
        # 允许用户手动指定 ilspycmd 的位置。
        "--ilspycmd",
        type=Path,
        help="Path to ilspycmd executable; otherwise search it in PATH",
    )
    parser.add_argument(
        # 跳过外部反编译器，只提取 DLL 中的可读字符串。
        "--strings-only",
        action="store_true",
        help="Only extract strings; do not invoke ilspycmd",
    )
    parser.add_argument(
        # 控制报告上下文中显示命中行前后的代码行数量。
        "--context",
        type=int,
        default=3,
        help="Number of context lines around each match",
    )
    return parser.parse_args()


def find_ilspycmd(explicit_path: Path | None) -> str | None:
    """查找可用的 ilspycmd 命令。"""

    # 如果用户显式指定了路径，则优先使用该路径。
    if explicit_path is not None:
        if explicit_path.is_file():
            return str(explicit_path)
        raise FileNotFoundError(f"ilspycmd does not exist: {explicit_path}")

    # 在系统 PATH 中查找 Windows 和跨平台命令名。
    for command in ("ilspycmd", "ilspycmd.exe"):
        found = shutil.which(command)
        if found:
            return found
    return None


def decompile_with_ilspy(dll_path: Path, output_dir: Path, ilspycmd: str) -> None:
    """调用 ILSpy 命令行工具，把 DLL 反编译为 C# 文件。"""

    # 将反编译结果单独放在 decompiled 子目录中，避免和报告混在一起。
    decompiled_dir = output_dir / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)

    # -o 指定输出目录，输入参数指定待反编译的程序集。
    command = [ilspycmd, "-o", str(decompiled_dir), str(dll_path)]
    try:
        # 执行反编译器，并把标准输出和错误输出保存下来供报告使用。
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        # 外部程序无法启动时，转换为更容易理解的错误信息。
        raise RuntimeError(f"无法启动 ilspycmd：{exc}") from exc

    # 将 ILSpy 的执行日志保存下来，方便排查版本或参数问题。
    log_path = output_dir / "ilspycmd.log.txt"
    log_path.write_text(
        "命令：" + " ".join(command) + "\n"
        + f"退出代码：{result.returncode}\n\n"
        + "标准输出：\n"
        + result.stdout
        + "\n标准错误：\n"
        + result.stderr,
        encoding="utf-8",
    )

    # 非零退出码表示反编译失败，阻止后续误把不完整结果当成成功结果。
    if result.returncode != 0:
        raise RuntimeError(
            f"ilspycmd 反编译失败，退出代码为 {result.returncode}，详见：{log_path}"
        )


def extract_printable_strings(data: bytes, minimum_length: int = 4) -> list[str]:
    """从 DLL 二进制中提取 ASCII 和 UTF-16LE 可读字符串。"""

    # 匹配连续的 ASCII 可打印字符。
    ascii_pattern = re.compile(rb"[ -~]{%d,}" % minimum_length)
    # 匹配 .NET/Windows 程序集中常见的 UTF-16LE 字符串。
    utf16_pattern = re.compile(
        rb"(?:[ -~]\x00){%d,}" % minimum_length
    )

    # 提取 ASCII 字符串并去除重复内容。
    strings: set[str] = set()
    for match in ascii_pattern.finditer(data):
        strings.add(match.group().decode("ascii", errors="replace"))

    # 提取 UTF-16LE 字符串并去除重复内容。
    for match in utf16_pattern.finditer(data):
        strings.add(match.group().decode("utf-16le", errors="replace"))

    # 按字典序输出，使报告在重复运行时保持稳定。
    return sorted(strings, key=str.casefold)


def iter_text_files(root: Path) -> Iterable[Path]:
    """遍历目录中的文本源码和报告文件。"""

    # 只分析常见的源码/文本格式，跳过 DLL 等二进制文件。
    suffixes = {".cs", ".il", ".txt", ".json", ".xml"}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def search_text_files(root: Path) -> list[str]:
    """搜索文本文件中的加密相关关键词，并返回带上下文的结果。"""

    # 保存所有命中结果，最后统一写入报告。
    matches: list[str] = []

    # 遍历反编译产生的 C# 文件和其他文本文件。
    for path in iter_text_files(root):
        try:
            # 逐行读取，便于显示文件名和行号。
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            # 个别文件读取失败时跳过，不影响其他文件分析。
            continue

        # 检查每一行是否包含至少一个目标关键词。
        for index, line in enumerate(lines):
            if not SEARCH_PATTERN.search(line):
                continue

            # 报告命中的文件和行号。
            matches.append(f"{path}:{index + 1}: {line.strip()}")

    # 返回所有命中行；不在这里做截断，以免漏掉关键位置。
    return matches


def write_string_report(
    strings: list[str], output_path: Path, matching_only: bool = False
) -> int:
    """写出字符串提取报告，并返回写入条目数量。"""

    # 根据参数决定输出全部字符串，还是只输出加密相关字符串。
    selected = [item for item in strings if SEARCH_PATTERN.search(item)] if matching_only else strings

    # 写入 UTF-8 文本，方便使用记事本、VS Code 等工具查看。
    output_path.write_text("\n".join(selected) + "\n", encoding="utf-8")
    return len(selected)


def write_analysis_report(
    dll_path: Path,
    output_dir: Path,
    ilspycmd: str | None,
    text_matches: list[str],
    matching_strings: list[str],
) -> Path:
    """生成最终的加密格式分析报告。"""

    # 预先写出可能的判断，帮助用户快速理解分析结果。
    key_found = any("(H+MbQeThWmZq4t7" in item for item in matching_strings + text_matches)
    # 组合报告标题、文件信息、关键词命中结果和后续建议。
    report: list[str] = [
        "Unity Assembly-CSharp.dll 加密格式分析报告",
        "=" * 52,
        f"输入文件：{dll_path}",
        f"文件大小：{dll_path.stat().st_size} 字节",
        f"ilspycmd：{ilspycmd or '未找到（仅执行了原始字符串扫描）'}",
        "",
        "关键判断：",
        f"- 已发现目标 AES 密钥：{key_found}",
        "- 如果反编译结果中同时出现 AES/Rijndael、ECB、PKCS7、GZip、MessagePack，"
        "则可以据此还原存档编码链路。",
        "",
        "文本文件命中：",
    ]

    # 添加源码中的关键词命中行。
    report.extend(text_matches or ["（没有找到文本关键词）"])
    report.extend(["", "原始 DLL 字符串命中："])

    # 添加 DLL 原始字符串中的关键词命中内容。
    report.extend(matching_strings or ["（没有找到原始字符串关键词）"])
    report.extend(
        [
            "",
            "说明：",
            "- 本报告是静态分析结果，不会修改 DLL 或游戏存档。",
            "- 如果 DLL 使用 IL2CPP，它可能不是普通的 .NET 程序集，需改用原生逆向工具。",
            "- 如果存在代码混淆，类名和方法名可能不可读，但字符串和调用常量仍可能有帮助。",
        ]
    )

    # 将报告保存到输出目录。
    report_path = output_dir / "encryption_report.txt"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    return report_path


def main() -> int:
    """执行 DLL 分析流程并返回进程状态码。"""

    # 解析用户参数。
    args = parse_args()
    dll_path: Path = args.dll
    output_dir: Path = args.output

    # 确认输入文件存在且是普通文件。
    if not dll_path.is_file():
        print(f"错误：找不到 DLL 文件：{dll_path}", file=sys.stderr)
        return 1

    # 防止用户传入负数上下文行数导致切片范围异常。
    if args.context < 0:
        print("错误：--context 不能小于 0", file=sys.stderr)
        return 1

    # 创建输出目录。
    output_dir.mkdir(parents=True, exist_ok=True)

    # 读取 DLL 原始内容，用于提取不依赖外部工具的可读字符串。
    raw_data = dll_path.read_bytes()
    all_strings = extract_printable_strings(raw_data)
    matching_strings = [item for item in all_strings if SEARCH_PATTERN.search(item)]
    write_string_report(all_strings, output_dir / "all_strings.txt")
    write_string_report(
        matching_strings,
        output_dir / "matching_strings.txt",
    )

    # 记录是否找到反编译器，默认优先生成可读 C# 源码。
    ilspycmd: str | None = None
    text_matches: list[str] = []
    if not args.strings_only:
        try:
            # 查找 ilspycmd 并执行反编译。
            ilspycmd = find_ilspycmd(args.ilspycmd)
            if ilspycmd is None:
                print(
                    "提示：未找到 ilspycmd，将跳过 C# 反编译，只生成原始字符串报告。"
                )
            else:
                decompile_with_ilspy(dll_path, output_dir, ilspycmd)
                # 搜索刚刚生成的 C# 文件中的加密关键词。
                text_matches = search_text_files(output_dir)
        except (FileNotFoundError, RuntimeError) as exc:
            # 外部反编译失败时保留字符串扫描结果，并在终端提示原因。
            print(f"警告：{exc}", file=sys.stderr)

    # 生成汇总报告。
    report_path = write_analysis_report(
        dll_path,
        output_dir,
        ilspycmd,
        text_matches,
        matching_strings,
    )

    # 输出结果文件位置，方便用户继续查看。
    print(f"分析完成：{dll_path}")
    print(f"分析目录：{output_dir}")
    print(f"重点报告：{report_path}")
    return 0


if __name__ == "__main__":
    # 仅在直接运行脚本时执行主函数；被其他脚本导入时不自动分析 DLL。
    raise SystemExit(main())
