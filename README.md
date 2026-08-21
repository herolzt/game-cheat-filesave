# Unity 游戏存档转换工具

本项目用于将 Unity 游戏的加密 `.bin` 存档转换为可编辑的 JSON，并将修改后的 JSON 再转换回游戏可以读取的 `.bin` 存档。

项目还提供 `Assembly-CSharp.dll` 静态分析脚本，用于定位游戏使用的存档加密、压缩和序列化格式。


## 目录结构

```text
game-cheat-filesave/
├─ bin_to_json.py                    # .bin → .json
├─ json_to_bin.py                    # .json → .bin
├─ analyze_assembly.py               # 分析 Assembly-CSharp.dll
├─ requirements.txt                  # Python 依赖
├─ GAME_Data/Managed/
│  └─ Assembly-CSharp.dll            # Unity 游戏程序集
└─ saveData/
   ├─ saveData04.bin                 # 原始游戏存档
   └─ saveData04.json                # 导出的 JSON 存档
```

## 环境配置

项目使用 Python 3.10 或更高版本。使用 Conda 时：

```powershell
conda create -n game310 python=3.10 -y
conda activate game310
pip install -r requirements.txt
```

`analyze_assembly.py` 的完整反编译功能还需要 .NET SDK 和 `ilspycmd`：

```powershell
dotnet tool install --global ilspycmd
```

## 分析 Assembly-CSharp.dll

在项目根目录执行：

```powershell
python .\analyze_assembly.py
```

脚本默认分析：

```text
GAME_Data\Managed\Assembly-CSharp.dll
```

结果会写入 `assembly_analysis`：

```text
assembly_analysis/
├─ decompiled/          # 反编译得到的 C# 文件
├─ all_strings.txt      # DLL 中提取出的全部可读字符串
├─ matching_strings.txt # 与加密和存档相关的字符串
├─ ilspycmd.log.txt     # ILSpy 执行日志
└─ encryption_report.txt# 加密格式分析报告
```
在生成的C#文件里搜索 PrivateKey ，
得到PrivateKey = "(H+MbQeThWmZq4t7"

在bin2json和json2bin文件里更改全局密钥 
```python
KEY = b"(H+MbQeThWmZq4t7"
```


## 存档转换流程

### `.bin` 转 `.json`

```powershell
python .\bin_to_json.py .\saveData\saveData04.bin
```

也可以指定输出路径：

```powershell
python .\bin_to_json.py `
  .\saveData\saveData04.bin `
  --output .\saveData\saveData04.json
```

### 编辑 JSON

使用 VS Code、Visual Studio 或其他文本编辑器修改导出的 JSON。建议保留 JSON 的整体结构和必要字段，不要随意删除顶层字段。

### `.json` 转 `.bin`

```powershell
python .\json_to_bin.py .\saveData\saveData04.json
```

默认输出文件名会根据输入 JSON 自动生成：

```text
saveData04.json  →  saveData04_modified.bin
xx.json          →  xx_modified.bin
```

如果不同版本游戏使用了不同密钥或不同存档格式，应以对应版本的 `Assembly-CSharp.dll` 分析结果为准。