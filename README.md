## 修改游戏存档 ##
将游戏的.bin存档读取成json的格式，手动修改json，然后再转成.bin
### 修改前需要知道GAME_Data\Managed\Assembly-CSharp.dll文件对存档的加密格式 即 KEY = b"(H+MbQeThWmZq4t7" ###

## 运行方法 ##
修改bin_to_json.py和json_to_bin.py的存档路径，或者将路径放入输入参数内，
依次运行：
```cmd
git clone https://github.com/herolzt/game-cheat-filesave
cd ~/game-cheat-filesave

conda create -n game310 python=3.10 -y
conda activate game310
pip install -r requirements.txt

python bin_to_json.py saveData04.bin
python json_to_bin.py saveData04.json

```