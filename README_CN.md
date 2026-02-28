# iApp-Frida-Decrypt

基于 Frida 的 iApp 框架脚本解密工具 - **无需 Xposed，PC 端直接操作**

## 这是什么？

iApp 是一个 Android 快速开发框架，它把脚本加密存储在 `assets/lib.so` 里。以前想解密只能用 Xposed 方案（需要在手机上装 LSPosed 等模块）。

**本项目是第一个纯 Frida 方案**，直接在电脑上通过 USB 连接手机就能解密，不用装任何 Xposed 模块。

## 为什么用 Frida？

| 对比项 | Xposed 方案 | Frida 方案（本项目） |
|--------|------------|---------------------|
| 需要装模块 | 需要 | 不需要 |
| 需要重启 | 需要 | 不需要 |
| 操作位置 | 手机上 | 电脑上 |
| 实时调试 | 麻烦 | 方便 |
| 修改脚本 | 要重新打包 | 热重载 |

## 原理

iApp 运行时会解密 `lib.so` 里的脚本，然后传给 Java 层执行。我们 Hook 这些关键方法来截获解密后的内容：

```
com.iapp.app.b.h3()     → UI 界面入口
com.iapp.app.b.h4()     → 逻辑脚本入口
com.iapp.app.run.mian.g() → 读取 this.r 字段（UI/事件 XML）
com.iapp.app.run.mian.g(String) → UI 元素定义
com.iapp.app.e.ah()     → 逻辑代码
bsh.Interpreter.eval()  → BeanShell 脚本
```

## 快速开始

### 1. 环境准备

```bash
# 安装 Frida（推荐 16.x 版本）
pip install frida-tools==16.1.4

# 下载对应架构的 frida-server
# ARM64: https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
```

### 2. 手机端准备

```bash
# 推送 frida-server 到手机
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# Root 权限运行
adb shell "su -c '/data/local/tmp/frida-server &'"

# 如果 SELinux 报错，临时关闭
adb shell "su -c 'setenforce 0'"
```

### 3. 运行解密

```bash
# 解密某个 iApp 应用（替换成实际包名）
python iapp_decrypt.py -p com.example.iapp

# 在应用里多点几个界面触发脚本加载...

# Ctrl+C 停止后，拉取解密结果
python iapp_decrypt.py --pull
```

### 4. 查看结果

```
output/
├── ui_events_main.xml      # UI 事件定义
├── ui_element_main_1.xml   # UI 元素
├── code_logic.txt          # 逻辑代码
└── fn_xxx.myu              # 函数定义
```

## 常见问题

**Q: 报错 "Failed to spawn"**

A: MIUI 等系统可能不兼容新版 Frida，降级到 16.1.4：
```bash
pip install frida==16.1.4 frida-tools==16.1.4
```

**Q: 没抓到任何脚本**

A: 
1. 确认是 iApp 应用（检查 `assets/lib.so`）
2. 多操作几个界面
3. 检查 `/data/local/tmp/iapp_out/` 权限

**Q: frida-server 闪退**

A: 关闭 SELinux：`adb shell "su -c 'setenforce 0'"`

## 技术细节

详细的逆向分析过程和 Hook 点发现过程，参见 [TECHNICAL.md](TECHNICAL.md)（如果你想了解是怎么找到这些 Hook 点的）。

## 免责声明

本工具仅供安全研究和学习。请勿用于非法用途。

## License

MIT
