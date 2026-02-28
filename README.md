# iApp-Frida-Decrypt

基于 Frida 的 iApp 框架脚本解密工具。

## 简介

iApp 是一个 Android 快速开发框架，使用自定义的 `.iyu` 脚本格式，并将脚本加密存储在 `assets/lib.so` 中。现有的解密工具都基于 Xposed 框架，需要在手机上安装 LSPosed/EdXposed 等模块。

**本项目提供了一个纯 Frida 方案**，可以直接在 PC 端通过 USB 连接手机进行解密，无需安装任何 Xposed 模块。

## 原理

iApp 应用运行时，会通过 JNI 调用 `libygsiyu.so` 解密 `lib.so` 中的脚本，然后传递给 Java 层执行。本工具通过 Hook 以下关键方法来捕获解密后的脚本：

| 方法 | 作用 |
|------|------|
| `com.iapp.app.b.h3(Context, String)` | UI 界面加载入口 |
| `com.iapp.app.b.h4(Context, String, Object[])` | 逻辑脚本执行入口 |
| `com.iapp.app.b.h7(Context, Object, String)` | 事件脚本执行 |
| `com.iapp.app.run.mian.g()` | 读取 `this.r` 字段获取 UI/事件 XML |
| `com.iapp.app.run.mian.g(String)` | 捕获 UI 元素定义 XML |
| `com.iapp.app.e.ah(Object[], String)` | 捕获逻辑代码 |
| `bsh.Interpreter.eval(Reader)` | 捕获 BeanShell 脚本 |
| `c.b.a.a.w.c` (静态 HashMap) | 导出函数定义 |

## 环境要求

- Windows / macOS / Linux
- Python 3.8+
- Frida 16.x（推荐 16.1.4，与 MIUI 兼容性最好）
- 已 Root 的 Android 设备
- USB 调试已开启

## 安装

```bash
# 安装 Frida
pip install frida-tools==16.1.4

# 下载 frida-server（需与 frida-tools 版本匹配）
# ARM64: https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
# ARM32: https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm.xz
```

## 使用方法

### 1. 启动 frida-server

```bash
# 推送到手机
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# Root 权限运行
adb shell "su -c '/data/local/tmp/frida-server &'"
```

### 2. 运行解密脚本

```bash
# 方式一：Spawn 模式（推荐，从头捕获）
python iapp_decrypt.py -p com.example.iapp

# 方式二：Attach 模式（附加到已运行的应用）
python iapp_decrypt.py -a com.example.iapp
```

### 3. 获取解密结果

解密的脚本会保存到设备的 `/data/local/tmp/iapp_out/` 目录：

```bash
adb pull /data/local/tmp/iapp_out/ ./output/
```

## 输出文件说明

| 文件名格式 | 内容 |
|-----------|------|
| `ui_events_*.xml` | UI 界面事件定义 |
| `ui_element_*.xml` | UI 元素定义 |
| `code_*.txt` | 逻辑代码 |
| `fn_*.myu` | 函数定义 |

## 常见问题

### Q: 报错 "Failed to spawn" 或 frida-server 崩溃

A: 可能是 Frida 版本与系统不兼容。MIUI 用户建议使用 Frida 16.1.4。

```bash
# 降级 Frida
pip install frida==16.1.4 frida-tools==16.1.4
```

### Q: SELinux 导致无法注入

A: 临时关闭 SELinux：

```bash
adb shell "su -c 'setenforce 0'"
```

### Q: 没有捕获到任何脚本

A: 
1. 确保应用确实是 iApp 框架开发的（检查 `assets/lib.so` 是否存在）
2. 尝试在应用中多操作几个界面，触发脚本加载
3. 检查 `/data/local/tmp/iapp_out/` 目录权限

## 与 Xposed 方案的对比

| 特性 | Xposed 方案 | Frida 方案（本项目） |
|------|------------|---------------------|
| 需要安装模块 | 是 | 否 |
| 需要重启 | 是 | 否 |
| 支持非 Root | 否 | 否 |
| PC 端操作 | 否 | 是 |
| 实时调试 | 困难 | 方便 |
| 兼容性 | 依赖 Xposed 版本 | 依赖 Frida 版本 |

## 免责声明

本工具仅供安全研究和学习用途。请勿用于非法目的。使用本工具所产生的一切后果由使用者自行承担。

## License

MIT License

## 致谢

- [Frida](https://frida.re/) - 动态插桩框架
- iApp 逆向社区的前辈们
