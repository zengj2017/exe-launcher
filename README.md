# EXE 加密分发系统

一人一码的 EXE 文件加密分发方案，支持云盘下载、密钥验证和时效控制。

## 项目结构

```
├── dist/                    # 分发文件
│   ├── launcher.py          # 启动器源码
│   ├── launcher_v2.py       # 时效版启动器
│   ├── config.json          # 配置文件
│   └── build_windows.bat    # Windows 编译脚本
├── tools/                   # 管理工具
│   ├── encrypt_exe.py       # EXE 加密工具
│   ├── generate_keys.py     # 密钥生成器
│   └── requirements.txt     # 依赖
└── .github/workflows/       # GitHub Actions
    └── build.yml            # 自动编译
```

## 快速开始

### 1. 安装依赖

```bash
pip install pycryptodome
```

### 2. 加密 EXE 文件

```bash
cd tools
python encrypt_exe.py
# 输入要加密的 EXE 文件路径
```

### 3. 配置 config.json

```json
{
    "download_url": "https://your-cloud-storage.com/encrypted.dat",
    "valid_keys": [
        {
            "key": "64位密钥",
            "validity_days": 30,
            "user_id": "user001"
        }
    ]
}
```

### 4. 编译启动器

**方法 A: GitHub Actions（推荐）**
- 推送代码到 GitHub
- 进入 Actions 页面
- 运行 "Build Launcher Executables"
- 下载 windows-executables

**方法 B: 本地编译（Windows）**
```bash
cd dist
build_windows.bat
```

### 5. 部署

将以下文件放在同一目录：
- `launcher.exe`
- `config.json`

用户输入密钥后，程序会下载加密文件并解密运行。

## 密钥验证

| 版本 | 说明 |
|------|------|
| launcher.exe | 基础版，支持永久密钥 |
| launcher_v2.exe | 时效版，支持有效期控制 |

## 安全特性

- AES-256-CBC 加密
- 一人一码，独立密钥
- 本地验证，无需联网
- 临时文件运行，自动清理

## License

MIT
