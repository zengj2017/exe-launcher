#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整示例：从加密到分发的完整流程演示
仅用于测试和学习
"""

import os
import sys

def print_section(title):
    """打印分节标题"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def demo_workflow():
    """演示完整工作流程"""
    print_section("EXE加密分发系统 - 完整流程演示")

    print("""
这是一个完整的EXE文件加密分发系统，支持：
✅ 一人一码的密钥系统
✅ 云盘直链下载
✅ 本地密钥验证
✅ AES-256加密保护

""")

    print_section("管理员操作流程")
    print("""
1️⃣  加密原始EXE文件
    命令: python tools/encrypt_exe.py
    输入: 原始EXE文件路径
    输出:
    - 加密文件 (program_encrypted.dat)
    - 主密钥文件 (program_master.key) ⚠️ 重要！

2️⃣  上传加密文件到云盘
    支持平台:
    - 阿里云OSS (推荐)
    - 蓝奏云
    - 百度网盘
    获取: 直链下载地址

3️⃣  生成用户激活密钥
    命令: python tools/generate_keys.py
    输入: 主密钥文件路径
    操作:
    - 单个生成: 输入用户ID、姓名、备注
    - 批量生成: 输入用户列表
    - 导出密钥: 生成密钥文本文件

4️⃣  配置下载脚本
    编辑: dist/download.bat
    修改: DOWNLOAD_URL 为实际云盘直链

5️⃣  编译启动器
    命令: pyinstaller --onefile --windowed --name=launcher dist/launcher.py
    输出: launcher.exe

6️⃣  打包分发文件
    打包以下文件给用户:
    - download.bat
    - launcher.exe
    - 使用说明.txt
""")

    print_section("用户使用流程")
    print("""
1️⃣  运行下载脚本
    双击: download.bat
    功能: 自动从云端下载加密程序

2️⃣  启动程序
    双击: launcher.exe
    输入: 64位激活密钥
    结果: 验证通过后自动运行程序
""")

    print_section("安全特性")
    print("""
🔐 一人一码机制
   - 每个用户独立密钥
   - SHA256哈希算法
   - 无法从一个密钥推导其他密钥

🔐 AES-256加密
   - 军事级别加密强度
   - CBC模式
   - 256位密钥长度

🔐 本地验证
   - 无需联网验证
   - 保护用户隐私
   - 防止中间人攻击

🔐 防破解措施
   - 加密文件不包含密钥
   - PE头验证
   - 临时文件自动清理
""")

    print_section("快速开始")
    print("""
步骤1: 安装依赖
    cd tools
    pip install -r requirements.txt

步骤2: 加密您的EXE文件
    python encrypt_exe.py

步骤3: 上传到云盘并获取直链

步骤4: 生成用户密钥
    python generate_keys.py

步骤5: 配置并分发
    编辑 dist/download.bat
    编译 dist/launcher.py
    打包分发给用户

详细说明请阅读: README.md
""")

    print_section("文件清单")

    files_structure = """
项目文件/
├── tools/                      管理工具目录
│   ├── encrypt_exe.py         ✅ EXE加密工具
│   ├── generate_keys.py       ✅ 密钥生成器
│   └── requirements.txt       ✅ Python依赖列表
│
├── dist/                      分发文件目录
│   ├── download.bat          ✅ 自动下载脚本
│   ├── launcher.py           ✅ 启动器源码
│   ├── build_launcher.txt    ✅ 编译说明
│   └── 使用说明.txt           ✅ 用户使用指南
│
├── README.md                 ✅ 完整使用文档
└── DEMO.py                   ✅ 本示例文件
"""
    print(files_structure)

    print_section("技术架构")
    print("""
┌─────────────────────────────────────────────────────────────┐
│                        管理员端                              │
├─────────────────────────────────────────────────────────────┤
│  原始EXE → [加密工具] → 加密DAT + 主密钥                      │
│  主密钥 → [密钥生成器] → 用户密钥(一人一码)                   │
│  加密DAT → [云盘上传] → 获取直链                             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                        用户端                                │
├─────────────────────────────────────────────────────────────┤
│  [下载脚本] → 从云盘下载加密DAT                              │
│  [启动器] → 输入密钥 → 验证 → 解密 → 运行程序                │
└─────────────────────────────────────────────────────────────┘
""")

    print_section("总结")
    print("""
本系统提供了一套完整的商业软件分发解决方案：

✅ 安全可靠 - AES-256加密 + 一人一码
✅ 易于使用 - 自动化脚本 + 图形界面
✅ 灵活分发 - 支持多种云盘平台
✅ 便于管理 - 密钥数据库 + 批量生成

适用场景:
- 商业软件授权销售
- 内部工具定向发布
- 企业系统安全部署
- 付费软件会员制度

现在就开始使用吧！
详细文档: README.md
""")

if __name__ == "__main__":
    demo_workflow()
