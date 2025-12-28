#!/usr/bin/env python3
"""
EXE 加壳保护工具
将原始 EXE 加密并打包成带密钥验证的新 EXE
"""

import os
import sys
import hashlib
import secrets
import base64
import tempfile
import shutil
import subprocess

# 生成的加壳程序模板
WRAPPER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
受保护的程序 - 需要密钥验证才能运行
"""

import os
import sys
import hashlib
import tempfile
import subprocess
import ctypes
import json
import urllib.request
import base64
from datetime import datetime

# ============ 配置区域 ============
ENCRYPTED_DATA = {encrypted_data}
ORIGINAL_FILENAME = {original_filename}
KEY_HASH = {key_hash}  # 密钥的 SHA256 哈希（用于快速验证）
KEYS_URL = {keys_url}  # 云端密钥验证地址（可选）
CONTACT_INFO = {contact_info}
# =================================

def derive_key(user_key: str) -> bytes:
    """从用户密钥派生 AES 密钥"""
    return hashlib.sha256(user_key.encode()).digest()

def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """AES-256-CBC 解密"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        # 使用纯 Python 实现（简化版）
        return simple_decrypt(encrypted, key)

    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def simple_decrypt(encrypted: bytes, key: bytes) -> bytes:
    """简化的 XOR 解密（备用方案）"""
    iv = encrypted[:16]
    ciphertext = encrypted[16:]

    # 使用 key + iv 生成密钥流
    result = bytearray()
    key_stream = hashlib.sha256(key + iv).digest()

    for i, byte in enumerate(ciphertext):
        if i % 32 == 0 and i > 0:
            key_stream = hashlib.sha256(key_stream + iv).digest()
        result.append(byte ^ key_stream[i % 32])

    # 去除 PKCS7 填充
    padding_len = result[-1]
    if padding_len <= 16:
        result = result[:-padding_len]

    return bytes(result)

def verify_key_online(user_key: str) -> tuple:
    """在线验证密钥"""
    if not KEYS_URL:
        return True, ""

    try:
        req = urllib.request.Request(KEYS_URL, headers={{"User-Agent": "ProtectedApp/1.0"}})
        with urllib.request.urlopen(req, timeout=10) as response:
            keys_data = json.loads(response.read().decode())

        for key_info in keys_data.get("keys", []):
            if key_info.get("key") == user_key:
                if not key_info.get("enabled", True):
                    return False, "此密钥已被禁用"

                expires = key_info.get("expires", "")
                if expires:
                    try:
                        exp_date = datetime.strptime(expires, "%Y-%m-%d")
                        if datetime.now() > exp_date:
                            return False, f"密钥已过期 ({{expires}})"
                    except:
                        pass

                return True, key_info.get("user", "")

        return False, "密钥未授权"
    except Exception as e:
        # 网络错误时，仅使用本地验证
        return True, ""

def verify_key_local(user_key: str) -> bool:
    """本地验证密钥（哈希比对）"""
    key_hash = hashlib.sha256(hashlib.sha256(user_key.encode()).digest()).hexdigest()
    return key_hash == KEY_HASH

def show_message(title: str, message: str, error: bool = False):
    """显示消息框"""
    try:
        MB_OK = 0x0
        MB_ICONERROR = 0x10
        MB_ICONINFO = 0x40
        icon = MB_ICONERROR if error else MB_ICONINFO
        ctypes.windll.user32.MessageBoxW(0, message, title, MB_OK | icon)
    except:
        print(f"{{title}}: {{message}}")

def get_key_input() -> str:
    """获取用户输入的密钥"""
    try:
        import tkinter as tk
        from tkinter import simpledialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        key = simpledialog.askstring(
            "密钥验证",
            "请输入 64 位授权密钥：",
            parent=root
        )
        root.destroy()
        return key if key else ""
    except:
        return input("请输入 64 位授权密钥: ")

def main():
    # 获取密钥
    user_key = get_key_input()

    if not user_key:
        show_message("验证失败", "未输入密钥", error=True)
        sys.exit(1)

    # 验证密钥格式
    user_key = user_key.strip().lower()
    if len(user_key) != 64:
        show_message("验证失败", "密钥格式错误，需要 64 位十六进制字符", error=True)
        sys.exit(1)

    # 本地验证
    if not verify_key_local(user_key):
        show_message("验证失败", "密钥无效", error=True)
        sys.exit(1)

    # 在线验证（可选）
    online_valid, info = verify_key_online(user_key)
    if not online_valid:
        show_message("验证失败", info, error=True)
        sys.exit(1)

    # 解密程序
    try:
        encrypted_bytes = base64.b64decode(ENCRYPTED_DATA)
        aes_key = derive_key(user_key)
        decrypted = decrypt_data(encrypted_bytes, aes_key)
    except Exception as e:
        show_message("解密失败", f"密钥无法解密此程序\\n{{str(e)}}", error=True)
        sys.exit(1)

    # 写入临时文件并运行
    try:
        temp_dir = tempfile.mkdtemp()
        temp_exe = os.path.join(temp_dir, ORIGINAL_FILENAME)

        with open(temp_exe, 'wb') as f:
            f.write(decrypted)

        # 运行程序
        if sys.platform == 'win32':
            os.startfile(temp_exe)
        else:
            subprocess.Popen([temp_exe], shell=True)

    except Exception as e:
        show_message("运行失败", f"无法启动程序\\n{{str(e)}}", error=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
'''

def encrypt_exe(exe_path: str, user_key: str) -> bytes:
    """加密 EXE 文件"""
    # 尝试使用 pycryptodome
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        with open(exe_path, 'rb') as f:
            data = f.read()

        key = hashlib.sha256(user_key.encode()).digest()
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        return iv + encrypted
    except ImportError:
        # 使用简化的 XOR 加密
        return simple_encrypt(exe_path, user_key)

def simple_encrypt(exe_path: str, user_key: str) -> bytes:
    """简化的 XOR 加密"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    key = hashlib.sha256(user_key.encode()).digest()
    iv = secrets.token_bytes(16)

    # PKCS7 填充
    padding_len = 16 - (len(data) % 16)
    data = data + bytes([padding_len] * padding_len)

    # XOR 加密
    result = bytearray()
    key_stream = hashlib.sha256(key + iv).digest()

    for i, byte in enumerate(data):
        if i % 32 == 0 and i > 0:
            key_stream = hashlib.sha256(key_stream + iv).digest()
        result.append(byte ^ key_stream[i % 32])

    return iv + bytes(result)

def generate_key() -> str:
    """生成随机 64 位十六进制密钥"""
    return secrets.token_hex(32)

def create_protected_exe(
    input_exe: str,
    output_dir: str,
    user_key: str = None,
    keys_url: str = "",
    contact_info: str = "联系管理员获取授权"
) -> dict:
    """
    创建受保护的 EXE

    Args:
        input_exe: 原始 EXE 路径
        output_dir: 输出目录
        user_key: 指定密钥（可选，不指定则自动生成）
        keys_url: 云端密钥验证地址（可选）
        contact_info: 联系信息

    Returns:
        包含输出文件路径和密钥的字典
    """
    if not os.path.exists(input_exe):
        raise FileNotFoundError(f"文件不存在: {input_exe}")

    # 生成或使用指定密钥
    if user_key:
        if len(user_key) != 64:
            raise ValueError("密钥必须是 64 位十六进制字符")
    else:
        user_key = generate_key()

    # 加密 EXE
    print(f"正在加密: {input_exe}")
    encrypted_data = encrypt_exe(input_exe, user_key)
    encrypted_b64 = base64.b64encode(encrypted_data).decode()

    # 计算密钥哈希（双重哈希，用于本地验证）
    key_hash = hashlib.sha256(hashlib.sha256(user_key.encode()).digest()).hexdigest()

    # 原始文件名
    original_filename = os.path.basename(input_exe)

    # 生成包装程序
    wrapper_code = WRAPPER_TEMPLATE.format(
        encrypted_data=repr(encrypted_b64),
        original_filename=repr(original_filename),
        key_hash=repr(key_hash),
        keys_url=repr(keys_url) if keys_url else "None",
        contact_info=repr(contact_info)
    )

    # 保存包装程序
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(original_filename)[0]
    wrapper_py = os.path.join(output_dir, f"{base_name}_protected.py")

    with open(wrapper_py, 'w', encoding='utf-8') as f:
        f.write(wrapper_code)

    print(f"生成包装程序: {wrapper_py}")

    # 尝试编译为 EXE
    output_exe = None
    try:
        output_exe = compile_to_exe(wrapper_py, output_dir)
    except Exception as e:
        print(f"注意: 无法自动编译 EXE ({e})")
        print("请手动使用 PyInstaller 编译")

    return {
        "wrapper_py": wrapper_py,
        "output_exe": output_exe,
        "key": user_key,
        "key_hash": key_hash,
        "original_size": os.path.getsize(input_exe),
        "encrypted_size": len(encrypted_data)
    }

def compile_to_exe(py_file: str, output_dir: str) -> str:
    """使用 PyInstaller 编译为 EXE"""
    try:
        import PyInstaller.__main__
    except ImportError:
        raise ImportError("需要安装 PyInstaller: pip install pyinstaller")

    base_name = os.path.splitext(os.path.basename(py_file))[0]

    PyInstaller.__main__.run([
        py_file,
        '--onefile',
        '--windowed',
        '--name', base_name,
        '--distpath', output_dir,
        '--workpath', os.path.join(output_dir, 'build'),
        '--specpath', os.path.join(output_dir, 'build'),
        '--clean',
        '--noconfirm'
    ])

    output_exe = os.path.join(output_dir, f"{base_name}.exe")
    if os.path.exists(output_exe):
        return output_exe
    return None

def main():
    import argparse

    parser = argparse.ArgumentParser(description='EXE 加壳保护工具')
    parser.add_argument('input', help='输入的 EXE 文件路径')
    parser.add_argument('-o', '--output', default='./protected', help='输出目录')
    parser.add_argument('-k', '--key', help='指定 64 位密钥（可选）')
    parser.add_argument('--keys-url', help='云端密钥验证地址（可选）')
    parser.add_argument('--contact', default='联系管理员获取授权', help='联系信息')

    args = parser.parse_args()

    try:
        result = create_protected_exe(
            args.input,
            args.output,
            args.key,
            args.keys_url,
            args.contact
        )

        print("\n" + "=" * 50)
        print("加壳完成!")
        print("=" * 50)
        print(f"包装程序: {result['wrapper_py']}")
        if result['output_exe']:
            print(f"输出 EXE: {result['output_exe']}")
        print(f"原始大小: {result['original_size']:,} 字节")
        print(f"加密大小: {result['encrypted_size']:,} 字节")
        print(f"\n授权密钥: {result['key']}")
        print("\n请妥善保管密钥，用户需要此密钥才能运行程序")

    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
