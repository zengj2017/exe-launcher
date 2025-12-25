#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXE文件加密工具
用途: 将原始EXE文件加密，上传到云端
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def generate_master_key():
    """生成主密钥(用于加密EXE)"""
    return get_random_bytes(32)  # 256-bit key

def derive_key_from_password(password):
    """从64位密钥字符串派生AES密钥"""
    # 使用SHA256确保密钥长度为32字节
    return hashlib.sha256(password.encode()).digest()

def encrypt_exe(input_exe_path, output_encrypted_path, master_key):
    """
    加密EXE文件
    :param input_exe_path: 原始EXE文件路径
    :param output_encrypted_path: 输出加密文件路径
    :param master_key: 主密钥(32字节)
    """
    print(f"[*] 正在读取文件: {input_exe_path}")

    with open(input_exe_path, 'rb') as f:
        exe_data = f.read()

    print(f"[*] 文件大小: {len(exe_data)} 字节")

    # 使用AES-256-CBC加密
    iv = get_random_bytes(16)
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(exe_data, AES.block_size))

    # 文件格式: IV(16字节) + 加密数据
    with open(output_encrypted_path, 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)

    print(f"[✓] 加密完成: {output_encrypted_path}")
    print(f"[✓] 加密文件大小: {len(iv) + len(encrypted_data)} 字节")

def save_master_key(master_key, key_file_path):
    """保存主密钥到文件"""
    with open(key_file_path, 'wb') as f:
        f.write(master_key)
    print(f"[✓] 主密钥已保存到: {key_file_path}")
    print(f"[!] 请妥善保管此文件，用于生成用户密钥")

def main():
    print("=" * 60)
    print("EXE文件加密工具 v1.0")
    print("=" * 60)

    # 输入文件路径
    input_exe = input("\n请输入原始EXE文件路径: ").strip()

    if not os.path.exists(input_exe):
        print("[✗] 错误: 文件不存在!")
        return

    # 生成输出文件名
    base_name = os.path.splitext(os.path.basename(input_exe))[0]
    output_encrypted = f"{base_name}_encrypted.dat"
    master_key_file = f"{base_name}_master.key"

    # 生成主密钥
    print("\n[*] 生成主密钥...")
    master_key = generate_master_key()

    # 加密文件
    print("[*] 开始加密...")
    encrypt_exe(input_exe, output_encrypted, master_key)

    # 保存主密钥
    save_master_key(master_key, master_key_file)

    print("\n" + "=" * 60)
    print("[✓] 所有操作完成!")
    print("=" * 60)
    print(f"\n下一步操作:")
    print(f"1. 将 '{output_encrypted}' 上传到云盘")
    print(f"2. 获取云盘直链地址")
    print(f"3. 使用 generate_keys.py 生成用户密钥")
    print(f"4. 保管好 '{master_key_file}'，删除原始EXE文件")
    print()

if __name__ == "__main__":
    main()
