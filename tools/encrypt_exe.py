#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXE文件加密工具 v2.0
用途: 将原始EXE文件加密，上传到云端
使用64位十六进制密钥加密，与launcher解密兼容
"""

import os
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def generate_64char_key():
    """生成64位十六进制密钥"""
    return secrets.token_hex(32)  # 32字节 = 64个十六进制字符


def derive_aes_key(hex_key):
    """从64位十六进制密钥派生AES密钥（与launcher一致）"""
    return hashlib.sha256(hex_key.encode()).digest()


def encrypt_exe(input_exe_path, output_encrypted_path, hex_key):
    """
    加密EXE文件
    :param input_exe_path: 原始EXE文件路径
    :param output_encrypted_path: 输出加密文件路径
    :param hex_key: 64位十六进制密钥
    """
    print(f"[*] 正在读取文件: {input_exe_path}")

    with open(input_exe_path, 'rb') as f:
        exe_data = f.read()

    print(f"[*] 文件大小: {len(exe_data)} 字节")

    # 从64位密钥派生AES密钥（与launcher解密方式一致）
    aes_key = derive_aes_key(hex_key)

    # 使用AES-256-CBC加密
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(exe_data, AES.block_size))

    # 文件格式: IV(16字节) + 加密数据
    with open(output_encrypted_path, 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)

    print(f"[✓] 加密完成: {output_encrypted_path}")
    print(f"[✓] 加密文件大小: {len(iv) + len(encrypted_data)} 字节")


def main():
    print("=" * 70)
    print("EXE文件加密工具 v2.0")
    print("=" * 70)

    # 输入文件路径
    input_exe = input("\n请输入原始EXE文件路径: ").strip()

    if not os.path.exists(input_exe):
        print("[✗] 错误: 文件不存在!")
        return

    # 选择密钥方式
    print("\n密钥选项:")
    print("1. 自动生成新密钥")
    print("2. 使用已有的64位密钥")
    choice = input("\n请选择 (1/2): ").strip()

    if choice == "2":
        hex_key = input("请输入64位十六进制密钥: ").strip()
        if len(hex_key) != 64:
            print(f"[✗] 错误: 密钥长度必须是64位，当前长度: {len(hex_key)}")
            return
        try:
            int(hex_key, 16)  # 验证是否为有效十六进制
        except ValueError:
            print("[✗] 错误: 密钥必须是有效的十六进制字符串")
            return
    else:
        hex_key = generate_64char_key()
        print(f"\n[✓] 已生成新密钥")

    # 生成输出文件名
    output_encrypted = "program_encrypted.dat"

    # 加密文件
    print("\n[*] 开始加密...")
    encrypt_exe(input_exe, output_encrypted, hex_key)

    print("\n" + "=" * 70)
    print("[✓] 加密完成!")
    print("=" * 70)
    print(f"\n加密密钥 (请妥善保管):")
    print(f"{hex_key}")
    print("\n" + "=" * 70)
    print(f"\n下一步操作:")
    print(f"1. 将 '{output_encrypted}' 上传到云盘，获取直链")
    print(f"2. 将上述密钥添加到 config.json 的 valid_keys 中")
    print(f"3. 用户使用此密钥即可解密运行程序")
    print()


if __name__ == "__main__":
    main()
