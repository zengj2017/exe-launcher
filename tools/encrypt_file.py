#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用文件加密工具 v3.0
用途: 将任意文件加密，上传到云端
支持: EXE, DLL, ZIP, 图片, 文档等所有文件类型
"""

import os
import hashlib
import secrets
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def generate_64char_key():
    """生成64位十六进制密钥"""
    return secrets.token_hex(32)


def derive_aes_key(hex_key):
    """从64位十六进制密钥派生AES密钥"""
    return hashlib.sha256(hex_key.encode()).digest()


def encrypt_file(input_path, output_path, hex_key):
    """
    加密任意文件
    文件格式: [文件名长度2字节][原始文件名][IV 16字节][加密数据]
    """
    print(f"[*] 正在读取文件: {input_path}")

    # 获取原始文件名
    original_filename = os.path.basename(input_path)
    filename_bytes = original_filename.encode('utf-8')

    with open(input_path, 'rb') as f:
        file_data = f.read()

    print(f"[*] 文件大小: {len(file_data)} 字节")
    print(f"[*] 原始文件名: {original_filename}")

    # 派生 AES 密钥
    aes_key = derive_aes_key(hex_key)

    # 加密
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    # 写入加密文件
    # 格式: [文件名长度 2字节][文件名][IV 16字节][加密数据]
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<H', len(filename_bytes)))  # 文件名长度
        f.write(filename_bytes)                          # 原始文件名
        f.write(iv)                                      # IV
        f.write(encrypted_data)                          # 加密数据

    total_size = 2 + len(filename_bytes) + 16 + len(encrypted_data)
    print(f"[✓] 加密完成: {output_path}")
    print(f"[✓] 加密文件大小: {total_size} 字节")

    return original_filename


def main():
    print("=" * 70)
    print("通用文件加密工具 v3.0")
    print("支持所有文件类型: EXE, DLL, ZIP, 图片, 文档等")
    print("=" * 70)

    # 输入文件路径
    input_file = input("\n请输入要加密的文件路径: ").strip().strip('"').strip("'")

    if not os.path.exists(input_file):
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
            int(hex_key, 16)
        except ValueError:
            print("[✗] 错误: 密钥必须是有效的十六进制字符串")
            return
    else:
        hex_key = generate_64char_key()
        print(f"\n[✓] 已生成新密钥")

    # 输出文件名
    output_file = "program_encrypted.dat"

    # 加密
    print("\n[*] 开始加密...")
    original_name = encrypt_file(input_file, output_file, hex_key)

    print("\n" + "=" * 70)
    print("[✓] 加密完成!")
    print("=" * 70)
    print(f"\n原始文件: {original_name}")
    print(f"加密密钥 (请妥善保管):")
    print(f"{hex_key}")
    print("\n" + "=" * 70)
    print(f"\n下一步操作:")
    print(f"1. 将 '{output_file}' 上传到云盘，获取直链")
    print(f"2. 将密钥添加到 config.json 的 valid_keys 中")
    print(f"3. 用户使用此密钥即可解密运行程序")
    print()


if __name__ == "__main__":
    main()
