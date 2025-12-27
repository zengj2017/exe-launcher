#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用加密工具 v4.0
支持: 单个文件 或 整个文件夹
文件夹会自动打包成 ZIP 后加密
"""

import os
import sys
import hashlib
import secrets
import struct
import zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def generate_64char_key():
    """生成64位十六进制密钥"""
    return secrets.token_hex(32)


def derive_aes_key(hex_key):
    """从64位十六进制密钥派生AES密钥"""
    return hashlib.sha256(hex_key.encode()).digest()


def zip_folder(folder_path, zip_path):
    """
    将文件夹打包成 ZIP
    :param folder_path: 文件夹路径
    :param zip_path: 输出 ZIP 路径
    """
    folder_name = os.path.basename(folder_path.rstrip('/\\'))

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                # 计算相对路径，保持文件夹结构
                arcname = os.path.join(folder_name, os.path.relpath(file_path, folder_path))
                zf.write(file_path, arcname)
                print(f"  添加: {arcname}")

    return zip_path


def encrypt_data(data, hex_key):
    """
    加密数据
    :param data: 原始数据
    :param hex_key: 64位十六进制密钥
    :return: IV + 加密数据
    """
    aes_key = derive_aes_key(hex_key)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data


def encrypt_file(input_path, output_path, hex_key):
    """
    加密文件或文件夹
    文件格式: [文件名长度2字节][原始文件名][IV 16字节][加密数据]
    """
    is_folder = os.path.isdir(input_path)

    if is_folder:
        # 文件夹：先打包成 ZIP
        folder_name = os.path.basename(input_path.rstrip('/\\'))
        temp_zip = f"{folder_name}_temp.zip"

        print(f"[*] 正在打包文件夹: {input_path}")
        zip_folder(input_path, temp_zip)

        original_filename = f"{folder_name}.zip"
        with open(temp_zip, 'rb') as f:
            file_data = f.read()

        # 删除临时 ZIP
        os.remove(temp_zip)
        print(f"[*] 打包完成，ZIP 大小: {len(file_data)} 字节")
    else:
        # 单个文件：直接读取
        original_filename = os.path.basename(input_path)
        with open(input_path, 'rb') as f:
            file_data = f.read()
        print(f"[*] 文件大小: {len(file_data)} 字节")

    print(f"[*] 原始名称: {original_filename}")

    # 加密
    filename_bytes = original_filename.encode('utf-8')
    encrypted = encrypt_data(file_data, hex_key)

    # 写入加密文件
    # 格式: [文件名长度 2字节][文件名][IV + 加密数据]
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<H', len(filename_bytes)))
        f.write(filename_bytes)
        f.write(encrypted)

    total_size = 2 + len(filename_bytes) + len(encrypted)
    print(f"[✓] 加密完成: {output_path}")
    print(f"[✓] 加密文件大小: {total_size} 字节")

    return original_filename


def main():
    print("=" * 70)
    print("通用加密工具 v4.0")
    print("支持: 单个文件 或 整个文件夹")
    print("=" * 70)

    # 输入路径
    input_path = input("\n请输入要加密的文件或文件夹路径: ").strip().strip('"').strip("'")

    if not os.path.exists(input_path):
        print("[✗] 错误: 路径不存在!")
        return

    is_folder = os.path.isdir(input_path)
    input_type = "文件夹" if is_folder else "文件"
    print(f"[*] 检测到: {input_type}")

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
    original_name = encrypt_file(input_path, output_file, hex_key)

    print("\n" + "=" * 70)
    print("[✓] 加密完成!")
    print("=" * 70)
    print(f"\n原始名称: {original_name}")
    print(f"加密密钥 (请妥善保管):")
    print(f"{hex_key}")
    print("\n" + "=" * 70)
    print(f"\n下一步操作:")
    print(f"1. 将 '{output_file}' 上传到云盘，获取直链")
    print(f"2. 将密钥添加到 keys.json 或发给用户")
    print(f"3. 用户验证后会收到 '{original_name}'")
    if is_folder:
        print(f"4. 用户自行解压 ZIP 文件使用")
    print()


if __name__ == "__main__":
    main()
