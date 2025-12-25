#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户密钥生成器 - 一人一码
用途: 基于用户信息生成唯一的64位激活密钥
"""

import hashlib
import secrets
import json
import os
from datetime import datetime

class KeyGenerator:
    def __init__(self, master_key_path):
        """
        初始化密钥生成器
        :param master_key_path: 主密钥文件路径
        """
        if not os.path.exists(master_key_path):
            raise FileNotFoundError(f"主密钥文件不存在: {master_key_path}")

        with open(master_key_path, 'rb') as f:
            self.master_key = f.read()

        self.keys_db_path = "user_keys.json"
        self.keys_db = self._load_keys_db()

    def _load_keys_db(self):
        """加载已生成的密钥数据库"""
        if os.path.exists(self.keys_db_path):
            with open(self.keys_db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"keys": []}

    def _save_keys_db(self):
        """保存密钥数据库"""
        with open(self.keys_db_path, 'w', encoding='utf-8') as f:
            json.dump(self.keys_db, f, ensure_ascii=False, indent=2)

    def generate_key(self, user_id, user_name="", notes=""):
        """
        生成用户专属密钥
        :param user_id: 用户唯一标识(如: USER001, 邮箱等)
        :param user_name: 用户姓名(可选)
        :param notes: 备注信息(可选)
        :return: 64位十六进制密钥字符串
        """
        # 检查用户是否已生成过密钥
        for key_info in self.keys_db["keys"]:
            if key_info["user_id"] == user_id:
                print(f"[!] 警告: 用户 {user_id} 已存在密钥")
                choice = input("是否重新生成? (y/N): ").strip().lower()
                if choice != 'y':
                    return key_info["key"]

        # 生成唯一密钥: 主密钥 + 用户ID + 随机盐 + 时间戳
        salt = secrets.token_bytes(16)
        timestamp = datetime.now().isoformat()
        key_material = self.master_key + user_id.encode() + salt + timestamp.encode()

        # 使用SHA256生成64位十六进制字符串
        user_key = hashlib.sha256(key_material).hexdigest()

        # 保存到数据库
        key_record = {
            "user_id": user_id,
            "user_name": user_name,
            "key": user_key,
            "generated_at": timestamp,
            "notes": notes,
            "activated": False
        }

        # 更新或添加记录
        existing_index = None
        for i, key_info in enumerate(self.keys_db["keys"]):
            if key_info["user_id"] == user_id:
                existing_index = i
                break

        if existing_index is not None:
            self.keys_db["keys"][existing_index] = key_record
        else:
            self.keys_db["keys"].append(key_record)

        self._save_keys_db()

        return user_key

    def batch_generate(self, user_list):
        """
        批量生成密钥
        :param user_list: 用户列表 [{"user_id": "xxx", "user_name": "xxx", "notes": "xxx"}, ...]
        :return: 生成的密钥列表
        """
        results = []
        for user_info in user_list:
            user_id = user_info.get("user_id")
            user_name = user_info.get("user_name", "")
            notes = user_info.get("notes", "")

            key = self.generate_key(user_id, user_name, notes)
            results.append({
                "user_id": user_id,
                "user_name": user_name,
                "key": key
            })

        return results

    def export_keys(self, output_file="keys_export.txt"):
        """导出所有密钥到文本文件"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("用户激活密钥列表\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            for key_info in self.keys_db["keys"]:
                f.write(f"用户ID: {key_info['user_id']}\n")
                if key_info['user_name']:
                    f.write(f"用户名: {key_info['user_name']}\n")
                f.write(f"激活密钥: {key_info['key']}\n")
                f.write(f"生成时间: {key_info['generated_at']}\n")
                if key_info['notes']:
                    f.write(f"备注: {key_info['notes']}\n")
                f.write("-" * 70 + "\n\n")

        print(f"[✓] 密钥已导出到: {output_file}")

    def list_keys(self):
        """列出所有已生成的密钥"""
        if not self.keys_db["keys"]:
            print("[!] 还没有生成任何密钥")
            return

        print("\n" + "=" * 70)
        print(f"已生成密钥数量: {len(self.keys_db['keys'])}")
        print("=" * 70)

        for i, key_info in enumerate(self.keys_db["keys"], 1):
            print(f"\n[{i}] 用户ID: {key_info['user_id']}")
            if key_info['user_name']:
                print(f"    用户名: {key_info['user_name']}")
            print(f"    密钥: {key_info['key']}")
            print(f"    生成时间: {key_info['generated_at']}")
            if key_info['notes']:
                print(f"    备注: {key_info['notes']}")

def main():
    print("=" * 70)
    print("用户密钥生成器 v1.0 - 一人一码")
    print("=" * 70)

    # 选择主密钥文件
    master_key_file = input("\n请输入主密钥文件路径 (如: program_master.key): ").strip()

    try:
        generator = KeyGenerator(master_key_file)
    except FileNotFoundError as e:
        print(f"[✗] 错误: {e}")
        return

    while True:
        print("\n" + "-" * 70)
        print("请选择操作:")
        print("1. 生成单个用户密钥")
        print("2. 批量生成密钥")
        print("3. 查看已生成的密钥")
        print("4. 导出密钥到文件")
        print("5. 退出")
        print("-" * 70)

        choice = input("\n请输入选项 (1-5): ").strip()

        if choice == "1":
            print("\n--- 生成单个用户密钥 ---")
            user_id = input("用户ID (必填): ").strip()
            if not user_id:
                print("[✗] 用户ID不能为空")
                continue

            user_name = input("用户姓名 (可选): ").strip()
            notes = input("备注信息 (可选): ").strip()

            key = generator.generate_key(user_id, user_name, notes)

            print("\n" + "=" * 70)
            print("[✓] 密钥生成成功!")
            print("=" * 70)
            print(f"用户ID: {user_id}")
            if user_name:
                print(f"用户名: {user_name}")
            print(f"\n激活密钥: {key}")
            print("\n请将此密钥提供给用户")
            print("=" * 70)

        elif choice == "2":
            print("\n--- 批量生成密钥 ---")
            print("请输入用户信息，每行一个，格式: 用户ID,用户名,备注")
            print("输入空行结束输入")
            print("示例: USER001,张三,VIP用户")

            user_list = []
            while True:
                line = input().strip()
                if not line:
                    break

                parts = line.split(',')
                user_info = {
                    "user_id": parts[0].strip(),
                    "user_name": parts[1].strip() if len(parts) > 1 else "",
                    "notes": parts[2].strip() if len(parts) > 2 else ""
                }
                user_list.append(user_info)

            if user_list:
                results = generator.batch_generate(user_list)
                print(f"\n[✓] 成功生成 {len(results)} 个密钥")

        elif choice == "3":
            generator.list_keys()

        elif choice == "4":
            output_file = input("\n输出文件名 (默认: keys_export.txt): ").strip()
            if not output_file:
                output_file = "keys_export.txt"
            generator.export_keys(output_file)

        elif choice == "5":
            print("\n再见!")
            break

        else:
            print("[✗] 无效选项，请重新选择")

if __name__ == "__main__":
    main()
