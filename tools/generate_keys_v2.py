#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户密钥生成器 v2.0 - 支持时效性验证
用途: 基于用户信息生成唯一的64位激活密钥，支持有效期限制
"""

import hashlib
import secrets
import json
import os
import time
from datetime import datetime, timedelta

class KeyGeneratorV2:
    def __init__(self, master_key_path):
        """
        初始化密钥生成器
        :param master_key_path: 主密钥文件路径
        """
        if not os.path.exists(master_key_path):
            raise FileNotFoundError(f"主密钥文件不存在: {master_key_path}")

        with open(master_key_path, 'rb') as f:
            self.master_key = f.read()

        self.keys_db_path = "user_keys_v2.json"
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

    def generate_key(self, user_id, user_name="", notes="", validity_days=None):
        """
        生成用户专属密钥（支持时效性）
        :param user_id: 用户唯一标识
        :param user_name: 用户姓名(可选)
        :param notes: 备注信息(可选)
        :param validity_days: 有效天数(None表示永久有效)
        :return: 64位十六进制密钥字符串
        """
        # 检查用户是否已生成过密钥
        for key_info in self.keys_db["keys"]:
            if key_info["user_id"] == user_id:
                print(f"[!] 警告: 用户 {user_id} 已存在密钥")
                choice = input("是否重新生成? (y/N): ").strip().lower()
                if choice != 'y':
                    return key_info["key"]

        # 计算过期时间戳
        generated_timestamp = int(time.time())
        if validity_days is not None:
            expiry_timestamp = generated_timestamp + (validity_days * 86400)
            expiry_date = datetime.fromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        else:
            expiry_timestamp = None
            expiry_date = "永久有效"

        # 生成密钥数据
        # 格式: 主密钥|用户ID|有效期时间戳|随机盐
        salt = secrets.token_bytes(16)
        key_data = f"{self.master_key.hex()}|{user_id}|{expiry_timestamp}|{salt.hex()}"

        # 生成64位密钥（前60位为哈希，后4位为校验码）
        key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:60]

        # 生成校验码（包含时效信息的指纹）
        if validity_days is not None:
            validity_fingerprint = hashlib.md5(str(validity_days).encode()).hexdigest()[:4]
        else:
            validity_fingerprint = "0000"

        user_key = key_hash + validity_fingerprint

        # 保存到数据库
        key_record = {
            "user_id": user_id,
            "user_name": user_name,
            "key": user_key,
            "generated_at": datetime.fromtimestamp(generated_timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            "generated_timestamp": generated_timestamp,
            "validity_days": validity_days,
            "expiry_timestamp": expiry_timestamp,
            "expiry_date": expiry_date,
            "notes": notes,
            "activated": False,
            "first_activation": None,
            "last_activation": None
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
        :param user_list: 用户列表 [{"user_id": "xxx", "user_name": "xxx", "validity_days": 30, ...}, ...]
        :return: 生成的密钥列表
        """
        results = []
        for user_info in user_list:
            user_id = user_info.get("user_id")
            user_name = user_info.get("user_name", "")
            notes = user_info.get("notes", "")
            validity_days = user_info.get("validity_days")

            key = self.generate_key(user_id, user_name, notes, validity_days)
            results.append({
                "user_id": user_id,
                "user_name": user_name,
                "key": key,
                "validity_days": validity_days
            })

        return results

    def export_keys(self, output_file="keys_export_v2.txt"):
        """导出所有密钥到文本文件"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("用户激活密钥列表 (V2 - 支持时效性)\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            for key_info in self.keys_db["keys"]:
                f.write(f"用户ID: {key_info['user_id']}\n")
                if key_info['user_name']:
                    f.write(f"用户名: {key_info['user_name']}\n")
                f.write(f"激活密钥: {key_info['key']}\n")
                f.write(f"生成时间: {key_info['generated_at']}\n")

                if key_info.get('validity_days'):
                    f.write(f"有效期: {key_info['validity_days']} 天\n")
                    f.write(f"过期时间: {key_info['expiry_date']}\n")
                else:
                    f.write(f"有效期: 永久有效\n")

                if key_info['notes']:
                    f.write(f"备注: {key_info['notes']}\n")
                f.write("-" * 80 + "\n\n")

        print(f"[✓] 密钥已导出到: {output_file}")

    def list_keys(self):
        """列出所有已生成的密钥"""
        if not self.keys_db["keys"]:
            print("[!] 还没有生成任何密钥")
            return

        print("\n" + "=" * 80)
        print(f"已生成密钥数量: {len(self.keys_db['keys'])}")
        print("=" * 80)

        current_time = int(time.time())

        for i, key_info in enumerate(self.keys_db["keys"], 1):
            print(f"\n[{i}] 用户ID: {key_info['user_id']}")
            if key_info['user_name']:
                print(f"    用户名: {key_info['user_name']}")
            print(f"    密钥: {key_info['key']}")
            print(f"    生成时间: {key_info['generated_at']}")

            # 显示有效期状态
            if key_info.get('validity_days'):
                print(f"    有效期: {key_info['validity_days']} 天")
                expiry_timestamp = key_info.get('expiry_timestamp')
                if expiry_timestamp:
                    if current_time > expiry_timestamp:
                        print(f"    状态: ❌ 已过期 ({key_info['expiry_date']})")
                    else:
                        remaining_days = (expiry_timestamp - current_time) // 86400
                        print(f"    状态: ✅ 有效 (还剩 {remaining_days} 天)")
                        print(f"    过期时间: {key_info['expiry_date']}")
            else:
                print(f"    有效期: ♾️  永久有效")

            if key_info['notes']:
                print(f"    备注: {key_info['notes']}")

    def extend_validity(self, user_id, additional_days):
        """
        延长密钥有效期
        :param user_id: 用户ID
        :param additional_days: 增加的天数
        """
        for key_info in self.keys_db["keys"]:
            if key_info["user_id"] == user_id:
                if key_info.get('expiry_timestamp'):
                    new_expiry = key_info['expiry_timestamp'] + (additional_days * 86400)
                    key_info['expiry_timestamp'] = new_expiry
                    key_info['expiry_date'] = datetime.fromtimestamp(new_expiry).strftime('%Y-%m-%d %H:%M:%S')

                    if key_info.get('validity_days'):
                        key_info['validity_days'] += additional_days

                    self._save_keys_db()
                    print(f"[✓] 已为用户 {user_id} 延长 {additional_days} 天")
                    print(f"[✓] 新的过期时间: {key_info['expiry_date']}")
                    return
                else:
                    print(f"[!] 用户 {user_id} 的密钥为永久有效，无需延期")
                    return

        print(f"[✗] 未找到用户: {user_id}")

def get_validity_preset():
    """获取预设的有效期选项"""
    print("\n请选择有效期:")
    print("1. 1天 (试用版)")
    print("2. 7天 (周卡)")
    print("3. 30天 (月卡)")
    print("4. 90天 (季卡)")
    print("5. 365天 (年卡)")
    print("6. 永久有效")
    print("7. 自定义天数")

    choice = input("\n请输入选项 (1-7): ").strip()

    validity_map = {
        "1": 1,
        "2": 7,
        "3": 30,
        "4": 90,
        "5": 365,
        "6": None
    }

    if choice in validity_map:
        return validity_map[choice]
    elif choice == "7":
        days = input("请输入自定义天数: ").strip()
        try:
            return int(days)
        except ValueError:
            print("[✗] 无效的天数")
            return None
    else:
        print("[✗] 无效选项")
        return None

def main():
    print("=" * 80)
    print("用户密钥生成器 v2.0 - 支持时效性验证")
    print("=" * 80)

    # 选择主密钥文件
    master_key_file = input("\n请输入主密钥文件路径 (如: program_master.key): ").strip()

    try:
        generator = KeyGeneratorV2(master_key_file)
    except FileNotFoundError as e:
        print(f"[✗] 错误: {e}")
        return

    while True:
        print("\n" + "-" * 80)
        print("请选择操作:")
        print("1. 生成单个用户密钥")
        print("2. 批量生成密钥")
        print("3. 查看已生成的密钥")
        print("4. 导出密钥到文件")
        print("5. 延长密钥有效期")
        print("6. 退出")
        print("-" * 80)

        choice = input("\n请输入选项 (1-6): ").strip()

        if choice == "1":
            print("\n--- 生成单个用户密钥 ---")
            user_id = input("用户ID (必填): ").strip()
            if not user_id:
                print("[✗] 用户ID不能为空")
                continue

            user_name = input("用户姓名 (可选): ").strip()
            notes = input("备注信息 (可选): ").strip()

            validity_days = get_validity_preset()
            if validity_days is False:
                continue

            key = generator.generate_key(user_id, user_name, notes, validity_days)

            print("\n" + "=" * 80)
            print("[✓] 密钥生成成功!")
            print("=" * 80)
            print(f"用户ID: {user_id}")
            if user_name:
                print(f"用户名: {user_name}")
            print(f"\n激活密钥: {key}")

            if validity_days:
                expiry = datetime.now() + timedelta(days=validity_days)
                print(f"有效期: {validity_days} 天")
                print(f"过期时间: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print(f"有效期: 永久有效")

            print("\n请将此密钥提供给用户")
            print("=" * 80)

        elif choice == "2":
            print("\n--- 批量生成密钥 ---")
            print("请输入用户信息，每行一个，格式: 用户ID,用户名,有效天数,备注")
            print("有效天数: 数字表示天数，0或留空表示永久")
            print("输入空行结束输入")
            print("示例: USER001,张三,30,月卡用户")
            print("示例: USER002,李四,0,永久用户")

            user_list = []
            while True:
                line = input().strip()
                if not line:
                    break

                parts = line.split(',')
                validity_str = parts[2].strip() if len(parts) > 2 else ""

                try:
                    validity_days = int(validity_str) if validity_str and validity_str != "0" else None
                except ValueError:
                    validity_days = None

                user_info = {
                    "user_id": parts[0].strip(),
                    "user_name": parts[1].strip() if len(parts) > 1 else "",
                    "validity_days": validity_days,
                    "notes": parts[3].strip() if len(parts) > 3 else ""
                }
                user_list.append(user_info)

            if user_list:
                results = generator.batch_generate(user_list)
                print(f"\n[✓] 成功生成 {len(results)} 个密钥")

        elif choice == "3":
            generator.list_keys()

        elif choice == "4":
            output_file = input("\n输出文件名 (默认: keys_export_v2.txt): ").strip()
            if not output_file:
                output_file = "keys_export_v2.txt"
            generator.export_keys(output_file)

        elif choice == "5":
            print("\n--- 延长密钥有效期 ---")
            user_id = input("用户ID: ").strip()
            if not user_id:
                print("[✗] 用户ID不能为空")
                continue

            days_str = input("延长天数: ").strip()
            try:
                additional_days = int(days_str)
                generator.extend_validity(user_id, additional_days)
            except ValueError:
                print("[✗] 无效的天数")

        elif choice == "6":
            print("\n再见!")
            break

        else:
            print("[✗] 无效选项，请重新选择")

if __name__ == "__main__":
    main()
