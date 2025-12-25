#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXE启动器 v2.0 - 支持时效性验证
用途: 验证用户密钥（含时效性），解密并运行EXE程序
编译命令: pyinstaller --onefile --windowed --icon=icon.ico launcher_v2.py
"""

import os
import sys
import hashlib
import subprocess
import tempfile
import time
import json
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ===== 配置区域 =====
ENCRYPTED_FILE = "program_encrypted.dat"  # 加密的EXE文件名
ACTIVATION_FILE = "activation.dat"  # 激活记录文件（存储首次激活时间）
# ===== 配置区域结束 =====

class ActivationManager:
    """激活管理器 - 管理首次激活时间"""

    def __init__(self):
        self.activation_file = ACTIVATION_FILE

    def get_activation_info(self, key_hash):
        """
        获取密钥的激活信息
        :param key_hash: 密钥哈希值（用于标识）
        :return: 激活信息字典或None
        """
        if not os.path.exists(self.activation_file):
            return None

        try:
            with open(self.activation_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get(key_hash)
        except:
            return None

    def save_activation_info(self, key_hash, activation_time, validity_days):
        """
        保存激活信息
        :param key_hash: 密钥哈希值
        :param activation_time: 激活时间戳
        :param validity_days: 有效天数
        """
        data = {}
        if os.path.exists(self.activation_file):
            try:
                with open(self.activation_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except:
                pass

        data[key_hash] = {
            "first_activation": activation_time,
            "validity_days": validity_days,
            "expiry_timestamp": activation_time + (validity_days * 86400) if validity_days else None
        }

        with open(self.activation_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

class LauncherGUIV2:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("程序启动器 v2.0")
        self.window.geometry("550x350")
        self.window.resizable(False, False)

        self.activation_mgr = ActivationManager()

        # 居中显示
        self.center_window()

        self.setup_ui()

    def center_window(self):
        """窗口居中"""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')

    def setup_ui(self):
        """设置界面"""
        # 标题
        title_label = tk.Label(
            self.window,
            text="程序启动验证 v2.0",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=20)

        # 说明文字
        info_label = tk.Label(
            self.window,
            text="请输入您的64位激活密钥\n支持时效性验证",
            font=("Arial", 10),
            fg="gray"
        )
        info_label.pack(pady=10)

        # 密钥输入框
        self.key_entry = tk.Entry(
            self.window,
            font=("Courier", 11),
            width=50,
            justify="center"
        )
        self.key_entry.pack(pady=10)
        self.key_entry.focus()

        # 绑定回车键
        self.key_entry.bind("<Return>", lambda e: self.verify_and_launch())

        # 有效期信息显示
        self.validity_label = tk.Label(
            self.window,
            text="",
            font=("Arial", 9),
            fg="blue"
        )
        self.validity_label.pack(pady=5)

        # 按钮框架
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=20)

        # 启动按钮
        self.launch_button = tk.Button(
            button_frame,
            text="验证并启动",
            font=("Arial", 11),
            width=15,
            height=2,
            bg="#4CAF50",
            fg="white",
            command=self.verify_and_launch
        )
        self.launch_button.pack(side=tk.LEFT, padx=10)

        # 退出按钮
        exit_button = tk.Button(
            button_frame,
            text="退出",
            font=("Arial", 11),
            width=15,
            height=2,
            bg="#f44336",
            fg="white",
            command=self.window.quit
        )
        exit_button.pack(side=tk.LEFT, padx=10)

        # 状态栏
        self.status_label = tk.Label(
            self.window,
            text="",
            font=("Arial", 9),
            fg="gray"
        )
        self.status_label.pack(side=tk.BOTTOM, pady=10)

    def parse_key_validity(self, user_key):
        """
        从密钥中解析有效期信息
        :param user_key: 64位密钥
        :return: 有效天数 (None表示永久)
        """
        # 密钥格式: 60位哈希 + 4位校验码
        # 校验码 "0000" 表示永久有效
        if len(user_key) != 64:
            return None

        validity_fingerprint = user_key[-4:]

        if validity_fingerprint == "0000":
            return None  # 永久有效

        # 尝试从常见有效期反推
        # 这里简化处理，实际应用中可以在密钥中编码更多信息
        validity_presets = {
            hashlib.md5(b"1").hexdigest()[:4]: 1,
            hashlib.md5(b"7").hexdigest()[:4]: 7,
            hashlib.md5(b"30").hexdigest()[:4]: 30,
            hashlib.md5(b"90").hexdigest()[:4]: 90,
            hashlib.md5(b"365").hexdigest()[:4]: 365,
        }

        return validity_presets.get(validity_fingerprint, 30)  # 默认30天

    def check_validity(self, user_key):
        """
        检查密钥有效期
        :param user_key: 用户密钥
        :return: (is_valid, message, remaining_days)
        """
        # 解析密钥中的有效期信息
        validity_days = self.parse_key_validity(user_key)

        if validity_days is None:
            return True, "永久有效", None

        # 生成密钥哈希用于标识
        key_hash = hashlib.sha256(user_key.encode()).hexdigest()[:16]

        # 获取激活信息
        activation_info = self.activation_mgr.get_activation_info(key_hash)

        current_time = int(time.time())

        if activation_info is None:
            # 首次激活
            self.activation_mgr.save_activation_info(key_hash, current_time, validity_days)
            return True, f"首次激活成功！有效期 {validity_days} 天", validity_days
        else:
            # 已激活，检查是否过期
            expiry_timestamp = activation_info.get('expiry_timestamp')

            if expiry_timestamp and current_time > expiry_timestamp:
                # 已过期
                expiry_date = datetime.fromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                return False, f"密钥已过期 (过期时间: {expiry_date})", 0
            else:
                # 仍有效
                remaining_days = (expiry_timestamp - current_time) // 86400
                return True, f"密钥有效，还剩 {remaining_days} 天", remaining_days

    def verify_and_launch(self):
        """验证密钥并启动程序"""
        user_key = self.key_entry.get().strip()

        # 验证密钥格式
        if not user_key:
            messagebox.showerror("错误", "请输入激活密钥")
            return

        if len(user_key) != 64:
            messagebox.showerror("错误", "密钥格式错误\n密钥应为64位十六进制字符")
            return

        try:
            int(user_key[:60], 16)  # 验证前60位是否为有效的十六进制
        except ValueError:
            messagebox.showerror("错误", "密钥格式错误\n密钥应为64位十六进制字符")
            return

        # 禁用按钮
        self.launch_button.config(state="disabled")
        self.status_label.config(text="正在验证密钥...", fg="blue")
        self.window.update()

        try:
            # 检查有效期
            is_valid, validity_msg, remaining_days = self.check_validity(user_key)

            if not is_valid:
                self.status_label.config(text="密钥已过期", fg="red")
                self.launch_button.config(state="normal")
                messagebox.showerror("密钥已过期", validity_msg)
                return

            # 显示有效期信息
            self.validity_label.config(text=validity_msg, fg="green")
            self.window.update()

            # 验证并解密
            exe_data = self.decrypt_exe(user_key)

            if exe_data is None:
                self.status_label.config(text="验证失败", fg="red")
                self.launch_button.config(state="normal")
                messagebox.showerror("验证失败", "密钥无效\n请检查密钥是否正确")
                return

            # 如果剩余天数少于7天，给出提醒
            if remaining_days is not None and remaining_days <= 7:
                messagebox.showwarning(
                    "有效期提醒",
                    f"您的密钥还剩 {remaining_days} 天有效期\n请及时续期！"
                )

            # 创建临时文件并运行
            self.status_label.config(text="正在启动程序...", fg="green")
            self.window.update()

            temp_exe = self.create_temp_exe(exe_data)
            self.run_exe(temp_exe)

            # 成功启动后关闭启动器
            self.window.destroy()

        except Exception as e:
            self.status_label.config(text="启动失败", fg="red")
            self.launch_button.config(state="normal")
            messagebox.showerror("错误", f"程序启动失败:\n{str(e)}")

    def decrypt_exe(self, user_key):
        """
        解密EXE文件
        :param user_key: 用户输入的64位密钥
        :return: 解密后的EXE数据，失败返回None
        """
        if not os.path.exists(ENCRYPTED_FILE):
            messagebox.showerror("错误", f"未找到加密文件: {ENCRYPTED_FILE}")
            return None

        try:
            # 从用户密钥派生AES密钥（使用前60位）
            key_hash_part = user_key[:60]
            aes_key = hashlib.sha256(key_hash_part.encode()).digest()

            # 读取加密文件
            with open(ENCRYPTED_FILE, 'rb') as f:
                iv = f.read(16)  # 读取IV
                encrypted_data = f.read()  # 读取加密数据

            # 解密
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            # 验证是否为有效的EXE文件(检查PE头)
            if not decrypted_data.startswith(b'MZ'):
                return None

            return decrypted_data

        except Exception as e:
            print(f"解密失败: {e}")
            return None

    def create_temp_exe(self, exe_data):
        """
        创建临时EXE文件
        :param exe_data: EXE文件数据
        :return: 临时文件路径
        """
        # 创建临时文件
        temp_dir = tempfile.gettempdir()
        temp_exe_path = os.path.join(temp_dir, "program_temp.exe")

        # 写入数据
        with open(temp_exe_path, 'wb') as f:
            f.write(exe_data)

        return temp_exe_path

    def run_exe(self, exe_path):
        """
        运行EXE程序
        :param exe_path: EXE文件路径
        """
        # 使用subprocess启动程序
        subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path))

    def run(self):
        """运行GUI"""
        self.window.mainloop()

def main():
    """主函数"""
    # 检查加密文件是否存在
    if not os.path.exists(ENCRYPTED_FILE):
        messagebox.showerror(
            "错误",
            f"未找到程序文件: {ENCRYPTED_FILE}\n\n请先运行下载脚本下载程序"
        )
        sys.exit(1)

    # 启动GUI
    app = LauncherGUIV2()
    app.run()

if __name__ == "__main__":
    main()
