#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXE启动器 - 验证密钥并解密运行
用途: 验证用户密钥，解密并运行EXE程序
编译命令: pyinstaller --onefile --noconsole --icon=icon.ico launcher.py
"""

import os
import sys
import hashlib
import subprocess
import tempfile
import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ===== 配置区域 =====
ENCRYPTED_FILE = "program_encrypted.dat"  # 加密的EXE文件名
MASTER_KEY_HASH = ""  # 主密钥的SHA256哈希值(在打包前填入)
# ===== 配置区域结束 =====

class LauncherGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("程序启动器")
        self.window.geometry("500x300")
        self.window.resizable(False, False)

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
            text="程序启动验证",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=20)

        # 说明文字
        info_label = tk.Label(
            self.window,
            text="请输入您的64位激活密钥",
            font=("Arial", 10)
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
            int(user_key, 16)
        except ValueError:
            messagebox.showerror("错误", "密钥格式错误\n密钥应为64位十六进制字符")
            return

        # 禁用按钮
        self.launch_button.config(state="disabled")
        self.status_label.config(text="正在验证密钥...", fg="blue")
        self.window.update()

        try:
            # 验证并解密
            exe_data = self.decrypt_exe(user_key)

            if exe_data is None:
                self.status_label.config(text="验证失败", fg="red")
                self.launch_button.config(state="normal")
                messagebox.showerror("验证失败", "密钥无效或已过期\n请检查密钥是否正确")
                return

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
            # 从用户密钥派生AES密钥
            aes_key = hashlib.sha256(user_key.encode()).digest()

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
    app = LauncherGUI()
    app.run()

if __name__ == "__main__":
    main()
