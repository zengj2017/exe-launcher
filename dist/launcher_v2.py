#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用文件启动器 V4 (时效版) - 验证密钥后下载并运行
支持所有文件类型: EXE, DLL, ZIP, 图片, 文档等
流程: 验证密钥 → 检查时效 → 下载加密文件 → 解密运行
编译命令: pyinstaller --onefile --windowed --name=launcher_v2 launcher_v2.py
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import tempfile
import threading
import urllib.request
import urllib.error
import struct
import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ===== 配置文件路径 =====
CONFIG_FILE = "config.json"
ACTIVATION_FILE = "activation.dat"
# ===== 配置文件路径结束 =====

def load_config():
    """从配置文件加载配置"""
    config = {
        "download_url": "https://your-cloud-storage.com/program_encrypted.dat",
        "encrypted_file": "program_encrypted.dat",
        "valid_keys": [],
        "enable_online_validation": False,
        "online_validation_url": ""
    }

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"加载配置文件失败: {e}")

    return config

# 加载配置
CONFIG = load_config()
DOWNLOAD_URL = CONFIG.get("download_url", "")
ENCRYPTED_FILE = CONFIG.get("encrypted_file", "program_encrypted.dat")
VALID_KEYS = CONFIG.get("valid_keys", [])
ENABLE_ONLINE_VALIDATION = CONFIG.get("enable_online_validation", False)
ONLINE_VALIDATION_URL = CONFIG.get("online_validation_url", "")


class ActivationManager:
    """激活记录管理器"""

    def __init__(self, activation_file=ACTIVATION_FILE):
        self.activation_file = activation_file
        self.data = self.load_activation_data()

    def load_activation_data(self):
        """加载激活记录"""
        if os.path.exists(self.activation_file):
            try:
                with open(self.activation_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_activation_data(self):
        """保存激活记录"""
        try:
            with open(self.activation_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"保存激活记录失败: {e}")

    def get_activation_info(self, key_hash):
        """获取密钥的激活信息"""
        return self.data.get(key_hash)

    def save_activation_info(self, key_hash, activation_time, validity_days):
        """保存激活信息"""
        if validity_days == 0:
            expiry_timestamp = 0  # 永久有效
        else:
            expiry_timestamp = activation_time + (validity_days * 86400)

        self.data[key_hash] = {
            "first_activation": activation_time,
            "validity_days": validity_days,
            "expiry_timestamp": expiry_timestamp
        }
        self.save_activation_data()

    def check_validity(self, key_hash, validity_days):
        """
        检查密钥有效性
        :return: (是否有效, 状态信息, 剩余天数)
        """
        activation_info = self.get_activation_info(key_hash)
        current_time = int(time.time())

        # 永久有效
        if validity_days == 0:
            if not activation_info:
                self.save_activation_info(key_hash, current_time, 0)
            return True, "密钥永久有效", None

        # 首次激活
        if not activation_info:
            self.save_activation_info(key_hash, current_time, validity_days)
            return True, f"首次激活成功，有效期 {validity_days} 天", validity_days

        # 检查是否过期
        expiry_timestamp = activation_info.get("expiry_timestamp", 0)

        if current_time > expiry_timestamp:
            return False, "密钥已过期", 0

        remaining_seconds = expiry_timestamp - current_time
        remaining_days = remaining_seconds // 86400

        return True, f"密钥有效，剩余 {remaining_days} 天", remaining_days


class LauncherGUIV2:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("程序启动器 (时效版)")
        self.window.geometry("550x420")
        self.window.resizable(False, False)

        # 下载状态
        self.download_cancelled = False
        self.download_thread = None

        # 激活管理器
        self.activation_manager = ActivationManager()

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
        title_label.pack(pady=15)

        # 说明文字
        info_label = tk.Label(
            self.window,
            text="请输入您的64位激活密钥",
            font=("Arial", 10)
        )
        info_label.pack(pady=8)

        # 密钥输入框
        self.key_entry = tk.Entry(
            self.window,
            font=("Courier", 11),
            width=55,
            justify="center"
        )
        self.key_entry.pack(pady=8)
        self.key_entry.focus()

        # 绑定回车键
        self.key_entry.bind("<Return>", lambda e: self.verify_and_download())

        # 时效信息框架
        validity_frame = tk.Frame(self.window, relief=tk.GROOVE, bd=1)
        validity_frame.pack(pady=10, padx=40, fill=tk.X)

        self.validity_label = tk.Label(
            validity_frame,
            text="等待验证...",
            font=("Arial", 10),
            fg="gray",
            pady=8
        )
        self.validity_label.pack()

        # 进度条框架
        progress_frame = tk.Frame(self.window)
        progress_frame.pack(pady=10, fill=tk.X, padx=40)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(fill=tk.X)

        # 进度文字
        self.progress_label = tk.Label(
            progress_frame,
            text="",
            font=("Arial", 9),
            fg="gray"
        )
        self.progress_label.pack(pady=5)

        # 按钮框架
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=15)

        # 启动按钮
        self.launch_button = tk.Button(
            button_frame,
            text="验证并下载",
            font=("Arial", 11),
            width=15,
            height=2,
            bg="#4CAF50",
            fg="white",
            command=self.verify_and_download
        )
        self.launch_button.pack(side=tk.LEFT, padx=10)

        # 退出按钮
        self.exit_button = tk.Button(
            button_frame,
            text="退出",
            font=("Arial", 11),
            width=15,
            height=2,
            bg="#f44336",
            fg="white",
            command=self.on_exit
        )
        self.exit_button.pack(side=tk.LEFT, padx=10)

        # 状态栏
        self.status_label = tk.Label(
            self.window,
            text="",
            font=("Arial", 9),
            fg="gray"
        )
        self.status_label.pack(side=tk.BOTTOM, pady=10)

    def on_exit(self):
        """退出处理"""
        self.download_cancelled = True
        self.window.quit()

    def verify_key(self, user_key):
        """
        验证密钥
        :param user_key: 用户输入的密钥
        :return: (是否有效, 错误信息, 有效天数)
        """
        # 验证格式：64位十六进制
        if len(user_key) != 64:
            return False, "密钥长度错误，应为64位", None

        try:
            int(user_key, 16)
        except ValueError:
            return False, "密钥格式错误，应为十六进制字符", None

        validity_days = 30  # 默认30天

        # 如果配置了有效密钥列表，进行验证
        if VALID_KEYS:
            key_found = False
            for key_info in VALID_KEYS:
                if isinstance(key_info, dict):
                    if key_info.get("key") == user_key:
                        key_found = True
                        validity_days = key_info.get("validity_days", 30)
                        break
                elif key_info == user_key:
                    key_found = True
                    break
            if not key_found:
                return False, "密钥无效", None
        else:
            # 如果没有配置密钥列表，从密钥末4位提取有效期信息
            validity_fingerprint = user_key[-4:]
            validity_days = self.parse_validity_fingerprint(validity_fingerprint)

        # 如果启用在线验证
        if ENABLE_ONLINE_VALIDATION and ONLINE_VALIDATION_URL:
            try:
                req = urllib.request.Request(
                    f"{ONLINE_VALIDATION_URL}?key={user_key}",
                    headers={'User-Agent': 'Launcher/2.0'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = response.read().decode()
                    if result.strip().lower() != "valid":
                        return False, "密钥验证失败", None
            except Exception as e:
                return False, f"在线验证失败: {str(e)}", None

        return True, "", validity_days

    def parse_validity_fingerprint(self, fingerprint):
        """
        从密钥末4位解析有效期
        :param fingerprint: 4位有效期指纹
        :return: 有效天数 (0=永久)
        """
        # 预定义的有效期指纹映射
        validity_map = {
            "0000": 0,    # 永久
            hashlib.md5(b"1").hexdigest()[:4]: 1,     # 1天
            hashlib.md5(b"7").hexdigest()[:4]: 7,     # 7天
            hashlib.md5(b"30").hexdigest()[:4]: 30,   # 30天
            hashlib.md5(b"90").hexdigest()[:4]: 90,   # 90天
            hashlib.md5(b"365").hexdigest()[:4]: 365, # 365天
        }
        return validity_map.get(fingerprint, 30)  # 默认30天

    def verify_and_download(self):
        """验证密钥并开始下载"""
        user_key = self.key_entry.get().strip()

        # 验证密钥
        if not user_key:
            messagebox.showerror("错误", "请输入激活密钥")
            return

        self.status_label.config(text="正在验证密钥...", fg="blue")
        self.validity_label.config(text="验证中...", fg="blue")
        self.window.update()

        is_valid, error_msg, validity_days = self.verify_key(user_key)

        if not is_valid:
            self.status_label.config(text="验证失败", fg="red")
            self.validity_label.config(text="密钥无效", fg="red")
            messagebox.showerror("验证失败", f"密钥无效\n{error_msg}")
            return

        # 检查时效性
        key_hash = hashlib.sha256(user_key.encode()).hexdigest()
        is_active, validity_msg, remaining_days = self.activation_manager.check_validity(
            key_hash, validity_days if validity_days is not None else 30
        )

        if not is_active:
            self.status_label.config(text="密钥已过期", fg="red")
            self.validity_label.config(text="❌ 密钥已过期，请续期", fg="red")
            messagebox.showerror("已过期", "您的密钥已过期\n请联系管理员续期")
            return

        # 更新有效期显示
        if remaining_days is not None:
            if remaining_days <= 7:
                self.validity_label.config(text=f"⚠️ {validity_msg}", fg="orange")
            else:
                self.validity_label.config(text=f"✓ {validity_msg}", fg="green")
        else:
            self.validity_label.config(text="✓ 永久有效", fg="green")

        # 验证通过，禁用按钮
        self.launch_button.config(state="disabled")
        self.key_entry.config(state="disabled")
        self.status_label.config(text="密钥验证通过，准备下载...", fg="green")
        self.window.update()

        # 如果剩余天数少于7天，给出提醒
        if remaining_days is not None and remaining_days <= 7:
            messagebox.showwarning(
                "有效期提醒",
                f"您的密钥还剩 {remaining_days} 天有效期\n请及时续期！"
            )

        # 保存当前密钥用于解密
        self.current_key = user_key

        # 检查是否已有本地文件
        if os.path.exists(ENCRYPTED_FILE):
            self.status_label.config(text="发现本地文件，正在解密...", fg="blue")
            self.window.update()
            self.decrypt_and_run(user_key)
        else:
            # 开始下载
            self.start_download(user_key)

    def start_download(self, user_key):
        """开始下载文件"""
        self.download_cancelled = False
        self.download_thread = threading.Thread(
            target=self.download_file,
            args=(user_key,),
            daemon=True
        )
        self.download_thread.start()

    def download_file(self, user_key):
        """下载加密文件（在后台线程中执行）"""
        try:
            self.update_status("正在连接服务器...", "blue")

            # 创建请求
            req = urllib.request.Request(
                DOWNLOAD_URL,
                headers={'User-Agent': 'Launcher/2.0'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                # 获取文件大小
                total_size = response.headers.get('Content-Length')
                total_size = int(total_size) if total_size else 0

                downloaded = 0
                block_size = 8192

                # 写入临时文件
                temp_file = ENCRYPTED_FILE + ".tmp"

                with open(temp_file, 'wb') as f:
                    while True:
                        if self.download_cancelled:
                            self.update_status("下载已取消", "red")
                            return

                        buffer = response.read(block_size)
                        if not buffer:
                            break

                        f.write(buffer)
                        downloaded += len(buffer)

                        # 更新进度
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            self.update_progress(progress, f"下载中: {downloaded}/{total_size} 字节")
                        else:
                            self.update_progress(0, f"下载中: {downloaded} 字节")

                # 下载完成，重命名文件
                if os.path.exists(ENCRYPTED_FILE):
                    os.remove(ENCRYPTED_FILE)
                os.rename(temp_file, ENCRYPTED_FILE)

                self.update_progress(100, "下载完成")
                self.update_status("下载完成，正在解密...", "green")

                # 解密并运行
                self.window.after(500, lambda: self.decrypt_and_run(user_key))

        except urllib.error.URLError as e:
            self.update_status(f"下载失败: 网络错误", "red")
            self.window.after(0, lambda: messagebox.showerror("下载失败", f"网络错误:\n{str(e)}"))
            self.enable_buttons()
        except Exception as e:
            self.update_status(f"下载失败: {str(e)}", "red")
            self.window.after(0, lambda: messagebox.showerror("下载失败", str(e)))
            self.enable_buttons()

    def update_progress(self, value, text):
        """更新进度条（线程安全）"""
        self.window.after(0, lambda: self.progress_var.set(value))
        self.window.after(0, lambda: self.progress_label.config(text=text))

    def update_status(self, text, color):
        """更新状态文字（线程安全）"""
        self.window.after(0, lambda: self.status_label.config(text=text, fg=color))

    def enable_buttons(self):
        """重新启用按钮"""
        self.window.after(0, lambda: self.launch_button.config(state="normal"))
        self.window.after(0, lambda: self.key_entry.config(state="normal"))

    def decrypt_and_run(self, user_key):
        """解密并运行程序"""
        try:
            result = self.decrypt_file(user_key)

            if result is None:
                self.status_label.config(text="解密失败", fg="red")
                messagebox.showerror("解密失败", "密钥无法解密此文件\n文件可能已损坏或密钥不匹配")
                self.enable_buttons()
                return

            file_data, original_filename = result

            # 创建临时文件并运行
            self.status_label.config(text="正在启动程序...", fg="green")
            self.window.update()

            temp_file = self.create_temp_file(file_data, original_filename)
            self.run_file(temp_file)

            # 成功启动后关闭启动器
            self.window.destroy()

        except Exception as e:
            self.status_label.config(text="启动失败", fg="red")
            messagebox.showerror("错误", f"程序启动失败:\n{str(e)}")
            self.enable_buttons()

    def decrypt_file(self, user_key):
        """
        解密文件（支持任意文件类型）
        :param user_key: 用户输入的64位密钥
        :return: (解密后的数据, 原始文件名) 或 None
        """
        if not os.path.exists(ENCRYPTED_FILE):
            messagebox.showerror("错误", f"未找到加密文件: {ENCRYPTED_FILE}")
            return None

        try:
            # 从用户密钥派生AES密钥
            aes_key = hashlib.sha256(user_key.encode()).digest()

            with open(ENCRYPTED_FILE, 'rb') as f:
                file_content = f.read()

            # 尝试新格式: [文件名长度2字节][文件名][IV 16字节][加密数据]
            try:
                filename_len = struct.unpack('<H', file_content[:2])[0]
                if 0 < filename_len < 256:
                    original_filename = file_content[2:2+filename_len].decode('utf-8')
                    iv = file_content[2+filename_len:2+filename_len+16]
                    encrypted_data = file_content[2+filename_len+16:]

                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                    return decrypted_data, original_filename
            except:
                pass

            # 兼容旧格式: [IV 16字节][加密数据]
            iv = file_content[:16]
            encrypted_data = file_content[16:]

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            if decrypted_data.startswith(b'MZ'):
                return decrypted_data, "program.exe"
            else:
                return decrypted_data, "program.dat"

        except Exception as e:
            print(f"解密失败: {e}")
            return None

    def create_temp_file(self, file_data, filename):
        """
        创建临时文件
        :param file_data: 文件数据
        :param filename: 原始文件名
        :return: 临时文件路径
        """
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, filename)

        with open(temp_path, 'wb') as f:
            f.write(file_data)

        return temp_path

    def run_file(self, file_path):
        """
        运行文件（根据类型选择打开方式）
        :param file_path: 文件路径
        """
        ext = os.path.splitext(file_path)[1].lower()

        if ext in ['.exe', '.bat', '.cmd']:
            subprocess.Popen([file_path], cwd=os.path.dirname(file_path))
        else:
            if sys.platform == 'win32':
                os.startfile(file_path)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', file_path])
            else:
                subprocess.Popen(['xdg-open', file_path])

    def run(self):
        """运行GUI"""
        self.window.mainloop()


def main():
    """主函数"""
    app = LauncherGUIV2()
    app.run()


if __name__ == "__main__":
    main()
