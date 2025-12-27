#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用文件启动器 V5 - 云端密钥验证 + 双重时间验证
支持: 云端密钥管理、有效期检查、防时间篡改
流程: 验证密钥(云端) → 检查有效期 → 下载加密文件 → 解密保存
编译命令: pyinstaller --onefile --windowed --name=launcher launcher.py
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
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ===== 配置 =====
CONFIG_FILE = "config.json"
ACTIVATION_FILE = "activation.dat"
DEFAULT_KEYS_URL = ""
DEFAULT_DOWNLOAD_URL = ""
EXPIRE_WARNING_DAYS = 7
OFFLINE_GRACE_DAYS = 3
# ===== 配置结束 =====


def load_config():
    """加载本地配置"""
    config = {
        "keys_url": DEFAULT_KEYS_URL,
        "download_url": DEFAULT_DOWNLOAD_URL,
        "encrypted_file": "program_encrypted.dat",
        "time_api": "http://worldtimeapi.org/api/ip",
        "contact": "",
        "offline_grace_days": OFFLINE_GRACE_DAYS,
        "expire_warning_days": EXPIRE_WARNING_DAYS
    }

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"加载配置失败: {e}")

    return config


CONFIG = load_config()
KEYS_URL = CONFIG.get("keys_url", "")
DOWNLOAD_URL = CONFIG.get("download_url", "")
ENCRYPTED_FILE = CONFIG.get("encrypted_file", "program_encrypted.dat")
TIME_API = CONFIG.get("time_api", "http://worldtimeapi.org/api/ip")
CONTACT = CONFIG.get("contact", "")


class ActivationManager:
    """激活状态管理（防时间篡改）"""

    def __init__(self):
        self.data_file = ACTIVATION_FILE
        self.data = self._load()

    def _load(self):
        """加载激活数据"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save(self):
        """保存激活数据"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f)
        except:
            pass

    def get_last_check_time(self):
        """获取上次检查时间"""
        return self.data.get("last_check_time", 0)

    def set_last_check_time(self, timestamp):
        """设置检查时间"""
        self.data["last_check_time"] = timestamp
        self._save()

    def is_time_tampered(self, current_time):
        """检测时间是否被篡改（当前时间比上次早）"""
        last_time = self.get_last_check_time()
        if last_time > 0 and current_time < last_time - 3600:
            return True
        return False


class TimeVerifier:
    """双重时间验证"""

    def __init__(self, activation_manager):
        self.activation = activation_manager

    def get_online_time(self):
        """获取在线时间"""
        try:
            req = urllib.request.Request(
                TIME_API,
                headers={'User-Agent': 'Launcher/1.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return data.get('unixtime', None)
        except:
            return None

    def get_verified_time(self):
        """
        获取可信时间（双重验证）
        返回: (时间戳, 是否可信)
        """
        # 优先使用在线时间
        online_time = self.get_online_time()
        if online_time:
            self.activation.set_last_check_time(online_time)
            return online_time, True

        # 备用：本地时间 + 防篡改检测
        local_time = time.time()

        if self.activation.is_time_tampered(local_time):
            return None, False

        # 检查离线时间是否超过宽限期
        last_check = self.activation.get_last_check_time()
        offline_days = CONFIG.get("offline_grace_days", OFFLINE_GRACE_DAYS)

        if last_check > 0:
            days_offline = (local_time - last_check) / 86400
            if days_offline > offline_days:
                return None, False

        self.activation.set_last_check_time(local_time)
        return local_time, True


class KeyValidator:
    """云端密钥验证"""

    def __init__(self):
        self.keys_data = None
        self.key_info = None
        self.last_error = ""

    def fetch_keys(self):
        """从云端或本地获取密钥列表"""
        # 优先尝试本地 keys.json
        local_keys_file = "keys.json"
        if os.path.exists(local_keys_file):
            try:
                with open(local_keys_file, 'r', encoding='utf-8') as f:
                    self.keys_data = json.load(f)
                    return self.keys_data
            except Exception as e:
                self.last_error = f"本地密钥文件读取失败: {str(e)}"

        # 如果没有本地文件，从云端获取
        if not KEYS_URL:
            self.last_error = "未配置密钥服务器地址"
            return None

        try:
            req = urllib.request.Request(
                KEYS_URL,
                headers={'User-Agent': 'Launcher/1.0'}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                self.keys_data = json.loads(response.read().decode())
                return self.keys_data
        except urllib.error.URLError as e:
            self.last_error = f"网络错误: {e.reason}"
            return None
        except Exception as e:
            self.last_error = f"获取失败: {str(e)}"
            return None

    def validate_key(self, user_key):
        """
        验证密钥
        返回: (是否有效, 错误信息, 密钥信息)
        """
        # 格式验证
        if len(user_key) != 64:
            return False, "密钥长度错误，应为64位", None

        try:
            int(user_key, 16)
        except ValueError:
            return False, "密钥格式错误", None

        # 如果没有配置云端URL，只做格式验证
        if not KEYS_URL:
            return True, "", {"key": user_key}

        # 获取云端密钥列表
        if not self.keys_data:
            self.fetch_keys()

        if not self.keys_data:
            error_detail = self.last_error if self.last_error else "未知错误"
            return False, f"无法连接验证服务器\n{error_detail}\n\n请检查网络连接", None

        # 查找密钥
        keys = self.keys_data.get("keys", [])
        for key_info in keys:
            if key_info.get("key") == user_key:
                # 检查是否启用
                if not key_info.get("enabled", True):
                    return False, "此密钥已被禁用", None

                self.key_info = key_info
                return True, "", key_info

        return False, "密钥无效", None

    def check_expiry(self, key_info, current_time):
        """
        检查有效期
        返回: (状态, 剩余天数, 消息)
        状态: "valid" | "warning" | "expired"
        """
        expires = key_info.get("expires", "")
        if not expires:
            return "valid", -1, ""

        try:
            expire_date = datetime.strptime(expires, "%Y-%m-%d")
            expire_timestamp = expire_date.timestamp() + 86400  # 到期日结束

            remaining_seconds = expire_timestamp - current_time
            remaining_days = remaining_seconds / 86400

            if remaining_days < 0:
                return "expired", 0, f"密钥已于 {expires} 过期"

            warning_days = CONFIG.get("expire_warning_days", EXPIRE_WARNING_DAYS)
            if remaining_days <= warning_days:
                return "warning", int(remaining_days), f"密钥将于 {int(remaining_days)} 天后过期"

            return "valid", int(remaining_days), ""

        except:
            return "valid", -1, ""


class LauncherGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("程序启动器")
        self.window.geometry("550x380")
        self.window.resizable(False, False)

        # 组件初始化
        self.activation = ActivationManager()
        self.time_verifier = TimeVerifier(self.activation)
        self.key_validator = KeyValidator()

        # 状态
        self.download_cancelled = False
        self.verified_key = None

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

        # 说明
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
            width=55,
            justify="center"
        )
        self.key_entry.pack(pady=10)
        self.key_entry.focus()
        self.key_entry.bind("<Return>", lambda e: self.start_verification())

        # 进度条
        progress_frame = tk.Frame(self.window)
        progress_frame.pack(pady=15, fill=tk.X, padx=40)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(fill=tk.X)

        self.progress_label = tk.Label(
            progress_frame,
            text="",
            font=("Arial", 9),
            fg="gray"
        )
        self.progress_label.pack(pady=5)

        # 按钮
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=20)

        self.launch_button = tk.Button(
            button_frame,
            text="验证并下载",
            font=("Arial", 11),
            width=15,
            height=2,
            bg="#4CAF50",
            fg="white",
            command=self.start_verification
        )
        self.launch_button.pack(side=tk.LEFT, padx=10)

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
        """退出"""
        self.download_cancelled = True
        self.window.quit()

    def start_verification(self):
        """开始验证流程"""
        user_key = self.key_entry.get().strip()

        if not user_key:
            messagebox.showerror("错误", "请输入激活密钥")
            return

        self.launch_button.config(state="disabled")
        self.key_entry.config(state="disabled")

        # 步骤1: 验证密钥
        self.status_label.config(text="正在验证密钥...", fg="blue")
        self.window.update()

        is_valid, error_msg, key_info = self.key_validator.validate_key(user_key)

        if not is_valid:
            self.status_label.config(text="验证失败", fg="red")
            messagebox.showerror("验证失败", error_msg)
            self.enable_buttons()
            return

        # 步骤2: 获取可信时间
        self.status_label.config(text="正在验证时间...", fg="blue")
        self.window.update()

        current_time, time_trusted = self.time_verifier.get_verified_time()

        if not time_trusted or current_time is None:
            self.status_label.config(text="时间验证失败", fg="red")
            messagebox.showerror("验证失败", "检测到系统时间异常\n请确保网络连接正常且未修改系统时间")
            self.enable_buttons()
            return

        # 步骤3: 检查有效期
        expiry_status, remaining_days, expiry_msg = self.key_validator.check_expiry(key_info, current_time)

        if expiry_status == "expired":
            self.status_label.config(text="密钥已过期", fg="red")
            contact_info = f"\n\n{CONTACT}" if CONTACT else ""
            messagebox.showerror("授权过期", f"{expiry_msg}{contact_info}")
            self.enable_buttons()
            return

        if expiry_status == "warning":
            messagebox.showwarning("即将过期", f"提醒：{expiry_msg}\n请及时续费")

        # 验证通过
        self.verified_key = user_key
        self.status_label.config(text="验证通过", fg="green")
        self.window.update()

        # 步骤4: 下载或解密
        if os.path.exists(ENCRYPTED_FILE):
            self.status_label.config(text="发现本地文件，正在解密...", fg="blue")
            self.window.update()
            self.decrypt_and_save(user_key)
        else:
            self.start_download(user_key)

    def enable_buttons(self):
        """重新启用按钮"""
        self.launch_button.config(state="normal")
        self.key_entry.config(state="normal")

    def start_download(self, user_key):
        """开始下载"""
        self.download_cancelled = False
        thread = threading.Thread(
            target=self.download_file,
            args=(user_key,),
            daemon=True
        )
        thread.start()

    def download_file(self, user_key):
        """下载文件"""
        try:
            self.update_status("正在连接服务器...", "blue")

            req = urllib.request.Request(
                DOWNLOAD_URL,
                headers={'User-Agent': 'Launcher/1.0'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                total_size = response.headers.get('Content-Length')
                total_size = int(total_size) if total_size else 0

                downloaded = 0
                block_size = 8192
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

                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            self.update_progress(progress, f"下载中: {downloaded}/{total_size} 字节")
                        else:
                            self.update_progress(0, f"下载中: {downloaded} 字节")

                if os.path.exists(ENCRYPTED_FILE):
                    os.remove(ENCRYPTED_FILE)
                os.rename(temp_file, ENCRYPTED_FILE)

                self.update_progress(100, "下载完成")
                self.update_status("下载完成，正在解密...", "green")

                self.window.after(500, lambda: self.decrypt_and_save(user_key))

        except Exception as e:
            self.update_status(f"下载失败", "red")
            self.window.after(0, lambda: messagebox.showerror("下载失败", str(e)))
            self.window.after(0, self.enable_buttons)

    def update_progress(self, value, text):
        """更新进度"""
        self.window.after(0, lambda: self.progress_var.set(value))
        self.window.after(0, lambda: self.progress_label.config(text=text))

    def update_status(self, text, color):
        """更新状态"""
        self.window.after(0, lambda: self.status_label.config(text=text, fg=color))

    def decrypt_and_save(self, user_key):
        """解密并保存文件"""
        try:
            result = self.decrypt_file(user_key)

            if result is None:
                self.status_label.config(text="解密失败", fg="red")
                messagebox.showerror("解密失败", "密钥无法解密此文件\n文件可能已损坏或密钥不匹配")
                self.enable_buttons()
                return

            file_data, original_filename = result

            self.status_label.config(text="正在保存文件...", fg="green")
            self.window.update()

            output_path = self.save_file(file_data, original_filename)

            ext = os.path.splitext(original_filename)[1].lower()

            if ext == '.zip':
                self.status_label.config(text="解密完成", fg="green")
                messagebox.showinfo("解密成功", f"文件已保存到:\n{output_path}\n\n请自行解压使用")
                self.window.destroy()
            elif ext in ['.exe', '.bat', '.cmd']:
                self.status_label.config(text="正在启动程序...", fg="green")
                self.window.update()
                self.run_file(output_path)
                self.window.destroy()
            else:
                self.status_label.config(text="正在打开文件...", fg="green")
                self.window.update()
                self.run_file(output_path)
                self.window.destroy()

        except Exception as e:
            self.status_label.config(text="处理失败", fg="red")
            messagebox.showerror("错误", f"文件处理失败:\n{str(e)}")
            self.enable_buttons()

    def decrypt_file(self, user_key):
        """解密文件"""
        if not os.path.exists(ENCRYPTED_FILE):
            messagebox.showerror("错误", f"未找到加密文件: {ENCRYPTED_FILE}")
            return None

        try:
            aes_key = hashlib.sha256(user_key.encode()).digest()

            with open(ENCRYPTED_FILE, 'rb') as f:
                file_content = f.read()

            # 新格式: [文件名长度2字节][文件名][IV 16字节][加密数据]
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

            # 旧格式
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

    def save_file(self, file_data, filename):
        """保存文件到当前目录"""
        if getattr(sys, 'frozen', False):
            current_dir = os.path.dirname(sys.executable)
        else:
            current_dir = os.path.dirname(os.path.abspath(__file__))

        output_path = os.path.join(current_dir, filename)

        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(output_path):
            output_path = os.path.join(current_dir, f"{base}_{counter}{ext}")
            counter += 1

        with open(output_path, 'wb') as f:
            f.write(file_data)

        return output_path

    def run_file(self, file_path):
        """运行文件"""
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
        """运行"""
        self.window.mainloop()


def main():
    app = LauncherGUI()
    app.run()


if __name__ == "__main__":
    main()
