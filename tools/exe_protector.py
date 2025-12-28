#!/usr/bin/env python3
"""
EXE 加壳保护工具
将原始 EXE 加密并打包成带密钥验证的新 EXE
"""

import os
import sys
import hashlib
import secrets
import base64
import tempfile
import shutil
import subprocess

# 生成的加壳程序模板
WRAPPER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
受保护的程序 - 需要密钥验证才能运行
"""

import os
import sys
import hashlib
import tempfile
import subprocess
import ctypes
import json
import urllib.request
import base64
from datetime import datetime

# ============ 配置区域 ============
ENCRYPTED_DATA = {encrypted_data}
ORIGINAL_FILENAME = {original_filename}
KEY_HASH = {key_hash}  # 密钥的 SHA256 哈希（用于快速验证）
KEYS_URL = {keys_url}  # 云端密钥验证地址（可选）
CONTACT_INFO = {contact_info}
ENABLE_MACHINE_BINDING = {enable_binding}  # 是否启用机器码绑定
APP_SECRET = {app_secret}  # 应用密钥（用于加密绑定数据）
WINDOW_TITLE = {window_title}  # 窗口标题
# =================================

def derive_key(user_key: str) -> bytes:
    """从用户密钥派生 AES 密钥"""
    return hashlib.sha256(user_key.encode()).digest()

def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """AES-256-CBC 解密"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        # 使用纯 Python 实现（简化版）
        return simple_decrypt(encrypted, key)

    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def simple_decrypt(encrypted: bytes, key: bytes) -> bytes:
    """简化的 XOR 解密（备用方案）"""
    iv = encrypted[:16]
    ciphertext = encrypted[16:]

    # 使用 key + iv 生成密钥流
    result = bytearray()
    key_stream = hashlib.sha256(key + iv).digest()

    for i, byte in enumerate(ciphertext):
        if i % 32 == 0 and i > 0:
            key_stream = hashlib.sha256(key_stream + iv).digest()
        result.append(byte ^ key_stream[i % 32])

    # 去除 PKCS7 填充
    padding_len = result[-1]
    if padding_len <= 16:
        result = result[:-padding_len]

    return bytes(result)

def verify_key_online(user_key: str) -> tuple:
    """在线验证密钥"""
    if not KEYS_URL:
        return True, ""

    try:
        req = urllib.request.Request(KEYS_URL, headers={{"User-Agent": "ProtectedApp/1.0"}})
        with urllib.request.urlopen(req, timeout=10) as response:
            keys_data = json.loads(response.read().decode())

        for key_info in keys_data.get("keys", []):
            if key_info.get("key") == user_key:
                if not key_info.get("enabled", True):
                    return False, "此密钥已被禁用"

                expires = key_info.get("expires", "")
                if expires:
                    try:
                        exp_date = datetime.strptime(expires, "%Y-%m-%d")
                        if datetime.now() > exp_date:
                            return False, f"密钥已过期 ({{expires}})"
                    except:
                        pass

                return True, key_info.get("user", "")

        return False, "密钥未授权"
    except Exception as e:
        # 网络错误时，仅使用本地验证
        return True, ""

def verify_key_local(user_key: str) -> bool:
    """本地验证密钥（哈希比对）"""
    key_hash = hashlib.sha256(hashlib.sha256(user_key.encode()).digest()).hexdigest()
    return key_hash == KEY_HASH

def get_machine_id() -> str:
    """获取机器唯一标识"""
    components = []

    try:
        if sys.platform == 'win32':
            # Windows: 获取多种硬件信息
            commands = {{
                'mac': 'wmic nic where "NetEnabled=true" get MACAddress',
                'disk': 'wmic diskdrive get SerialNumber',
                'board': 'wmic baseboard get SerialNumber',
                'cpu': 'wmic cpu get ProcessorId'
            }}

            for name, cmd in commands.items():
                try:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True,
                        text=True, timeout=5
                    )
                    lines = [l.strip() for l in result.stdout.split('\\n') if l.strip()]
                    if len(lines) > 1:
                        value = lines[1]
                        if value and value not in ['None', 'To be filled', '']:
                            components.append(f"{{name}}:{{value}}")
                except:
                    pass
    except:
        pass

    # 备用方案：使用 MAC 地址
    if not components:
        try:
            import uuid
            mac = ':'.join(['{{:02x}}'.format((uuid.getnode() >> i) & 0xff)
                           for i in range(0,48,8)][::-1])
            components.append(f"mac:{{mac}}")
        except:
            components.append("fallback:unknown")

    combined = '|'.join(sorted(components))
    machine_id = hashlib.sha256(combined.encode()).hexdigest()[:32]
    return machine_id

def encrypt_binding_data(data: dict, secret: str) -> bytes:
    """加密绑定数据"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Random import get_random_bytes

        # 计算校验和
        import json
        json_str = json.dumps(data.get('bindings', {{}}), sort_keys=True)
        data['checksum'] = hashlib.sha256(json_str.encode()).hexdigest()

        key = hashlib.sha256(secret.encode()).digest()
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = json.dumps(data).encode()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        return iv + ciphertext
    except:
        # 简化版加密
        import json
        json_str = json.dumps(data)
        key = hashlib.sha256(secret.encode()).digest()
        result = bytearray()
        for i, byte in enumerate(json_str.encode()):
            result.append(byte ^ key[i % 32])
        return bytes(result)

def decrypt_binding_data(encrypted: bytes, secret: str) -> dict:
    """解密绑定数据"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        key = hashlib.sha256(secret.encode()).digest()
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        data = json.loads(plaintext.decode())

        # 验证校验和
        json_str = json.dumps(data.get('bindings', {{}}), sort_keys=True)
        expected = hashlib.sha256(json_str.encode()).hexdigest()
        if data.get('checksum') != expected:
            raise ValueError("数据已被篡改")

        return data
    except:
        # 简化版解密
        key = hashlib.sha256(secret.encode()).digest()
        result = bytearray()
        for i, byte in enumerate(encrypted):
            result.append(byte ^ key[i % 32])
        return json.loads(result.decode())

class MachineBinding:
    """机器码绑定管理"""

    def __init__(self):
        self.machine_id = get_machine_id()
        self.binding_file = self._get_binding_path()
        self.bindings = self._load_bindings()

    def _get_binding_path(self) -> str:
        """获取绑定文件路径"""
        if sys.platform == 'win32':
            appdata = os.environ.get('APPDATA', '')
            if appdata:
                binding_dir = os.path.join(appdata, '.app_binding')
                try:
                    os.makedirs(binding_dir, exist_ok=True)
                    return os.path.join(binding_dir, 'binding.dat')
                except:
                    pass
        return 'binding.dat'

    def _load_bindings(self) -> dict:
        """加载绑定数据"""
        if not os.path.exists(self.binding_file):
            return {{"version": 1, "bindings": {{}}}}

        try:
            with open(self.binding_file, 'rb') as f:
                encrypted = f.read()
            return decrypt_binding_data(encrypted, APP_SECRET)
        except:
            return {{"version": 1, "bindings": {{}}, "corrupted": True}}

    def _save_bindings(self):
        """保存绑定数据"""
        try:
            encrypted = encrypt_binding_data(self.bindings, APP_SECRET)
            with open(self.binding_file, 'wb') as f:
                f.write(encrypted)

            # Windows: 额外保存到注册表
            if sys.platform == 'win32':
                try:
                    import winreg
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                          r"Software\\AppBinding")
                    bindings_json = json.dumps(self.bindings)
                    winreg.SetValueEx(key, "data", 0, winreg.REG_SZ, bindings_json)
                    winreg.CloseKey(key)
                except:
                    pass
        except:
            pass

    def verify_and_bind(self, user_key: str) -> tuple:
        """验证并绑定密钥到当前机器"""
        if self.bindings.get("corrupted"):
            return False, "安全数据已损坏，请联系管理员"

        key_hash = hashlib.sha256(user_key.encode()).hexdigest()[:16]
        bindings = self.bindings.get("bindings", {{}})

        if key_hash in bindings:
            # 已有绑定记录
            binding = bindings[key_hash]
            bound_machine = binding.get("machine_id")

            if bound_machine != self.machine_id:
                return False, "此密钥已绑定到其他机器\\n无法在当前机器使用"

            # 更新使用记录
            binding["last_use"] = datetime.now().isoformat()
            binding["use_count"] = binding.get("use_count", 0) + 1
            self._save_bindings()

            return True, f"验证通过 (使用次数: {{binding['use_count']}})"
        else:
            # 首次使用，创建绑定
            bindings[key_hash] = {{
                "machine_id": self.machine_id,
                "first_use": datetime.now().isoformat(),
                "last_use": datetime.now().isoformat(),
                "use_count": 1
            }}
            self.bindings["bindings"] = bindings
            self._save_bindings()

            return True, "密钥已绑定到当前机器"

def show_message(title: str, message: str, error: bool = False):
    """显示现代化消息框"""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.title("")
        root.overrideredirect(True)  # 无边框窗口
        root.attributes('-topmost', True)

        # 窗口大小和居中
        width, height = 400, 200
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        root.geometry(f"{{width}}x{{height}}+{{x}}+{{y}}")

        # 主容器（模拟圆角和阴影）
        main_bg = "#ffffff"
        root.configure(bg="#e0e0e0")

        # 内容框架
        main_frame = tk.Frame(root, bg=main_bg)
        main_frame.place(x=2, y=2, width=width-4, height=height-4)

        # 顶部颜色条
        accent_color = "#e74c3c" if error else "#2ecc71"
        top_bar = tk.Frame(main_frame, bg=accent_color, height=4)
        top_bar.pack(fill="x")

        # 图标和标题区域
        header_frame = tk.Frame(main_frame, bg=main_bg)
        header_frame.pack(fill="x", pady=(25, 15))

        # 圆形图标背景
        icon_canvas = tk.Canvas(header_frame, width=50, height=50,
                               bg=main_bg, highlightthickness=0)
        icon_canvas.pack()

        # 绘制圆形背景
        icon_bg_color = "#ffeaea" if error else "#eafff0"
        icon_canvas.create_oval(5, 5, 45, 45, fill=icon_bg_color, outline="")

        # 图标文字
        icon_text = "✕" if error else "✓"
        icon_canvas.create_text(25, 25, text=icon_text,
                               font=("Segoe UI", 20, "bold"),
                               fill=accent_color)

        # 标题
        title_label = tk.Label(main_frame, text=title,
                              font=("Segoe UI", 13, "bold"),
                              fg="#2c3e50", bg=main_bg)
        title_label.pack()

        # 消息
        msg_label = tk.Label(main_frame, text=message,
                            font=("Segoe UI", 10),
                            fg="#7f8c8d", bg=main_bg,
                            wraplength=350, justify="center")
        msg_label.pack(pady=(8, 20))

        # 按钮
        btn_frame = tk.Frame(main_frame, bg=main_bg)
        btn_frame.pack()

        def on_enter(e):
            btn.config(bg="#34495e" if error else "#27ae60")

        def on_leave(e):
            btn.config(bg=accent_color)

        btn = tk.Button(btn_frame, text="确 定",
                       font=("Segoe UI", 10),
                       bg=accent_color, fg="white",
                       width=15, height=1,
                       relief="flat", cursor="hand2",
                       activebackground="#34495e",
                       activeforeground="white",
                       command=root.destroy)
        btn.pack(ipady=5)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

        # 支持拖动窗口
        def start_move(event):
            root.x = event.x
            root.y = event.y

        def do_move(event):
            x = root.winfo_x() + event.x - root.x
            y = root.winfo_y() + event.y - root.y
            root.geometry(f"+{{x}}+{{y}}")

        main_frame.bind("<Button-1>", start_move)
        main_frame.bind("<B1-Motion>", do_move)

        root.mainloop()
    except:
        try:
            MB_OK = 0x0
            MB_ICONERROR = 0x10
            MB_ICONINFO = 0x40
            icon = MB_ICONERROR if error else MB_ICONINFO
            ctypes.windll.user32.MessageBoxW(0, message, title, MB_OK | icon)
        except:
            print(f"{{title}}: {{message}}")

def get_key_input() -> str:
    """获取用户输入的密钥 - 现代化界面"""
    try:
        import tkinter as tk

        result = {{"key": ""}}

        root = tk.Tk()
        root.title("")
        root.overrideredirect(True)  # 无边框窗口
        root.attributes('-topmost', True)

        # 窗口大小和居中
        width, height = 480, 340
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        root.geometry(f"{{width}}x{{height}}+{{x}}+{{y}}")

        # 主容器
        main_bg = "#ffffff"
        root.configure(bg="#c0c0c0")

        main_frame = tk.Frame(root, bg=main_bg)
        main_frame.place(x=2, y=2, width=width-4, height=height-4)

        # 顶部渐变色条
        gradient_frame = tk.Frame(main_frame, bg="#667eea", height=80)
        gradient_frame.pack(fill="x")
        gradient_frame.pack_propagate(False)

        # 关闭按钮
        def on_close():
            result["key"] = ""
            root.destroy()

        close_btn = tk.Label(gradient_frame, text="×",
                            font=("Segoe UI", 16),
                            fg="#ffffff", bg="#667eea",
                            cursor="hand2")
        close_btn.place(x=width-35, y=5)
        close_btn.bind("<Button-1>", lambda e: on_close())
        close_btn.bind("<Enter>", lambda e: close_btn.config(fg="#ffcccc"))
        close_btn.bind("<Leave>", lambda e: close_btn.config(fg="#ffffff"))

        # 标题图标和文字
        title_frame = tk.Frame(gradient_frame, bg="#667eea")
        title_frame.pack(expand=True)

        icon_label = tk.Label(title_frame, text="🔐",
                             font=("Segoe UI", 24),
                             fg="#ffffff", bg="#667eea")
        icon_label.pack()

        title_label = tk.Label(title_frame, text=WINDOW_TITLE,
                              font=("Segoe UI", 14, "bold"),
                              fg="#ffffff", bg="#667eea")
        title_label.pack()

        # 内容区域
        content_frame = tk.Frame(main_frame, bg=main_bg)
        content_frame.pack(fill="both", expand=True, padx=40, pady=25)

        # 提示文字
        hint_label = tk.Label(content_frame, text="请输入您的授权密钥",
                             font=("Segoe UI", 10),
                             fg="#95a5a6", bg=main_bg)
        hint_label.pack(anchor="w")

        # 输入框容器（模拟现代输入框）
        entry_container = tk.Frame(content_frame, bg="#f8f9fa",
                                  highlightbackground="#e1e8ed",
                                  highlightthickness=1)
        entry_container.pack(fill="x", pady=(8, 0), ipady=12)

        key_var = tk.StringVar()
        key_entry = tk.Entry(entry_container, textvariable=key_var,
                            font=("Consolas", 11),
                            bg="#f8f9fa", fg="#2c3e50",
                            relief="flat", bd=0)
        key_entry.pack(fill="x", padx=15, pady=5)
        key_entry.focus_set()

        # 输入框获得焦点时的效果
        def on_focus_in(e):
            entry_container.config(highlightbackground="#667eea", highlightthickness=2)

        def on_focus_out(e):
            entry_container.config(highlightbackground="#e1e8ed", highlightthickness=1)

        key_entry.bind("<FocusIn>", on_focus_in)
        key_entry.bind("<FocusOut>", on_focus_out)

        # 状态标签
        status_frame = tk.Frame(content_frame, bg=main_bg)
        status_frame.pack(fill="x", pady=(8, 0))

        status_label = tk.Label(status_frame, text="",
                               font=("Segoe UI", 9),
                               fg="#95a5a6", bg=main_bg)
        status_label.pack(side="left")

        # 进度指示器
        progress_label = tk.Label(status_frame, text="0/64",
                                 font=("Segoe UI", 9),
                                 fg="#bdc3c7", bg=main_bg)
        progress_label.pack(side="right")

        def update_status(*args):
            key = key_var.get().strip()
            length = len(key)
            progress_label.config(text=f"{{length}}/64")

            if length == 0:
                status_label.config(text="", fg="#95a5a6")
                progress_label.config(fg="#bdc3c7")
            elif length == 64:
                try:
                    int(key, 16)
                    status_label.config(text="✓ 格式正确，可以验证", fg="#2ecc71")
                    progress_label.config(fg="#2ecc71")
                except:
                    status_label.config(text="✕ 包含无效字符", fg="#e74c3c")
                    progress_label.config(fg="#e74c3c")
            else:
                status_label.config(text="继续输入...", fg="#f39c12")
                progress_label.config(fg="#f39c12")

        key_var.trace("w", update_status)

        # 按钮区域
        btn_frame = tk.Frame(content_frame, bg=main_bg)
        btn_frame.pack(fill="x", pady=(25, 0))

        def on_submit():
            result["key"] = key_var.get().strip()
            root.destroy()

        # 验证按钮
        def submit_enter(e):
            submit_btn.config(bg="#764ba2")

        def submit_leave(e):
            submit_btn.config(bg="#667eea")

        submit_btn = tk.Button(btn_frame, text="验 证 授 权",
                              font=("Segoe UI", 11, "bold"),
                              bg="#667eea", fg="white",
                              relief="flat", cursor="hand2",
                              activebackground="#764ba2",
                              activeforeground="white",
                              command=on_submit)
        submit_btn.pack(fill="x", ipady=10)
        submit_btn.bind("<Enter>", submit_enter)
        submit_btn.bind("<Leave>", submit_leave)

        # 取消链接
        cancel_label = tk.Label(content_frame, text="取消",
                               font=("Segoe UI", 9, "underline"),
                               fg="#95a5a6", bg=main_bg,
                               cursor="hand2")
        cancel_label.pack(pady=(15, 0))
        cancel_label.bind("<Button-1>", lambda e: on_close())
        cancel_label.bind("<Enter>", lambda e: cancel_label.config(fg="#667eea"))
        cancel_label.bind("<Leave>", lambda e: cancel_label.config(fg="#95a5a6"))

        # 底部联系信息
        contact_frame = tk.Frame(main_frame, bg="#f8f9fa", height=35)
        contact_frame.pack(fill="x", side="bottom")
        contact_frame.pack_propagate(False)

        contact_label = tk.Label(contact_frame, text=CONTACT_INFO,
                                font=("Segoe UI", 8),
                                fg="#95a5a6", bg="#f8f9fa")
        contact_label.pack(expand=True)

        # 快捷键
        root.bind('<Return>', lambda e: on_submit())
        root.bind('<Escape>', lambda e: on_close())

        # 支持拖动窗口
        def start_move(event):
            root.x = event.x
            root.y = event.y

        def do_move(event):
            x = root.winfo_x() + event.x - root.x
            y = root.winfo_y() + event.y - root.y
            root.geometry(f"+{{x}}+{{y}}")

        gradient_frame.bind("<Button-1>", start_move)
        gradient_frame.bind("<B1-Motion>", do_move)

        root.mainloop()
        return result["key"]

    except:
        return input("请输入 64 位授权密钥: ")

def main():
    # 获取密钥
    user_key = get_key_input()

    if not user_key:
        show_message("验证失败", "未输入密钥", error=True)
        sys.exit(1)

    # 验证密钥格式
    user_key = user_key.strip().lower()
    if len(user_key) != 64:
        show_message("验证失败", "密钥格式错误，需要 64 位十六进制字符", error=True)
        sys.exit(1)

    # 本地验证
    if not verify_key_local(user_key):
        show_message("验证失败", "密钥无效", error=True)
        sys.exit(1)

    # 在线验证（可选）
    online_valid, info = verify_key_online(user_key)
    if not online_valid:
        show_message("验证失败", info, error=True)
        sys.exit(1)

    # 机器码绑定验证
    if ENABLE_MACHINE_BINDING:
        try:
            binding = MachineBinding()
            success, msg = binding.verify_and_bind(user_key)
            if not success:
                show_message("绑定验证失败", msg, error=True)
                sys.exit(1)
            # 验证成功时显示提示信息
            if "绑定" in msg:
                show_message("验证成功", msg, error=False)
        except Exception as e:
            show_message("绑定验证失败", f"验证过程出错\\n{{str(e)}}", error=True)
            sys.exit(1)

    # 解密程序
    try:
        encrypted_bytes = base64.b64decode(ENCRYPTED_DATA)
        aes_key = derive_key(user_key)
        decrypted = decrypt_data(encrypted_bytes, aes_key)
    except Exception as e:
        show_message("解密失败", f"密钥无法解密此程序\\n{{str(e)}}", error=True)
        sys.exit(1)

    # 写入临时文件并运行
    try:
        temp_dir = tempfile.mkdtemp()
        temp_exe = os.path.join(temp_dir, ORIGINAL_FILENAME)

        with open(temp_exe, 'wb') as f:
            f.write(decrypted)

        # 运行程序
        if sys.platform == 'win32':
            os.startfile(temp_exe)
        else:
            subprocess.Popen([temp_exe], shell=True)

    except Exception as e:
        show_message("运行失败", f"无法启动程序\\n{{str(e)}}", error=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
'''

def encrypt_exe(exe_path: str, user_key: str) -> bytes:
    """加密 EXE 文件"""
    # 尝试使用 pycryptodome
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        with open(exe_path, 'rb') as f:
            data = f.read()

        key = hashlib.sha256(user_key.encode()).digest()
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        return iv + encrypted
    except ImportError:
        # 使用简化的 XOR 加密
        return simple_encrypt(exe_path, user_key)

def simple_encrypt(exe_path: str, user_key: str) -> bytes:
    """简化的 XOR 加密"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    key = hashlib.sha256(user_key.encode()).digest()
    iv = secrets.token_bytes(16)

    # PKCS7 填充
    padding_len = 16 - (len(data) % 16)
    data = data + bytes([padding_len] * padding_len)

    # XOR 加密
    result = bytearray()
    key_stream = hashlib.sha256(key + iv).digest()

    for i, byte in enumerate(data):
        if i % 32 == 0 and i > 0:
            key_stream = hashlib.sha256(key_stream + iv).digest()
        result.append(byte ^ key_stream[i % 32])

    return iv + bytes(result)

def generate_key() -> str:
    """生成随机 64 位十六进制密钥"""
    return secrets.token_hex(32)

def create_protected_exe(
    input_exe: str,
    output_dir: str,
    user_key: str = None,
    keys_url: str = "",
    contact_info: str = "联系管理员获取授权",
    enable_machine_binding: bool = True,
    app_secret: str = None,
    window_title: str = "软件授权验证"
) -> dict:
    """
    创建受保护的 EXE

    Args:
        input_exe: 原始 EXE 路径
        output_dir: 输出目录
        user_key: 指定密钥（可选，不指定则自动生成）
        keys_url: 云端密钥验证地址（可选）
        contact_info: 联系信息
        enable_machine_binding: 是否启用机器码绑定（默认True）
        app_secret: 应用密钥（用于加密绑定数据，可选）

    Returns:
        包含输出文件路径和密钥的字典
    """
    if not os.path.exists(input_exe):
        raise FileNotFoundError(f"文件不存在: {input_exe}")

    # 生成或使用指定密钥
    if user_key:
        if len(user_key) != 64:
            raise ValueError("密钥必须是 64 位十六进制字符")
    else:
        user_key = generate_key()

    # 生成应用密钥（用于加密绑定数据）
    if not app_secret:
        app_secret = secrets.token_hex(32)

    # 加密 EXE
    print(f"正在加密: {input_exe}")
    encrypted_data = encrypt_exe(input_exe, user_key)
    encrypted_b64 = base64.b64encode(encrypted_data).decode()

    # 计算密钥哈希（双重哈希，用于本地验证）
    key_hash = hashlib.sha256(hashlib.sha256(user_key.encode()).digest()).hexdigest()

    # 原始文件名
    original_filename = os.path.basename(input_exe)

    # 生成包装程序
    wrapper_code = WRAPPER_TEMPLATE.format(
        encrypted_data=repr(encrypted_b64),
        original_filename=repr(original_filename),
        key_hash=repr(key_hash),
        keys_url=repr(keys_url) if keys_url else "None",
        contact_info=repr(contact_info),
        enable_binding=enable_machine_binding,
        app_secret=repr(app_secret),
        window_title=repr(window_title)
    )

    # 保存包装程序
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(original_filename)[0]
    wrapper_py = os.path.join(output_dir, f"{base_name}_protected.py")

    with open(wrapper_py, 'w', encoding='utf-8') as f:
        f.write(wrapper_code)

    print(f"生成包装程序: {wrapper_py}")

    # 尝试编译为 EXE
    output_exe = None
    try:
        output_exe = compile_to_exe(wrapper_py, output_dir)
    except Exception as e:
        print(f"注意: 无法自动编译 EXE ({e})")
        print("请手动使用 PyInstaller 编译")

    return {
        "wrapper_py": wrapper_py,
        "output_exe": output_exe,
        "key": user_key,
        "key_hash": key_hash,
        "original_size": os.path.getsize(input_exe),
        "encrypted_size": len(encrypted_data)
    }

def compile_to_exe(py_file: str, output_dir: str) -> str:
    """使用 PyInstaller 编译为 EXE"""
    try:
        import PyInstaller.__main__
    except ImportError:
        raise ImportError("需要安装 PyInstaller: pip install pyinstaller")

    base_name = os.path.splitext(os.path.basename(py_file))[0]

    PyInstaller.__main__.run([
        py_file,
        '--onefile',
        '--windowed',
        '--name', base_name,
        '--distpath', output_dir,
        '--workpath', os.path.join(output_dir, 'build'),
        '--specpath', os.path.join(output_dir, 'build'),
        '--clean',
        '--noconfirm'
    ])

    output_exe = os.path.join(output_dir, f"{base_name}.exe")
    if os.path.exists(output_exe):
        return output_exe
    return None

def main():
    import argparse

    parser = argparse.ArgumentParser(description='EXE 加壳保护工具')
    parser.add_argument('input', help='输入的 EXE 文件路径')
    parser.add_argument('-o', '--output', default='./protected', help='输出目录')
    parser.add_argument('-k', '--key', help='指定 64 位密钥（可选）')
    parser.add_argument('--keys-url', help='云端密钥验证地址（可选）')
    parser.add_argument('--contact', default='联系管理员获取授权', help='联系信息')
    parser.add_argument('--title', default='软件授权验证', help='窗口标题')
    parser.add_argument('--enable-binding', action='store_true', default=True,
                       help='启用机器码绑定（默认启用）')
    parser.add_argument('--no-binding', dest='enable_binding', action='store_false',
                       help='禁用机器码绑定')

    args = parser.parse_args()

    try:
        result = create_protected_exe(
            args.input,
            args.output,
            args.key,
            args.keys_url,
            args.contact,
            args.enable_binding,
            window_title=args.title
        )

        print("\n" + "=" * 50)
        print("加壳完成!")
        print("=" * 50)
        print(f"包装程序: {result['wrapper_py']}")
        if result['output_exe']:
            print(f"输出 EXE: {result['output_exe']}")
        print(f"原始大小: {result['original_size']:,} 字节")
        print(f"加密大小: {result['encrypted_size']:,} 字节")
        print(f"\n授权密钥: {result['key']}")
        print("\n请妥善保管密钥，用户需要此密钥才能运行程序")

    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
