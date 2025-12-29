"""用户模型"""
from flask_login import UserMixin
from .database import get_db

class User(UserMixin):
    """用户模型类"""

    def __init__(self, id, username, password_hash, role, parent_id=None,
                 quota_total=0, quota_used=0, enabled=True, created_at=None,
                 updated_at=None, last_login=None, note=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.parent_id = parent_id
        self.quota_total = quota_total
        self.quota_used = quota_used
        self.enabled = enabled
        self.created_at = created_at
        self.updated_at = updated_at
        self.last_login = last_login
        self.note = note

    @staticmethod
    def get(user_id):
        """根据ID获取用户"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        db.close()

        if row:
            return User(**dict(row))
        return None

    @staticmethod
    def get_by_username(username):
        """根据用户名获取用户"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        db.close()

        if row:
            return User(**dict(row))
        return None

    @staticmethod
    def create(username, password_hash, role, parent_id=None, quota_total=0, note=None):
        """创建新用户"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, parent_id, quota_total, note)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, role, parent_id, quota_total, note))
        user_id = cursor.lastrowid
        db.commit()
        db.close()
        return user_id

    @staticmethod
    def get_all(role=None):
        """获取所有用户"""
        db = get_db()
        cursor = db.cursor()
        if role:
            cursor.execute('SELECT * FROM users WHERE role = ? ORDER BY created_at DESC', (role,))
        else:
            cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        rows = cursor.fetchall()
        db.close()
        return [User(**dict(row)) for row in rows]

    def update_quota(self, used_delta):
        """更新配额使用量"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE users SET quota_used = quota_used + ? WHERE id = ?
        ''', (used_delta, self.id))
        db.commit()
        db.close()
        self.quota_used += used_delta

    def set_quota(self, total):
        """设置配额总量"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE users SET quota_total = ? WHERE id = ?
        ''', (total, self.id))
        db.commit()
        db.close()
        self.quota_total = total

    def toggle_enabled(self):
        """切换启用/禁用状态"""
        new_status = not self.enabled
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE users SET enabled = ? WHERE id = ?
        ''', (new_status, self.id))
        db.commit()
        db.close()
        self.enabled = new_status

    def update_last_login(self):
        """更新最后登录时间"""
        from datetime import datetime
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE users SET last_login = ? WHERE id = ?
        ''', (datetime.now(), self.id))
        db.commit()
        db.close()

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'parent_id': self.parent_id,
            'quota_total': self.quota_total,
            'quota_used': self.quota_used,
            'enabled': self.enabled,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'note': self.note
        }
