"""密钥模型"""
from .database import get_db
from datetime import datetime, timedelta
import secrets

class Key:
    """密钥模型类"""

    def __init__(self, id, key_value, user_name, expires, enabled,
                 note, created_by, created_at, updated_at):
        self.id = id
        self.key_value = key_value
        self.user_name = user_name
        self.expires = expires
        self.enabled = enabled
        self.note = note
        self.created_by = created_by
        self.created_at = created_at
        self.updated_at = updated_at

    @staticmethod
    def generate_key():
        """生成64位十六进制密钥"""
        return secrets.token_hex(32)

    @staticmethod
    def create(user_name, created_by, days=None, expires=None, note=None):
        """创建新密钥"""
        key_value = Key.generate_key()

        # 计算过期时间
        if expires:
            expires_str = expires
        elif days:
            expires_date = datetime.now() + timedelta(days=days)
            expires_str = expires_date.strftime('%Y-%m-%d')
        else:
            expires_str = None  # 永久有效

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO keys (key_value, user_name, expires, note, created_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (key_value, user_name, expires_str, note, created_by))
        key_id = cursor.lastrowid
        db.commit()
        db.close()

        return key_id, key_value

    @staticmethod
    def get(key_id):
        """根据ID获取密钥"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM keys WHERE id = ?', (key_id,))
        row = cursor.fetchone()
        db.close()

        if row:
            return Key(**dict(row))
        return None

    @staticmethod
    def get_by_value(key_value):
        """根据密钥值获取"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM keys WHERE key_value = ?', (key_value,))
        row = cursor.fetchone()
        db.close()

        if row:
            return Key(**dict(row))
        return None

    @staticmethod
    def get_all(created_by=None, enabled=None, limit=None, offset=0):
        """获取密钥列表"""
        db = get_db()
        cursor = db.cursor()

        query = 'SELECT * FROM keys WHERE 1=1'
        params = []

        if created_by is not None:
            query += ' AND created_by = ?'
            params.append(created_by)

        if enabled is not None:
            query += ' AND enabled = ?'
            params.append(enabled)

        query += ' ORDER BY created_at DESC'

        if limit:
            query += ' LIMIT ? OFFSET ?'
            params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        db.close()

        return [Key(**dict(row)) for row in rows]

    @staticmethod
    def count(created_by=None, enabled=None):
        """统计密钥数量"""
        db = get_db()
        cursor = db.cursor()

        query = 'SELECT COUNT(*) as count FROM keys WHERE 1=1'
        params = []

        if created_by is not None:
            query += ' AND created_by = ?'
            params.append(created_by)

        if enabled is not None:
            query += ' AND enabled = ?'
            params.append(enabled)

        cursor.execute(query, params)
        count = cursor.fetchone()['count']
        db.close()

        return count

    def extend(self, days):
        """延长有效期"""
        if self.expires:
            current_expires = datetime.strptime(self.expires, '%Y-%m-%d')
        else:
            current_expires = datetime.now()

        new_expires = current_expires + timedelta(days=days)
        new_expires_str = new_expires.strftime('%Y-%m-%d')

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE keys SET expires = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        ''', (new_expires_str, self.id))
        db.commit()
        db.close()

        self.expires = new_expires_str

    def toggle_enabled(self):
        """切换启用/禁用状态"""
        new_status = not self.enabled
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE keys SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        ''', (new_status, self.id))
        db.commit()
        db.close()

        self.enabled = new_status

    def update_note(self, note):
        """更新备注"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE keys SET note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        ''', (note, self.id))
        db.commit()
        db.close()

        self.note = note

    def delete(self):
        """删除密钥"""
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM keys WHERE id = ?', (self.id,))
        db.commit()
        db.close()

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'key_value': self.key_value,
            'user_name': self.user_name,
            'expires': self.expires,
            'enabled': self.enabled,
            'note': self.note,
            'created_by': self.created_by,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
