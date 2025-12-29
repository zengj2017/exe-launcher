"""操作日志模型"""
from .database import get_db
import json

class OperationLog:
    """操作日志模型类"""

    def __init__(self, id, user_id, action, target_type, target_id,
                 details, ip_address, created_at):
        self.id = id
        self.user_id = user_id
        self.action = action
        self.target_type = target_type
        self.target_id = target_id
        self.details = details
        self.ip_address = ip_address
        self.created_at = created_at

    @staticmethod
    def create(user_id, action, target_type=None, target_id=None,
               details=None, ip_address=None):
        """创建操作日志"""
        details_str = json.dumps(details, ensure_ascii=False) if details else None

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO operation_logs
            (user_id, action, target_type, target_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, action, target_type, target_id, details_str, ip_address))
        log_id = cursor.lastrowid
        db.commit()
        db.close()

        return log_id

    @staticmethod
    def get_all(user_id=None, action=None, limit=None, offset=0):
        """获取操作日志列表"""
        db = get_db()
        cursor = db.cursor()

        query = 'SELECT * FROM operation_logs WHERE 1=1'
        params = []

        if user_id is not None:
            query += ' AND user_id = ?'
            params.append(user_id)

        if action:
            query += ' AND action = ?'
            params.append(action)

        query += ' ORDER BY created_at DESC'

        if limit:
            query += ' LIMIT ? OFFSET ?'
            params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        db.close()

        return [OperationLog(**dict(row)) for row in rows]

    @staticmethod
    def count(user_id=None, action=None):
        """统计日志数量"""
        db = get_db()
        cursor = db.cursor()

        query = 'SELECT COUNT(*) as count FROM operation_logs WHERE 1=1'
        params = []

        if user_id is not None:
            query += ' AND user_id = ?'
            params.append(user_id)

        if action:
            query += ' AND action = ?'
            params.append(action)

        cursor.execute(query, params)
        count = cursor.fetchone()['count']
        db.close()

        return count

    def to_dict(self):
        """转换为字典"""
        details_obj = json.loads(self.details) if self.details else None
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'details': details_obj,
            'ip_address': self.ip_address,
            'created_at': self.created_at
        }
