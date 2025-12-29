"""数据库连接管理"""
import sqlite3
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))
import config

def get_db():
    """获取数据库连接"""
    db = sqlite3.connect(config.DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """初始化数据库表"""
    # 确保数据目录存在
    Path(config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    db = get_db()
    cursor = db.cursor()

    # 创建 users 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(128) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            parent_id INTEGER,
            quota_total INTEGER DEFAULT 0,
            quota_used INTEGER DEFAULT 0,
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            note TEXT,
            FOREIGN KEY (parent_id) REFERENCES users(id)
        )
    ''')

    # 创建 keys 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_value VARCHAR(64) UNIQUE NOT NULL,
            user_name VARCHAR(100),
            expires DATE,
            enabled BOOLEAN DEFAULT TRUE,
            note TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # 创建 operation_logs 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action VARCHAR(50) NOT NULL,
            target_type VARCHAR(20),
            target_id INTEGER,
            details TEXT,
            ip_address VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    db.commit()
    db.close()

    print("数据库初始化完成")

if __name__ == '__main__':
    init_db()
