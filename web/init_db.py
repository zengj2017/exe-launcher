"""数据库初始化脚本"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from models.database import init_db
from models.user import User
import hashlib
import config

def simple_password_hash(password):
    """简单的密码哈希（使用 SHA256）"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_admin_user():
    """创建默认管理员账户"""
    # 检查是否已存在 admin 用户
    admin = User.get_by_username('admin')
    if admin:
        print("管理员账户已存在")
        return

    # 创建默认管理员
    password = 'admin123'  # 默认密码
    password_hash = simple_password_hash(password)

    user_id = User.create(
        username='admin',
        password_hash=password_hash,
        role='admin',
        parent_id=None,
        quota_total=-1,  # 无限配额
        note='系统管理员'
    )

    print(f"创建管理员账户成功！")
    print(f"用户名: admin")
    print(f"密码: {password}")
    print(f"请登录后立即修改密码！")

if __name__ == '__main__':
    print("正在初始化数据库...")
    init_db()
    print("\n正在创建默认管理员账户...")
    create_admin_user()
    print("\n初始化完成！")
