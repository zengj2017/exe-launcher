"""Web 管理系统配置文件"""
import os
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).parent.parent

# Flask 配置
SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

# 数据库配置
DATABASE_PATH = os.path.join(BASE_DIR, 'web', 'data', 'database.db')

# keys.json 路径
KEYS_JSON_PATH = os.path.join(BASE_DIR, 'keys.json')

# Git 配置
GIT_AUTO_PUSH = os.environ.get('GIT_AUTO_PUSH', 'True').lower() == 'true'
GIT_REMOTE = 'origin'
GIT_BRANCH = 'main'

# 默认配置
DEFAULT_DEALER_QUOTA = 100  # 经销商默认配额
DEFAULT_KEY_DAYS = 30       # 密钥默认有效期（天）

# 分页配置
ITEMS_PER_PAGE = 20
