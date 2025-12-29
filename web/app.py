"""Flask Web 应用入口"""
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import hashlib
from functools import wraps
import config
from models import init_db, User, Key, OperationLog
from services.key_service import KeyService
from services.git_service import GitService
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG

# 简单密码哈希函数
def simple_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(hash_value, password):
    return hash_value == simple_password_hash(password)

# Flask-Login 配置
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# 权限装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('需要管理员权限', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def dealer_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'dealer']:
            flash('权限不足', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============ 认证路由 ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.get_by_username(username)

        if user and check_password_hash(user.password_hash, password):
            if not user.enabled:
                flash('账户已被禁用，请联系管理员', 'error')
                return render_template('login.html')

            login_user(user)
            user.update_last_login()

            # 记录登录日志
            OperationLog.create(
                user_id=user.id,
                action='login',
                ip_address=request.remote_addr
            )

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """登出"""
    OperationLog.create(
        user_id=current_user.id,
        action='logout',
        ip_address=request.remote_addr
    )
    logout_user()
    return redirect(url_for('login'))

# ============ 主页面路由 ============

@app.route('/')
@login_required
def index():
    """首页重定向到仪表盘"""
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    """仪表盘"""
    # 统计数据
    if current_user.role == 'admin':
        total_keys = Key.count()
        enabled_keys = Key.count(enabled=True)
    else:
        total_keys = Key.count(created_by=current_user.id)
        enabled_keys = Key.count(created_by=current_user.id, enabled=True)

    # 计算即将过期的密钥（7天内）
    expiring_soon = 0
    expired = 0
    all_keys = Key.get_all(created_by=None if current_user.role == 'admin' else current_user.id)
    today = datetime.now().date()

    for key in all_keys:
        if key.expires and key.enabled:
            expire_date = datetime.strptime(key.expires, '%Y-%m-%d').date()
            days_remaining = (expire_date - today).days
            if days_remaining < 0:
                expired += 1
            elif days_remaining <= 7:
                expiring_soon += 1

    # 最近操作记录
    recent_logs = OperationLog.get_all(
        user_id=None if current_user.role == 'admin' else current_user.id,
        limit=10
    )

    return render_template('dashboard.html',
                         total_keys=total_keys,
                         enabled_keys=enabled_keys,
                         expiring_soon=expiring_soon,
                         expired=expired,
                         recent_logs=recent_logs)

@app.route('/keys')
@login_required
@dealer_or_admin_required
def keys_page():
    """密钥管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    # 获取筛选参数
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')

    # 根据权限获取密钥
    created_by = None if current_user.role == 'admin' else current_user.id
    enabled_filter = None if status == 'all' else (status == 'enabled')

    offset = (page - 1) * per_page
    keys = Key.get_all(created_by=created_by, enabled=enabled_filter, limit=per_page, offset=offset)
    total = Key.count(created_by=created_by, enabled=enabled_filter)

    total_pages = (total + per_page - 1) // per_page

    return render_template('keys.html',
                         keys=keys,
                         page=page,
                         total_pages=total_pages,
                         total=total)

@app.route('/users')
@login_required
@admin_required
def users_page():
    """用户管理页面"""
    users = User.get_all()
    return render_template('users.html', users=users)

@app.route('/logs')
@login_required
def logs_page():
    """操作日志页面"""
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    user_id = None if current_user.role == 'admin' else current_user.id

    offset = (page - 1) * per_page
    logs = OperationLog.get_all(user_id=user_id, limit=per_page, offset=offset)
    total = OperationLog.count(user_id=user_id)

    total_pages = (total + per_page - 1) // per_page

    return render_template('logs.html',
                         logs=logs,
                         page=page,
                         total_pages=total_pages)

# ============ API 路由 ============

@app.route('/api/keys/create', methods=['POST'])
@login_required
@dealer_or_admin_required
def api_create_key():
    """创建密钥 API"""
    try:
        user_name = request.form.get('user_name')
        days = request.form.get('days', type=int)
        note = request.form.get('note', '')

        # 检查配额（非admin）
        if current_user.role != 'admin':
            if current_user.quota_used >= current_user.quota_total:
                return jsonify({'success': False, 'message': '配额已用完'})

        # 创建密钥
        key_id, key_value = Key.create(
            user_name=user_name,
            created_by=current_user.id,
            days=days if days else None,
            note=note
        )

        # 更新配额
        if current_user.role != 'admin':
            current_user.update_quota(1)

        # 记录日志
        OperationLog.create(
            user_id=current_user.id,
            action='create_key',
            target_type='key',
            target_id=key_id,
            details={'user_name': user_name, 'days': days},
            ip_address=request.remote_addr
        )

        # 同步到 keys.json
        KeyService.sync_to_json()

        return jsonify({'success': True, 'key_value': key_value, 'key_id': key_id})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/keys/<int:key_id>/toggle', methods=['POST'])
@login_required
@dealer_or_admin_required
def api_toggle_key(key_id):
    """启用/禁用密钥"""
    try:
        key = Key.get(key_id)
        if not key:
            return jsonify({'success': False, 'message': '密钥不存在'})

        # 权限检查
        if current_user.role != 'admin' and key.created_by != current_user.id:
            return jsonify({'success': False, 'message': '权限不足'})

        key.toggle_enabled()

        # 记录日志
        OperationLog.create(
            user_id=current_user.id,
            action='toggle_key',
            target_type='key',
            target_id=key_id,
            details={'enabled': key.enabled},
            ip_address=request.remote_addr
        )

        # 同步到 keys.json
        KeyService.sync_to_json()

        return jsonify({'success': True, 'enabled': key.enabled})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/keys/<int:key_id>/extend', methods=['POST'])
@login_required
@dealer_or_admin_required
def api_extend_key(key_id):
    """延长密钥有效期"""
    try:
        key = Key.get(key_id)
        if not key:
            return jsonify({'success': False, 'message': '密钥不存在'})

        # 权限检查
        if current_user.role != 'admin' and key.created_by != current_user.id:
            return jsonify({'success': False, 'message': '权限不足'})

        days = request.form.get('days', type=int)
        if not days or days <= 0:
            return jsonify({'success': False, 'message': '天数无效'})

        key.extend(days)

        # 记录日志
        OperationLog.create(
            user_id=current_user.id,
            action='extend_key',
            target_type='key',
            target_id=key_id,
            details={'days': days, 'new_expires': key.expires},
            ip_address=request.remote_addr
        )

        # 同步到 keys.json
        KeyService.sync_to_json()

        return jsonify({'success': True, 'expires': key.expires})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/keys/<int:key_id>/delete', methods=['POST'])
@login_required
@dealer_or_admin_required
def api_delete_key(key_id):
    """删除密钥"""
    try:
        key = Key.get(key_id)
        if not key:
            return jsonify({'success': False, 'message': '密钥不存在'})

        # 权限检查
        if current_user.role != 'admin' and key.created_by != current_user.id:
            return jsonify({'success': False, 'message': '权限不足'})

        # 记录日志（在删除前）
        OperationLog.create(
            user_id=current_user.id,
            action='delete_key',
            target_type='key',
            target_id=key_id,
            details={'key_value': key.key_value[:8] + '...'},
            ip_address=request.remote_addr
        )

        # 减少配额
        if current_user.role != 'admin' and key.created_by == current_user.id:
            current_user.update_quota(-1)

        key.delete()

        # 同步到 keys.json
        KeyService.sync_to_json()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/sync', methods=['POST'])
@login_required
@admin_required
def api_sync():
    """同步到 GitHub"""
    try:
        # 先同步到 keys.json
        KeyService.sync_to_json()

        # Git 推送
        if config.GIT_AUTO_PUSH:
            result = GitService.push_changes('更新密钥数据')
            return jsonify({'success': True, 'message': result})
        else:
            return jsonify({'success': True, 'message': 'keys.json 已更新（未推送到Git）'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    # 初始化数据库（如果不存在）
    import os
    if not os.path.exists(config.DATABASE_PATH):
        print("数据库不存在，正在初始化...")
        from init_db import create_admin_user
        init_db()
        create_admin_user()

    app.run(host='0.0.0.0', port=5001, debug=config.DEBUG)
