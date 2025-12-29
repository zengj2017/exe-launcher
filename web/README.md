# Web 密钥管理系统

基于 Flask 的密钥管理系统，支持多用户、配额管理、密钥续期等功能。

## 功能特性

### 核心功能
- ✅ 用户认证系统（登录/登出）
- ✅ 三种角色：admin（管理员）、dealer（经销商）、user（用户）
- ✅ 密钥管理：创建、续期、启用/禁用、删除
- ✅ 配额管理：经销商有密钥创建配额限制
- ✅ 操作日志：记录所有操作历史
- ✅ Git 同步：一键同步到 GitHub/CDN

### 页面
- 📄 登录页面
- 📊 仪表盘：统计数据、配额信息、最近操作
- 🔑 密钥管理：列表、创建、续期、状态切换
- 👥 用户管理：经销商账户管理（仅admin）
- 📝 操作日志：查看操作历史

### UI 设计
- 🎨 现代化紫色主题 (#667eea)
- 📱 响应式设计
- 🚀 流畅的交互体验

## 快速开始

### 1. 安装依赖

```bash
cd web
pip3 install -r requirements.txt
```

### 2. 初始化数据库

```bash
python3 init_db.py
```

这将创建默认管理员账户：
- 用户名：`admin`
- 密码：`admin123`

### 3. 启动服务

```bash
python3 app.py
```

服务将在 **http://localhost:5001** 启动

### 4. 访问系统

浏览器打开：http://localhost:5001

使用默认账户登录后，请立即修改密码！

## 使用指南

### 管理员操作

#### 创建密钥
1. 进入「密钥管理」页面
2. 点击「创建密钥」
3. 填写用户名称、有效期、备注
4. 点击「创建」，系统会显示完整密钥
5. 复制密钥提供给用户

#### 续期密钥
1. 在密钥列表中找到目标密钥
2. 点击续期图标 ⏱
3. 输入延长天数
4. 确认操作

#### 同步到 GitHub
1. 点击「同步到Git」按钮
2. 系统自动更新 keys.json 并推送到 GitHub
3. jsdelivr CDN 会自动更新（可能有缓存延迟）

### 经销商操作

经销商可以：
- 查看自己创建的密钥
- 创建新密钥（配额内）
- 续期自己创建的密钥
- 启用/禁用自己创建的密钥

**注意**：经销商有配额限制，超过配额无法创建新密钥。

### 权限矩阵

| 操作 | admin | dealer | user |
|------|:-----:|:------:|:----:|
| 查看所有密钥 | ✓ | ✗ | ✗ |
| 查看自己的密钥 | ✓ | ✓ | ✓ |
| 创建密钥 | ✓(无限) | ✓(配额内) | ✗ |
| 续期任意密钥 | ✓ | ✗ | ✗ |
| 续期自己的密钥 | ✓ | ✓ | ✗ |
| 禁用任意密钥 | ✓ | ✗ | ✗ |
| 禁用自己的密钥 | ✓ | ✓ | ✗ |
| 创建经销商 | ✓ | ✗ | ✗ |
| 设置配额 | ✓ | ✗ | ✗ |
| Git 同步 | ✓ | ✗ | ✗ |

## 技术栈

- **后端**：Flask 3.0
- **数据库**：SQLite（本地文件）
- **认证**：Flask-Login
- **前端**：HTML + CSS + JavaScript
- **Git 同步**：GitPython
- **加密**：PyCryptodome

## 数据库表结构

### users（用户表）
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键 |
| username | VARCHAR | 用户名 |
| password_hash | VARCHAR | 密码哈希 |
| role | VARCHAR | 角色（admin/dealer/user） |
| quota_total | INTEGER | 配额总量 |
| quota_used | INTEGER | 已用配额 |
| enabled | BOOLEAN | 是否启用 |

### keys（密钥表）
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键 |
| key_value | VARCHAR(64) | 密钥值 |
| user_name | VARCHAR | 终端用户 |
| expires | DATE | 过期日期 |
| enabled | BOOLEAN | 是否启用 |
| created_by | INTEGER | 创建者ID |

### operation_logs（操作日志表）
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键 |
| user_id | INTEGER | 操作用户 |
| action | VARCHAR | 操作类型 |
| details | TEXT | 详情 |
| ip_address | VARCHAR | IP地址 |
| created_at | TIMESTAMP | 操作时间 |

## API 接口

### 密钥管理
- `POST /api/keys/create` - 创建密钥
- `POST /api/keys/<id>/toggle` - 启用/禁用密钥
- `POST /api/keys/<id>/extend` - 延长有效期
- `POST /api/keys/<id>/delete` - 删除密钥

### 同步
- `POST /api/sync` - 同步到 GitHub

## 配置文件

编辑 `config.py` 修改配置：

```python
# Flask 配置
SECRET_KEY = '你的密钥'
DEBUG = True

# 数据库路径
DATABASE_PATH = './data/database.db'

# keys.json 路径
KEYS_JSON_PATH = '../keys.json'

# Git 配置
GIT_AUTO_PUSH = True
GIT_REMOTE = 'origin'
GIT_BRANCH = 'main'

# 默认配置
DEFAULT_DEALER_QUOTA = 100  # 经销商默认配额
DEFAULT_KEY_DAYS = 30       # 密钥默认有效期
```

## 常见问题

### 1. 端口被占用？

macOS 的 5000 端口默认被 AirPlay 占用，系统已自动使用 5001 端口。

如需更改端口，修改 `app.py` 最后一行：
```python
app.run(host='0.0.0.0', port=你的端口, debug=config.DEBUG)
```

### 2. Git 同步失败？

确保：
- 已配置 Git 凭据
- 对仓库有写权限
- keys.json 路径配置正确

### 3. 忘记密码？

重新初始化数据库：
```bash
rm -rf data/database.db
python3 init_db.py
```

## 安全建议

1. ⚠️ **立即修改默认密码**
2. 🔒 **生产环境使用 HTTPS**
3. 🛡️ **定期备份数据库**
4. 🔑 **妥善保管 SECRET_KEY**
5. 📊 **定期查看操作日志**

## 后续扩展

未来可添加：
- [ ] 批量创建密钥
- [ ] 创建经销商账户（前端）
- [ ] 修改密码功能
- [ ] 数据导出（CSV/Excel）
- [ ] 邮件通知
- [ ] API Token 认证
- [ ] 多语言支持

## 联系方式

如有问题，请提交 Issue 或联系管理员。

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
