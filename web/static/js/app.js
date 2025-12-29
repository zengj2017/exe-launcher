// 密钥管理系统 - 通用脚本

// 显示模态框
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('show');
        modal.style.display = 'flex';
    }
}

// 关闭模态框
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
}

// 点击模态框外部关闭
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.classList.remove('show');
        setTimeout(() => {
            event.target.style.display = 'none';
        }, 300);
    }
}

// Toast 图标映射
function getToastIcon(type) {
    const icons = {
        'success': '✓',
        'error': '✕',
        'warning': '⚠',
        'info': 'ℹ'
    };
    return icons[type] || icons['info'];
}

// 现代化 Toast 通知系统
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    toast.innerHTML = `
        <div class="toast-icon">${getToastIcon(type)}</div>
        <div class="toast-content">
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.classList.add('toast-exit')">✕</button>
        <div class="toast-progress"></div>
    `;

    document.body.appendChild(toast);

    // 4秒后自动关闭
    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// 兼容旧的 showMessage 函数（使用 Toast）
function showMessage(message, type = 'success') {
    showToast(message, type);
}

// AJAX 请求辅助函数
async function fetchAPI(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...options.headers
            }
        });

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('API 请求失败:', error);
        showToast('请求失败，请稍后重试', 'error');
        return { success: false, message: error.message };
    }
}

// 页面加载动画
document.addEventListener('DOMContentLoaded', function() {
    // 为所有卡片添加渐入动画
    const cards = document.querySelectorAll('.stat-card, .glass-card, .table-container');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
    });
});
