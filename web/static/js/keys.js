// 密钥管理页面脚本

// 显示创建密钥模态框
function showCreateKeyModal() {
    showModal('createKeyModal');
}

// 创建密钥表单提交
document.addEventListener('DOMContentLoaded', function() {
    const createForm = document.getElementById('createKeyForm');
    if (createForm) {
        createForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const formData = new FormData(createForm);
            const data = await fetchAPI('/api/keys/create', {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            if (data.success) {
                closeModal('createKeyModal');
                showMessage('密钥创建成功！');
                showKeyDetail(data.key_id, data.key_value);
                setTimeout(() => location.reload(), 2000);
            } else {
                showMessage(data.message || '创建失败', 'error');
            }
        });
    }

    // 续期表单提交
    const extendForm = document.getElementById('extendKeyForm');
    if (extendForm) {
        extendForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const keyId = document.getElementById('extend_key_id').value;
            const formData = new FormData(extendForm);

            const data = await fetchAPI(`/api/keys/${keyId}/extend`, {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            if (data.success) {
                closeModal('extendKeyModal');
                showMessage('续期成功！新过期日期: ' + data.expires);
                setTimeout(() => location.reload(), 1500);
            } else {
                showMessage(data.message || '续期失败', 'error');
            }
        });
    }
});

// 显示密钥详情
function showKeyDetail(keyId, keyValue) {
    document.getElementById('fullKeyValue').textContent = keyValue;
    showModal('keyDetailModal');
}

// 复制密钥
function copyKey() {
    const keyValue = document.getElementById('fullKeyValue').textContent;
    navigator.clipboard.writeText(keyValue).then(() => {
        showMessage('密钥已复制到剪贴板');
    }).catch(() => {
        showMessage('复制失败', 'error');
    });
}

// 显示续期模态框
function showExtendModal(keyId) {
    document.getElementById('extend_key_id').value = keyId;
    showModal('extendKeyModal');
}

// 切换密钥状态
async function toggleKey(keyId) {
    if (!confirm('确定要切换密钥状态吗？')) {
        return;
    }

    const data = await fetchAPI(`/api/keys/${keyId}/toggle`, {
        method: 'POST'
    });

    if (data.success) {
        showMessage(data.enabled ? '密钥已启用' : '密钥已禁用');
        setTimeout(() => location.reload(), 1000);
    } else {
        showMessage(data.message || '操作失败', 'error');
    }
}

// 删除密钥
async function deleteKey(keyId) {
    if (!confirm('确定要删除这个密钥吗？此操作不可恢复！')) {
        return;
    }

    const data = await fetchAPI(`/api/keys/${keyId}/delete`, {
        method: 'POST'
    });

    if (data.success) {
        showMessage('密钥已删除');
        document.getElementById('key-row-' + keyId).remove();
    } else {
        showMessage(data.message || '删除失败', 'error');
    }
}

// 同步到 Git
async function syncToGit() {
    if (!confirm('确定要同步到 GitHub 吗？')) {
        return;
    }

    showMessage('正在同步...', 'warning');

    const data = await fetchAPI('/api/sync', {
        method: 'POST'
    });

    if (data.success) {
        showMessage(data.message);
    } else {
        showMessage(data.message || '同步失败', 'error');
    }
}
