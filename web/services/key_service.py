"""密钥服务"""
import json
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import config
from models import Key

class KeyService:
    """密钥服务类"""

    @staticmethod
    def sync_to_json():
        """将数据库中的密钥同步到 keys.json"""
        # 获取所有密钥
        all_keys = Key.get_all()

        # 读取现有 keys.json
        try:
            with open(config.KEYS_JSON_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {
                "version": 2,
                "updated": "",
                "keys": [],
                "settings": {
                    "download_url": "",
                    "contact": "续费联系管理员"
                }
            }

        # 更新密钥列表
        from datetime import datetime
        data['updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data['keys'] = []

        for key in all_keys:
            data['keys'].append({
                'key': key.key_value,
                'user': key.user_name or '',
                'expires': key.expires or '',
                'enabled': key.enabled,
                'note': key.note or ''
            })

        # 写回文件
        with open(config.KEYS_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        return len(all_keys)
