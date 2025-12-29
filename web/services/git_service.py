"""Git 同步服务"""
import subprocess
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import config

class GitService:
    """Git 同步服务类"""

    @staticmethod
    def push_changes(message):
        """推送更改到 GitHub"""
        try:
            repo_dir = config.BASE_DIR

            # git add keys.json
            subprocess.run(
                ['git', 'add', 'keys.json'],
                cwd=repo_dir,
                check=True,
                capture_output=True
            )

            # git commit
            subprocess.run(
                ['git', 'commit', '-m', message],
                cwd=repo_dir,
                check=True,
                capture_output=True
            )

            # git push
            result = subprocess.run(
                ['git', 'push', config.GIT_REMOTE, config.GIT_BRANCH],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True
            )

            return '同步成功！已推送到 GitHub'

        except subprocess.CalledProcessError as e:
            # 如果没有更改需要提交，也算成功
            if 'nothing to commit' in str(e.stderr):
                return 'keys.json 已是最新，无需推送'
            raise Exception(f'Git 操作失败: {e.stderr}')
