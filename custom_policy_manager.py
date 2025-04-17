import requests
import json
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from config import WAF_CONFIGS, API_CONFIG

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 配置重试策略
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

class CustomPolicyManager:
    def __init__(self):
        self.base_url = None
        self.headers = {
            "Content-Type": "application/json"
        }
        
        # 创建Session并配置重试机制
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False


    def switch_challenge(self, site_id, enable=True, level=1, expire=3600, replay=False, negate=False, pattern=None):
        """启用或禁用站点的challenge验证
        Args:
            pattern: 列表类型，每个元素为一个规则字典，包含k、op、v和sub_k属性
                     例如：[[{"k":"uri","op":"has","v":["/api/test"],"sub_k":""}]]
        """
        url = f"{self.base_url}/open/site/challenge"
        data = {
            "enable": enable,
            "id": site_id,
            "level": level,
            "expire": expire,
            "replay": replay,
            "negate": negate,
            "pattern": pattern if pattern is not None else []
        }
        import logging
        logging.info(f"Calling switch_challenge API - site_id: {site_id}, enable: {enable}, pattern: {pattern}")
        response = self.session.put(url, headers=self.headers, json=data, timeout=30)
        response_json = response.json()
        logging.info(f"switch_challenge API response: {response_json}")
        return response_json

    def create_policy(self, name, description, rules):
        """创建新的自定义规则"""
        url = f"{self.base_url}/open/policy"
        data = {
            "name": name,
            "description": description,
            "rules": rules
        }
        response = self.session.post(url, headers=self.headers, json=data, timeout=30)
        return response.json()

    # 在 CustomPolicyManager 类中添加以下方法
    def delete_policy(self, policy_id):
        """删除自定义规则"""
        url = f"{self.base_url}/open/policy"
        params = {"id": policy_id}
        response = self.session.delete(url, headers=self.headers, params=params, timeout=30)
        return response.json()

    def update_policy(self, policy_id, update_data):
        """更新自定义规则"""
        url = f"{self.base_url}/open/policy"
        data = {
            "id": policy_id,
            **update_data
        }
        response = self.session.put(url, headers=self.headers, json=data, timeout=30)
        return response.json()

    def switch_policy(self, site_id, enable=True):
        """启用或禁用站点的策略
        Args:
            site_id: 站点ID
            enable: True表示启用，False表示禁用
        Returns:
            API响应结果
        """
        url = f"{self.base_url}/open/site/policy"
        data = {
            "enable": enable,
            "id": site_id
        }
        response = self.session.put(url, headers=self.headers, json=data, timeout=30)
        return response.json()


if __name__ == "__main__":
    # 创建管理器实例
    manager = CustomPolicyManager()

    # 4. Challenge验证功能测试
    site_id = 11  # 替换为实际的站点ID
    print("\n4. Challenge验证功能测试：")
    
    # 4.1 开启Challenge验证
    print("\n4.1 开启Challenge验证：")
    # 支持多个独立的URL规则
    pattern = [[{"k":"uri","op":"has","v":["/api/test"],"sub_k":""},{"k":"uri","op":"has","v":["/accounts/login"],"sub_k":""}]]
    enable_challenge = manager.switch_challenge(
        site_id=site_id,
        enable=True,
        level=1,  # 验证强度：1=标准，2=严格
        expire=3600,  # 验证有效期（秒）
        pattern=pattern  # 支持多个独立的URL规则的验证
    )
    print(json.dumps(enable_challenge, indent=2, ensure_ascii=False))

    # # 4.2 关闭Challenge验证
    # print("\n4.2 关闭Challenge验证：")
    # disable_challenge = manager.switch_challenge(
    #     site_id=site_id,
    #     enable=False,
    #     level=1,
    #     expire=3600,
    #     replay=False,
    #     negate=False,
    #     pattern=[]
    # )
    # print(json.dumps(disable_challenge, indent=2, ensure_ascii=False))



