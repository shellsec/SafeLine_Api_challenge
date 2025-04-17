# WAF API配置
WAF_OFFICE_CONFIGS = {
    "office": [
        {
            "name": "waf1_instance1",
            "base_url": "https://192.168.1.1:9443/api",
            "api_token": "api_token",
            "id": [1],
            "URL": [
                {
                    "k": "uri",
                    "op": "=",
                    "v": "/accounts/signup",
                    "sub_k": ""
                }
                # {
                #     "k": "uri",
                #     "op": "=",
                #     "v": "/api/auth",
                #     "sub_k": ""
                # },
                # {
                #     "k": "uri",
                #     "op": "=",
                #     "v": "/user/profile",
                #     "sub_k": ""
                # }
            ]
        }
    ]
}



# API服务配置
API_CONFIG = {
    "tokens": [
        "KQo55s0kDZtSBqYbiCuhIG9E",
        "api_token",
        "api_token"
    ],
    "host": "0.0.0.0",
    "port": 8000,
    "log_file": "/opt/waf-api/logs/waf_api.log"  # 修改为Linux路径格式
}

# 当前使用的配置
# WAF_CONFIGS = WAF_TEST_CONFIGS
# WAF_CONFIGS = WAF_TEST_CONFIGS
WAF_CONFIGS = WAF_OFFICE_CONFIGS

