# SafeLine WAF API

一个用于管理SafeLine WAF策略的FastAPI接口服务。

## 功能特点

- 支持多雷池WAF实例管理
- 提供策略启用/禁用接口
- 支持查询WAF策略状态
- 完整的日志记录
- Token认证保护

## 安装要求

- Python 3.8+
- FastAPI
- uvicorn

## 应用场景
1、custom_policy_manager.py - 自定义策略管理
2、api_server.py - API服务，加入自定义策略管理，推荐编辑waf策略在控制台，减少误操作，接口只开启关闭策略，不允许编辑策略

## 快速开始

1. 安装依赖
```bash
pip install -r requirements.txt
```

2. 配置WAF实例
编辑`config.py`文件，配置WAF实例信息：
```python
# WAF API配置，支持多个链接
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
```

3. 启动服务
```bash
python api_server.py
```

## API接口

启用

curl -k -X POST -H "token: api-token" http://192.168.1.2:8000/api/challenge/enable/office



关闭

curl -k -X POST -H "token: api-token" http://192.168.1.2:8000/api/challenge/disable/office


## 配置说明

### API配置
在`config.py`中配置API服务参数：
```python
API_CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "tokens": ["your-api-token"],
    "log_file": "logs/waf_api.log"
}
```

## 日志
服务日志默认保存在`logs/waf_api.log`文件中。

## 贡献
欢迎提交Issue和Pull Request。

## 许可证
本项目采用MIT许可证。详见[LICENSE](LICENSE)文件。


## 其他
开发API接口调通：2小时
fastapi输出和配置：2小时
4小时交付