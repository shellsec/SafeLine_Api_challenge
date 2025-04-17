from fastapi import FastAPI, Header, HTTPException
from typing import Optional, List, Dict
from custom_policy_manager import CustomPolicyManager
from config import WAF_CONFIGS, API_CONFIG
import asyncio
import logging
import os
from datetime import datetime

# 设置日志
log_dir = os.path.dirname(API_CONFIG["log_file"])
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=API_CONFIG["log_file"],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI(
    docs_url=None,          # 禁用 Swagger UI
    redoc_url=None,         # 禁用 ReDoc
    openapi_url=None,       # 禁用 OpenAPI
    swagger_ui_oauth2_redirect_url=None,  # 禁用 OAuth2 重定向
)

async def verify_token(token: Optional[str] = Header(None)):
    if not token or token not in API_CONFIG["tokens"]:
        logging.warning(f"Invalid token attempt: {token}")
        raise HTTPException(status_code=401, detail="Invalid token")
    logging.info(f"Valid token used for API access")

async def process_waf_instance(waf_config: Dict, enable: bool, is_challenge: bool = False) -> Dict:
    try:
        # 验证必要的配置字段是否存在
        required_fields = ["base_url", "api_token", "id", "name"]
        for field in required_fields:
            if field not in waf_config:
                raise ValueError(f"缺少必要的配置字段: {field}")

        policy_manager = CustomPolicyManager()
        policy_manager.base_url = waf_config["base_url"]
        policy_manager.headers["X-SLCE-API-TOKEN"] = waf_config["api_token"]
        
        results = []
        for site_id in waf_config["id"]:
            try:
                if is_challenge:
                    # 构造正确的 pattern 格式
                    pattern = []
                    if enable and "URL" in waf_config:
                        # 将每个 URL 规则转换为正确的格式
                        for rule in waf_config["URL"]:
                            # 修改 op 为 "has"，并将 v 转换为列表
                            pattern.append([{
                                "k": rule["k"],
                                "op": "has",  # 修改操作符
                                "v": [rule["v"]],  # 将值转换为列表
                                "sub_k": rule["sub_k"]
                            }])
                    logging.info(f"Configuring challenge for site {site_id} - enable: {enable}, pattern: {pattern}")
                    result = policy_manager.switch_challenge(
                        site_id=site_id,
                        enable=enable,
                        level=1,  # 使用标准验证强度
                        expire=3600,  # 1小时过期
                        replay=False,
                        negate=False,
                        pattern=pattern
                    )
                    logging.info(f"Challenge API response for site {site_id}: {result}")
                else:
                    logging.info(f"Switching policy for site {site_id} - enable: {enable}")
                    result = policy_manager.switch_policy(site_id, enable)
                    logging.info(f"Policy API response for site {site_id}: {result}")
                
                status = "success"
                logging.info(f"Successfully {'enabled' if enable else 'disabled'} {'challenge' if is_challenge else 'policy'} for site {site_id} on WAF {waf_config['name']}")
            except Exception as e:
                status = "error"
                error_msg = str(e)
                logging.error(f"Error processing {'challenge' if is_challenge else 'policy'} for site {site_id} on WAF {waf_config['name']}: {error_msg}")
                result = {"error": error_msg, "details": getattr(e, 'response', {}).get('text', 'No additional details')}
            
            results.append({
                "site_id": site_id,
                "status": status,
                "result": result
            })
        
        return {
            "waf_name": waf_config["name"],
            "results": results
        }
    except Exception as e:
        logging.error(f"Error processing WAF instance {waf_config['name']}: {str(e)}")
        return {
            "waf_name": waf_config["name"],
            "status": "error",
            "error": str(e)
        }

async def process_waf_instances(waf_instances: List[Dict], enable: bool, is_challenge: bool = False) -> List[Dict]:
    results = []
    for instance in waf_instances:
        result = await process_waf_instance(instance, enable, is_challenge)
        results.append(result)
    return results

@app.post("/api/challenge/enable/{waf_id}")
async def enable_challenge_for_waf(waf_id: str, token: Optional[str] = Header(None)):
    await verify_token(token)
    if waf_id not in WAF_CONFIGS:
        raise HTTPException(status_code=404, detail=f"WAF {waf_id} not found")
    results = await process_waf_instances(WAF_CONFIGS[waf_id], True, True)
    return {"results": results}

@app.post("/api/challenge/disable/{waf_id}")
async def disable_challenge_for_waf(waf_id: str, token: Optional[str] = Header(None)):
    await verify_token(token)
    if waf_id not in WAF_CONFIGS:
        raise HTTPException(status_code=404, detail=f"WAF {waf_id} not found")
    results = await process_waf_instances(WAF_CONFIGS[waf_id], False, True)
    return {"results": results}


@app.get("/api/status/{waf_id}")
async def get_waf_status(waf_id: str, token: Optional[str] = Header(None)):
    await verify_token(token)
    if waf_id not in WAF_CONFIGS:
        raise HTTPException(status_code=404, detail=f"WAF {waf_id} not found")
    
    status_results = []
    for instance in WAF_CONFIGS[waf_id]:
        try:
            policy_manager = CustomPolicyManager()
            policy_manager.base_url = instance["base_url"]
            policy_manager.headers["X-SLCE-API-TOKEN"] = instance["api_token"]
            
            policies_status = []
            for policy_id in instance["policy_ids"]:
                try:
                    detail = policy_manager.get_policy_detail(policy_id)
                    status = "success"
                    is_enabled = detail.get("data", {}).get("is_enabled", False)
                except Exception as e:
                    status = "error"
                    is_enabled = None
                    logging.error(f"Error getting status for policy {policy_id} on WAF {instance['name']}: {str(e)}")
                
                policies_status.append({
                    "policy_id": policy_id,
                    "status": status,
                    "is_enabled": is_enabled
                })
            
            status_results.append({
                "waf_name": instance["name"],
                "policies": policies_status
            })
        except Exception as e:
            logging.error(f"Error processing WAF instance {instance['name']} status: {str(e)}")
            status_results.append({
                "waf_name": instance["name"],
                "status": "error",
                "error": str(e)
            })
    
    return {"results": status_results}

if __name__ == "__main__":
    logging.info("Starting WAF API server")
    import uvicorn
    # uvicorn.run(app, host="0.0.0.0", port=8000)
    uvicorn.run(
        app,
        host=API_CONFIG["host"],
        port=API_CONFIG["port"],
        log_level="info",
        reload=False,
        workers=1,
        loop="asyncio",  # 使用默认的 asyncio 而不是 uvloop
        http="h11"      # 使用 h11 而不是 httptools
    )