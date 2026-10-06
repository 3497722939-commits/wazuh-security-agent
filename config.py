"""
配置模块：从环境变量读取 Wazuh 连接信息，不硬编码密码。
自动加载同目录下的 .env 文件。
"""
import os


def _load_env_file():
    """从同目录的 .env 文件加载环境变量（不覆盖已有的）。"""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


_load_env_file()


class Config:
    # Indexer (OpenSearch) 连接
    WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.174.137:9200")
    WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "admin")
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")

    # Wazuh REST API（预留，MVP 阶段主要用 Indexer）
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://192.168.174.137:55000")

    # 查询限制
    MAX_RESULTS = int(os.getenv("WAZUH_MAX_RESULTS", "500"))
    DEFAULT_LOOKBACK_HOURS = int(os.getenv("WAZUH_LOOKBACK_HOURS", "24"))
    MAX_LOOKBACK_HOURS = int(os.getenv("WAZUH_MAX_LOOKBACK_HOURS", "168"))  # 7天

    # Wazuh 索引名
    ALERTS_INDEX = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")
    MONITORING_INDEX = os.getenv("WAZUH_MONITORING_INDEX", "wazuh-monitoring-*")

    # SSL 验证（内网自签证书，默认不验证）
    VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

    @classmethod
    def validate(cls):
        """校验必要配置是否齐全。"""
        if not cls.WAZUH_PASSWORD:
            raise ValueError(
                "WAZUH_PASSWORD 环境变量未设置。请设置后重试。"
            )
        return True
