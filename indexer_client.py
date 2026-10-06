"""
Wazuh Indexer (OpenSearch) 客户端：只读搜索接口。
"""
import json
import ssl
import base64
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

from config import Config

logger = logging.getLogger(__name__)


class IndexerClient:
    def __init__(self):
        self.base_url = Config.WAZUH_INDEXER_URL.rstrip("/")
        self._auth = base64.b64encode(
            f"{Config.WAZUH_USERNAME}:{Config.WAZUH_PASSWORD}".encode()
        ).decode()
        self._ctx = ssl.create_default_context()
        if not Config.VERIFY_SSL:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, path, body=None, timeout=20):
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Basic {self._auth}")
        req.add_header("Content-Type", "application/json")
        logger.debug("Indexer request: %s %s body=%s", method, path,
                     json.dumps(body)[:200] if body else "None")
        try:
            resp = urllib.request.urlopen(req, context=self._ctx, timeout=timeout)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            err = e.read().decode()
            logger.error("Indexer HTTP %d: %s", e.code, err[:300])
            raise

    # ---- 基础查询 ----

    def search(self, index, query_body):
        """执行搜索，返回完整 JSON 响应。"""
        path = f"/{urllib.parse.quote(index)}/_search"
        return self._request("POST", path, query_body)

    def cluster_health(self):
        return self._request("GET", "/_cluster/health")

    def list_indices(self, pattern="wazuh-*"):
        return self._request("GET", f"/_cat/indices/{pattern}?format=json")

    # ---- 高层封装 ----

    def count(self, index, query_dsl):
        path = f"/{urllib.parse.quote(index)}/_count"
        body = {"query": query_dsl.get("query", query_dsl)}
        r = self._request("POST", path, body)
        return r.get("count", 0)

    def range_query(self, start_iso, end_iso, extra_query=None):
        """构建时间范围查询。"""
        q = {
            "range": {
                "timestamp": {
                    "gte": start_iso,
                    "lte": end_iso,
                }
            }
        }
        if extra_query:
            return {"bool": {"must": [q, extra_query]}}
        return q

    @staticmethod
    def time_range(hours=None, start=None, end=None):
        """返回 (start_iso, end_iso)，使用 +0800 时区。"""
        tz = timezone(timedelta(hours=8))
        now = datetime.now(tz)
        if end is None:
            end = now
        else:
            end = datetime.fromisoformat(end)
        if start:
            start = datetime.fromisoformat(start)
        elif hours:
            start = end - timedelta(hours=hours)
        else:
            start = end - timedelta(hours=Config.DEFAULT_LOOKBACK_HOURS)
        return start.isoformat(), end.isoformat()
