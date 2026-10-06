"""
登录事件查询工具：SSH 登录成功/失败、按 IP/用户/主机筛选。
"""
import logging
from indexer_client import IndexerClient
from config import Config

logger = logging.getLogger(__name__)


class LoginEventsTool:
    # SSH 登录相关规则组
    SSH_GROUPS = ["sshd", "authentication_success", "authentication_failure"]

    def __init__(self, client=None):
        self.client = client or IndexerClient()
        self.index = Config.ALERTS_INDEX

    def _build_query(self, start_iso, end_iso, src_ip=None, username=None,
                     agent=None, outcome=None):
        """构建登录事件查询。outcome: success/failure/None."""
        must = [
            {"range": {"timestamp": {"gte": start_iso, "lte": end_iso}}},
            {"terms": {"rule.groups": ["sshd"]}},
        ]
        if src_ip:
            must.append({"match": {"data.srcip": src_ip}})
        if username:
            must.append({"match": {"data.dstuser": username}})
        if agent:
            must.append({"match": {"agent.name": agent}})
        if outcome == "success":
            must.append({"match": {"rule.groups": "authentication_success"}})
        elif outcome == "failure":
            must.append({"match": {"rule.groups": "authentication_failure"}})
        return {"bool": {"must": must}}

    def search_login_events(self, start_iso=None, end_iso=None, hours=None,
                            src_ip=None, username=None, agent=None,
                            outcome=None, size=None):
        """查询登录事件。"""
        size = min(size or Config.MAX_RESULTS, Config.MAX_RESULTS)
        start, end = self.client.time_range(hours=hours, start=start_iso, end=end_iso)
        query = self._build_query(start, end, src_ip, username, agent, outcome)
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": query,
        }
        logger.info("login_events: src_ip=%s user=%s outcome=%s time=%s~%s",
                    src_ip, username, outcome, start, end)
        r = self.client.search(self.index, body)
        hits = r["hits"]["hits"]
        total = r["hits"]["total"]["value"]
        return [h["_source"] for h in hits], total

    def count_failures_by_ip(self, start_iso=None, end_iso=None, hours=None,
                             agent=None):
        """统计各来源 IP 的登录失败次数。"""
        start, end = self.client.time_range(hours=hours, start=start_iso, end=end_iso)
        must = [
            {"range": {"timestamp": {"gte": start, "lte": end}}},
            {"match": {"rule.groups": "authentication_failure"}},
            {"match": {"rule.groups": "sshd"}},
        ]
        if agent:
            must.append({"match": {"agent.name": agent}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "by_srcip": {
                    "terms": {"field": "data.srcip", "size": 50},
                    "aggs": {
                        "usernames": {"terms": {"field": "data.dstuser", "size": 10}},
                        "earliest": {"min": {"field": "timestamp"}},
                        "latest": {"max": {"field": "timestamp"}},
                    },
                }
            },
        }
        r = self.client.search(self.index, body)
        result = []
        for b in r["aggregations"]["by_srcip"]["buckets"]:
            result.append({
                "srcip": b["key"],
                "failure_count": b["doc_count"],
                "usernames": [u["key"] for u in b["usernames"]["buckets"]],
                "first_seen": b["earliest"]["value_as_string"] if b.get("earliest") else None,
                "last_seen": b["latest"]["value_as_string"] if b.get("latest") else None,
            })
        return result

    def check_success_after_failure(self, start_iso, end_iso, src_ip, agent=None):
        """检查指定 IP 在时间范围内是否有失败后成功登录。"""
        # 先查失败时间
        failures, f_total = self.search_login_events(
            start_iso=start_iso, end_iso=end_iso, src_ip=src_ip,
            agent=agent, outcome="failure", size=100
        )
        if not failures:
            return {"has_failure": False, "has_success_after": False, "failures": [], "successes": []}

        # 查同 IP 成功登录
        successes, s_total = self.search_login_events(
            start_iso=start_iso, end_iso=end_iso, src_ip=src_ip,
            agent=agent, outcome="success", size=100
        )
        # 判断是否有成功晚于首个失败
        first_failure_ts = min(f["timestamp"] for f in failures)
        success_after = [s for s in successes if s["timestamp"] >= first_failure_ts]
        return {
            "has_failure": True,
            "has_success_after": len(success_after) > 0,
            "first_failure_time": first_failure_ts,
            "failures": failures,
            "successes": successes,
            "success_after_count": len(success_after),
        }
