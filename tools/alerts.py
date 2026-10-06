"""
告警查询工具：搜索 Wazuh 告警事件。
"""
import logging
from indexer_client import IndexerClient
from config import Config

logger = logging.getLogger(__name__)


class AlertsTool:
    def __init__(self, client=None):
        self.client = client or IndexerClient()
        self.index = Config.ALERTS_INDEX

    def search_alerts(self, start_iso=None, end_iso=None, hours=None,
                      agent=None, rule_id=None, rule_group=None,
                      min_level=None, size=None, sort_desc=True):
        """搜索告警事件。"""
        size = size or Config.MAX_RESULTS
        size = min(size, Config.MAX_RESULTS)
        start, end = self.client.time_range(hours=hours, start=start_iso, end=end_iso)

        must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]
        if agent:
            must.append({"match": {"agent.name": agent}})
        if rule_id:
            must.append({"match": {"rule.id": str(rule_id)}})
        if rule_group:
            must.append({"match": {"rule.groups": rule_group}})
        if min_level is not None:
            must.append({"range": {"rule.level": {"gte": min_level}}})

        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc" if sort_desc else "asc"}}],
            "query": {"bool": {"must": must}},
        }
        logger.info("search_alerts: %d alerts query, time=%s ~ %s", size, start, end)
        r = self.client.search(self.index, body)
        hits = r["hits"]["hits"]
        total = r["hits"]["total"]["value"]
        return [h["_source"] for h in hits], total

    def alerts_by_rule(self, start_iso=None, end_iso=None, hours=None, size=20):
        """按规则聚合告警数量。"""
        start, end = self.client.time_range(hours=hours, start=start_iso, end=end_iso)
        body = {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": start, "lte": end}}},
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.id", "size": size},
                    "aggs": {
                        "desc": {"terms": {"field": "rule.description.keyword", "size": 1}},
                        "level": {"terms": {"field": "rule.level", "size": 1}},
                        "sample": {"top_hits": {"size": 1, "_source": ["rule.description"]}},
                    },
                }
            },
        }
        r = self.client.search(self.index, body)
        buckets = r["aggregations"]["by_rule"]["buckets"]
        result = []
        for b in buckets:
            desc = b["desc"]["buckets"][0]["key"] if b["desc"]["buckets"] else ""
            if not desc:
                # fallback: 从 top_hits 取描述
                try:
                    desc = b["sample"]["hits"]["hits"][0]["_source"]["rule"]["description"]
                except (KeyError, IndexError):
                    desc = ""
            lvl = b["level"]["buckets"][0]["key"] if b["level"]["buckets"] else 0
            result.append({
                "rule_id": b["key"],
                "count": b["doc_count"],
                "description": desc,
                "level": lvl,
            })
        return result

    def alerts_by_agent(self, start_iso=None, end_iso=None, hours=None):
        """按主机聚合告警数量。"""
        start, end = self.client.time_range(hours=hours, start=start_iso, end=end_iso)
        body = {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": start, "lte": end}}},
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 50},
                }
            },
        }
        r = self.client.search(self.index, body)
        return [{"agent": b["key"], "count": b["doc_count"]}
                for b in r["aggregations"]["by_agent"]["buckets"]]
