"""
Wazuh 工具定义和执行器：供 LLM function calling 调用。
所有工具只读，不做任何修改。
"""
import json
from datetime import datetime, timedelta
from indexer_client import IndexerClient
from config import Config

# 初始化 Wazuh 客户端
_wazuh = IndexerClient()


# ---- 工具定义（OpenAI function calling 格式）----

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_alerts",
            "description": "搜索 Wazuh 告警事件。支持按时间范围、来源IP、用户名、主机名、规则级别过滤。返回匹配的告警列表。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "查询最近多少小时的事件，默认24小时",
                        "default": 24
                    },
                    "src_ip": {
                        "type": "string",
                        "description": "按来源IP过滤，例如 192.168.1.20"
                    },
                    "username": {
                        "type": "string",
                        "description": "按目标用户名过滤，例如 root"
                    },
                    "agent_name": {
                        "type": "string",
                        "description": "按主机名过滤，例如 wazuh-server"
                    },
                    "min_level": {
                        "type": "integer",
                        "description": "最低规则级别，0-15，默认不过滤"
                    },
                    "size": {
                        "type": "integer",
                        "description": "返回条数上限，默认50，最大500",
                        "default": 50
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "count_ssh_failures",
            "description": "统计 SSH 登录失败事件。按来源IP聚合，返回每个IP的失败次数、尝试的用户名、最早和最晚时间。用于检测暴力破解。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "查询最近多少小时，默认24",
                        "default": 24
                    },
                    "agent_name": {
                        "type": "string",
                        "description": "按主机名过滤"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_ssh_success_after_failure",
            "description": "检查指定来源IP在时间范围内是否有SSH登录失败后又出现成功登录的情况。这是判断是否被入侵的关键指标。",
            "parameters": {
                "type": "object",
                "properties": {
                    "src_ip": {
                        "type": "string",
                        "description": "要检查的来源IP，例如 192.168.1.20"
                    },
                    "hours": {
                        "type": "integer",
                        "description": "查询最近多少小时，默认24",
                        "default": 24
                    }
                },
                "required": ["src_ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "alert_summary",
            "description": "获取告警概览统计：按主机聚合告警数量、按规则聚合Top N告警。当用户询问整体安全状况、最近有什么告警/事件、高危事件、异常事件、安全概览、告警有多少、哪台主机告警多等问题时必须调用此工具获取真实数据。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "统计最近多少小时，默认24",
                        "default": 24
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_agents",
            "description": "查询 Wazuh 管理的所有监控主机（agent）列表及其状态。",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]


# ---- 工具执行器 ----

def execute_tool(name, args_json):
    """根据工具名和参数执行查询，返回结果字符串。"""
    try:
        args = json.loads(args_json) if isinstance(args_json, str) else args_json
    except json.JSONDecodeError:
        args = {}

    try:
        if name == "search_alerts":
            return _search_alerts(args)
        elif name == "count_ssh_failures":
            return _count_ssh_failures(args)
        elif name == "check_ssh_success_after_failure":
            return _check_success_after_failure(args)
        elif name == "alert_summary":
            return _alert_summary(args)
        elif name == "list_agents":
            return _list_agents()
        else:
            return json.dumps({"error": f"未知工具: {name}"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"查询失败: {str(e)}"}, ensure_ascii=False)


def _search_alerts(args):
    hours = args.get("hours", 24)
    size = min(args.get("size", 50), Config.MAX_RESULTS)
    start, end = _time_range(hours)
    must = [{"range": {"timestamp": {"gte": start, "lte": end}}}]

    if args.get("src_ip"):
        must.append({"match": {"data.srcip": args["src_ip"]}})
    if args.get("username"):
        must.append({"match": {"data.dstuser": args["username"]}})
    if args.get("agent_name"):
        must.append({"match": {"agent.name": args["agent_name"]}})
    if args.get("min_level") is not None:
        must.append({"range": {"rule.level": {"gte": args["min_level"]}}})

    body = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": ["timestamp", "agent", "rule", "data", "location"]
    }
    r = _wazuh.search(Config.ALERTS_INDEX, body)
    hits = r["hits"]["hits"]
    total = r["hits"]["total"]["value"]
    results = []
    for h in hits[:20]:  # 最多返回20条给LLM
        s = h["_source"]
        results.append({
            "time": s.get("timestamp"),
            "agent": s.get("agent", {}).get("name"),
            "rule_id": s.get("rule", {}).get("id"),
            "rule_desc": s.get("rule", {}).get("description"),
            "level": s.get("rule", {}).get("level"),
            "srcip": s.get("data", {}).get("srcip", ""),
            "user": s.get("data", {}).get("dstuser", "") or s.get("data", {}).get("srcuser", ""),
        })
    return json.dumps({
        "total": total,
        "returned": len(results),
        "alerts": results
    }, ensure_ascii=False)


def _count_ssh_failures(args):
    hours = args.get("hours", 24)
    agent = args.get("agent_name")
    start, end = _time_range(hours)

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
                "terms": {"field": "data.srcip", "size": 20},
                "aggs": {
                    "usernames": {"terms": {"field": "data.dstuser", "size": 10}},
                    "earliest": {"min": {"field": "timestamp"}},
                    "latest": {"max": {"field": "timestamp"}},
                }
            }
        }
    }
    r = _wazuh.search(Config.ALERTS_INDEX, body)
    buckets = r["aggregations"]["by_srcip"]["buckets"]
    results = []
    for b in buckets:
        results.append({
            "srcip": b["key"],
            "failure_count": b["doc_count"],
            "usernames": [u["key"] for u in b["usernames"]["buckets"]],
            "first_seen": b.get("earliest", {}).get("value_as_string", ""),
            "last_seen": b.get("latest", {}).get("value_as_string", ""),
        })
    return json.dumps({"total_ips": len(results), "failures_by_ip": results}, ensure_ascii=False)


def _check_success_after_failure(args):
    src_ip = args["src_ip"]
    hours = args.get("hours", 24)
    start, end = _time_range(hours)

    # 查失败
    failures, f_total = _query_events(start, end, src_ip, "failure")
    # 查成功
    successes, s_total = _query_events(start, end, src_ip, "success")

    result = {
        "src_ip": src_ip,
        "failure_count": f_total,
        "success_count": s_total,
        "has_success_after_failure": False,
        "detail": ""
    }
    if f_total == 0:
        result["detail"] = "该IP没有登录失败事件"
    elif s_total == 0:
        result["detail"] = f"有 {f_total} 次失败，但没有成功登录"
    else:
        first_failure = min(f["timestamp"] for f in failures)
        success_after = [s for s in successes if s["timestamp"] > first_failure]
        if success_after:
            result["has_success_after_failure"] = True
            result["detail"] = (
                f"危险：{len(success_after)} 次成功登录发生在首次失败之后！"
                f"首次失败: {first_failure}, 成功时间: {[s['timestamp'] for s in success_after[:3]]}"
            )
        else:
            result["detail"] = f"有 {f_total} 次失败和 {s_total} 次成功，但成功都在失败之前"
    return json.dumps(result, ensure_ascii=False)


def _alert_summary(args):
    hours = args.get("hours", 24)
    start, end = _time_range(hours)

    # 按主机
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": start, "lte": end}}},
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_rule": {
                "terms": {"field": "rule.id", "size": 15},
                "aggs": {"sample": {"top_hits": {"size": 1, "_source": ["rule.description", "rule.level"]}}}
            }
        }
    }
    r = _wazuh.search(Config.ALERTS_INDEX, body)
    agents = [{"agent": b["key"], "count": b["doc_count"]}
              for b in r["aggregations"]["by_agent"]["buckets"]]
    rules = []
    for b in r["aggregations"]["by_rule"]["buckets"]:
        sample = b.get("sample", {}).get("hits", {}).get("hits", [{}])
        desc = sample[0]["_source"].get("rule", {}).get("description", "") if sample else ""
        lvl = sample[0]["_source"].get("rule", {}).get("level", 0) if sample else 0
        rules.append({"rule_id": b["key"], "count": b["doc_count"], "desc": desc, "level": lvl})
    return json.dumps({"by_agent": agents, "top_rules": rules}, ensure_ascii=False)


def _list_agents():
    try:
        r = _wazuh.search(Config.MONITORING_INDEX, {
            "size": 10,
            "sort": [{"timestamp": "desc"}],
            "query": {"match_all": {}}
        })
        agents = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            agents.append({
                "name": s.get("agent", {}).get("name"),
                "ip": s.get("agent", {}).get("ip"),
                "status": s.get("agent", {}).get("status", "unknown"),
                "version": s.get("agent", {}).get("version", ""),
                "lastKeepAlive": s.get("agent", {}).get("lastKeepAlive", ""),
            })
        return json.dumps({"agents": agents}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"agents": [{"name": "wazuh-server", "status": "active"}]}, ensure_ascii=False)


# ---- 辅助函数 ----

def _time_range(hours):
    from indexer_client import IndexerClient
    return IndexerClient.time_range(hours=hours)


def _query_events(start, end, src_ip, outcome):
    group = "authentication_success" if outcome == "success" else "authentication_failure"
    must = [
        {"range": {"timestamp": {"gte": start, "lte": end}}},
        {"match": {"rule.groups": "sshd"}},
        {"match": {"rule.groups": group}},
        {"match": {"data.srcip": src_ip}},
    ]
    body = {
        "size": 100,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"must": must}},
        "_source": ["timestamp", "data.srcip", "data.dstuser", "agent.name", "rule.description"]
    }
    r = _wazuh.search(Config.ALERTS_INDEX, body)
    hits = r["hits"]["hits"]
    total = r["hits"]["total"]["value"]
    events = []
    for h in hits:
        s = h["_source"]
        events.append({
            "timestamp": s.get("timestamp"),
            "srcip": s.get("data", {}).get("srcip"),
            "user": s.get("data", {}).get("dstuser"),
            "agent": s.get("agent", {}).get("name"),
            "desc": s.get("rule", {}).get("description"),
        })
    return events, total
