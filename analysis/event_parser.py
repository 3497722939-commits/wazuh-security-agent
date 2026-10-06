"""
事件解析：从 Wazuh 告警 JSON 中提取结构化字段。
"""
import logging

logger = logging.getLogger(__name__)


def parse_alert(alert):
    """从一条 Wazuh 告警中提取关键字段。"""
    src = alert if isinstance(alert, dict) else {}
    agent = src.get("agent", {}) or {}
    rule = src.get("rule", {}) or {}
    data = src.get("data", {}) or {}
    manager = src.get("manager", {}) or {}

    return {
        "timestamp": src.get("timestamp", ""),
        "agent_name": agent.get("name", "unknown"),
        "agent_ip": agent.get("ip", ""),
        "manager": manager.get("name", ""),
        "rule_id": rule.get("id", ""),
        "rule_description": rule.get("description", ""),
        "rule_level": rule.get("level", 0),
        "rule_groups": rule.get("groups", []),
        "location": src.get("location", ""),
        "srcip": data.get("srcip", ""),
        "srcuser": data.get("srcuser", ""),
        "dstuser": data.get("dstuser", ""),
        "srcport": data.get("srcport", ""),
        "raw_data": data,
    }


def parse_alerts(alerts):
    """批量解析。"""
    return [parse_alert(a) for a in alerts]


def is_ssh_failure(parsed):
    return "sshd" in (parsed["rule_groups"] or []) and \
           "authentication_failure" in (parsed["rule_groups"] or [])


def is_ssh_success(parsed):
    return "sshd" in (parsed["rule_groups"] or []) and \
           "authentication_success" in (parsed["rule_groups"] or [])


def is_sudo_success(parsed):
    return "authentication_success" in (parsed["rule_groups"] or []) and \
           "sudo" in (parsed["rule_description"] or "").lower()
