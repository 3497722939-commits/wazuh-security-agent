"""
蓝队 Agent 主入口：自然语言对话，自动查询 Wazuh 并分析。
第一阶段 MVP：SSH 登录事件分析。
"""
import re
import sys
import logging
from datetime import datetime, timedelta

from config import Config
from indexer_client import IndexerClient
from tools.alerts import AlertsTool
from tools.login_events import LoginEventsTool
from analysis.ssh_detector import SSHBruteForceDetector
from report.formatter import ReportFormatter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("blue-team-agent")

# 抑制 SSL 警告
import warnings
warnings.filterwarnings("ignore", message=".*SSL.*")
import logging as _logging
_logging.getLogger("urllib3").setLevel(_logging.ERROR)


class BlueTeamAgent:
    def __init__(self):
        Config.validate()
        self.client = IndexerClient()
        self.alerts_tool = AlertsTool(self.client)
        self.login_tool = LoginEventsTool(self.client)
        self.detector = SSHBruteForceDetector()
        self.formatter = ReportFormatter()

    def ask(self, question):
        """处理用户自然语言提问。"""
        q = question.strip().lower()
        logger.info("用户提问: %s", question)

        # 意图识别
        if any(k in q for k in ["你好", "hi", "hello", "帮助", "help", "你是谁"]):
            return self._help()

        if any(k in q for k in ["概览", "概况", "最近告警", "整体", "overview", "dashboard"]):
            return self._overview(question)

        if any(k in q for k in ["ssh", "登录", "login", "暴力", "brute", "失败登录", "异常登录"]):
            return self._analyze_ssh(question)

        if "ip" in q or any(c.isdigit() and "." in q for c in q):
            # 提取 IP
            ip = self._extract_ip(question)
            if ip:
                return self._analyze_ip(ip, question)

        # 默认：尝试 SSH 分析
        return self._analyze_ssh(question)

    def _help(self):
        return (
            "蓝队安全分析 Agent\n"
            "我可以查询 Wazuh 并分析安全事件。\n\n"
            "你可以这样问我：\n"
            "  - 最近有没有高危安全事件？\n"
            "  - 检查一下最近的 SSH 登录失败\n"
            "  - 昨天有没有异常登录？\n"
            "  - 192.168.1.20 最近触发了什么告警？\n"
            "  - 有没有失败登录后又成功登录的情况？\n"
            "  - 最近告警概览\n"
        )

    def _extract_time_range(self, question):
        """从问题中提取时间范围。"""
        q = question.lower()
        hours = Config.DEFAULT_LOOKBACK_HOURS
        if "昨天" in q:
            hours = 24
        elif "今天" in q:
            hours = 12
        elif "本周" in q or "这周" in q:
            hours = 24 * 7
        elif "小时" in q:
            m = re.search(r"(\d+)\s*小时", q)
            if m:
                hours = int(m.group(1))
        elif "分钟" in q:
            m = re.search(r"(\d+)\s*分钟", q)
            if m:
                hours = max(int(m.group(1)) / 60, 0.1)
        hours = min(hours, Config.MAX_LOOKBACK_HOURS)
        return hours

    def _extract_ip(self, question):
        m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", question)
        return m.group(1) if m else None

    def _extract_username(self, question):
        for kw in ["用户", "user", "账号", "登录"]:
            m = re.search(rf"{kw}[:\s]+([a-zA-Z_][a-zA-Z0-9_]*)", question, re.I)
            if m:
                return m.group(1)
        return None

    def _extract_agent(self, question):
        for kw in ["主机", "agent", "服务器", "machine"]:
            m = re.search(rf"{kw}[:\s]+([a-zA-Z0-9_-]+)", question, re.I)
            if m:
                return m.group(1)
        return None

    def _analyze_ssh(self, question):
        hours = self._extract_time_range(question)
        src_ip = self._extract_ip(question)
        username = self._extract_username(question)
        agent = self._extract_agent(question)

        start, end = self.client.time_range(hours=hours)
        logger.info("SSH分析: hours=%d ip=%s user=%s agent=%s", hours, src_ip, username, agent)

        # 查询所有 SSH 登录事件（成功+失败）
        try:
            events, total = self.login_tool.search_login_events(
                start_iso=start, end_iso=end,
                src_ip=src_ip, username=username, agent=agent,
                size=Config.MAX_RESULTS
            )
        except Exception as e:
            logger.error("查询失败: %s", e)
            return f"查询 Wazuh 时出错: {e}\n请检查网络连接和凭据配置。"

        if not events:
            return (f"在指定时间范围内（{start[:19]} ~ {end[:19]}）"
                    f"没有查询到相关的 SSH 登录事件。\n"
                    f"查询条件: IP={src_ip or '全部'}, 用户={username or '全部'}, 主机={agent or '全部'}")

        # 分析
        result = self.detector.analyze(events)
        result["failure_count"] = result.get("failure_count", 0)
        result["success_count"] = result.get("success_count", 0)

        ctx = {"start": start[:19], "end": end[:19], "src_ip": src_ip or "全部",
               "agent": agent or "全部"}
        return self.formatter.format_ssh_report(result, ctx)

    def _analyze_ip(self, ip, question):
        """按 IP 分析。"""
        hours = self._extract_time_range(question)
        start, end = self.client.time_range(hours=hours)
        logger.info("IP分析: %s, hours=%d", ip, hours)

        try:
            events, total = self.login_tool.search_login_events(
                start_iso=start, end_iso=end, src_ip=ip, size=Config.MAX_RESULTS
            )
        except Exception as e:
            return f"查询出错: {e}"

        if not events:
            # 查所有告警
            events, total = self.alerts_tool.search_alerts(
                start_iso=start, end_iso=end, size=50
            )
            events = [e for e in events if self._alert_mentions_ip(e, ip)]
            if not events:
                return f"IP {ip} 在指定时间范围内没有查询到相关事件。"

        result = self.detector.analyze(events)
        ctx = {"start": start[:19], "end": end[:19], "src_ip": ip, "agent": "全部"}
        return self.formatter.format_ssh_report(result, ctx)

    def _alert_mentions_ip(self, alert, ip):
        data_str = json.dumps(alert.get("data", {}))
        return ip in data_str

    def _overview(self, question):
        hours = self._extract_time_range(question)
        start, end = self.client.time_range(hours=hours)
        try:
            by_rule = self.alerts_tool.alerts_by_rule(start_iso=start, end_iso=end)
            by_agent = self.alerts_tool.alerts_by_agent(start_iso=start, end_iso=end)
        except Exception as e:
            return f"查询出错: {e}"
        ctx = {"start": start[:19], "end": end[:19]}
        return self.formatter.format_summary(by_rule, by_agent, ctx)


def main():
    import json
    agent = BlueTeamAgent()

    # 支持命令行直接提问
    if len(sys.argv) > 1:
        q = " ".join(sys.argv[1:])
        print(agent.ask(q))
        return

    # 交互式对话
    print("蓝队安全分析 Agent（输入 'quit' 退出，'help' 查看帮助）")
    print("=" * 50)
    while True:
        try:
            q = input("\n你> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q:
            continue
        if q.lower() in ("quit", "exit", "退出"):
            break
        print()
        print(agent.ask(q))


if __name__ == "__main__":
    main()
