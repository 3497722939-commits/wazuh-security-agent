"""
报告格式化器：将分析结果转为结构化的中文报告。
"""
import logging

logger = logging.getLogger(__name__)


class ReportFormatter:
    @staticmethod
    def format_ssh_report(result, query_context):
        """格式化 SSH 分析报告。"""
        lines = []
        lines.append("=" * 60)
        lines.append("【安全分析报告】SSH 登录事件")
        lines.append("=" * 60)

        # 查询上下文
        lines.append(f"时间范围: {query_context.get('start')} ~ {query_context.get('end')}")
        lines.append(f"查询主机: {query_context.get('agent', '全部')}")
        lines.append(f"查询 IP: {query_context.get('src_ip', '全部')}")
        lines.append(f"失败事件总数: {result.get('failure_count', 0)}")
        lines.append(f"成功事件总数: {result.get('success_count', 0)}")
        lines.append("")

        if not result.get("detected"):
            lines.append("结论: 未发现可疑 SSH 登录活动")
            lines.append(f"说明: {result.get('reason', '未检测到登录失败事件')}")
            lines.append("")
            lines.append("建议: 无需进一步操作。继续保持监控。")
            return "\n".join(lines)

        threats = result.get("threats", [])
        high_count = sum(1 for t in threats if t["risk_level"] == "高")
        mid_count = sum(1 for t in threats if t["risk_level"] == "中")

        lines.append(f"结论: 发现 {len(threats)} 个可疑来源 IP"
                     f"（高风险 {high_count}，中风险 {mid_count}）")
        lines.append("")

        for i, t in enumerate(threats, 1):
            lines.append(f"--- 威胁 {i}: {t['srcip']} ---")
            lines.append(f"风险等级: {t['risk_level']}")
            lines.append(f"置信度: {t['confidence']:.2f}")
            lines.append(f"失败次数: {t['failure_count']}")
            lines.append(f"时间范围: {t['time_range']}")
            lines.append(f"持续时间: {t['duration_minutes']} 分钟")
            if t["users_tried"]:
                lines.append(f"尝试用户名: {', '.join(t['users_tried'])}")
            if t["target_hosts"]:
                lines.append(f"涉及主机: {', '.join(t['target_hosts'])}")
            if t["has_success_after_failure"]:
                lines.append(f"⚠ 失败后出现成功登录: {t['success_logins']} 次")
            lines.append("")
            lines.append("关键证据:")
            for r in t["reasons"]:
                lines.append(f"  - {r}")
            lines.append("")

        lines.append("建议:")
        suggestions = ReportFormatter._suggestions(threats)
        for j, s in enumerate(suggestions, 1):
            lines.append(f"  {j}. {s}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    @staticmethod
    def _suggestions(threats):
        s = []
        high = [t for t in threats if t["risk_level"] == "高"]
        if high:
            s.append("高风险 IP 需立即人工介入，检查是否已被入侵")
            s.append("核查失败后成功登录的会话，确认是否为合法用户")
        if any(t["has_success_after_failure"] for t in threats):
            s.append("检查成功登录后的操作历史（sudo、进程、文件变更）")
        s.append("在防火墙或安全组层面考虑临时封禁恶意 IP")
        s.append("检查该 IP 是否在其他主机上也产生了告警")
        s.append("确认是否为已知运维 IP 或扫描器，避免误报")
        return s

    @staticmethod
    def format_summary(alerts_by_rule, alerts_by_agent, query_context):
        """格式化概览报告。"""
        lines = []
        lines.append("=" * 60)
        lines.append("【安全概览】")
        lines.append("=" * 60)
        lines.append(f"时间范围: {query_context.get('start')} ~ {query_context.get('end')}")
        lines.append("")
        lines.append("按主机统计告警:")
        for a in alerts_by_agent[:10]:
            lines.append(f"  {a['agent']}: {a['count']} 条")
        lines.append("")
        lines.append("按规则统计 Top 10:")
        for r in alerts_by_rule[:10]:
            lines.append(f"  [{r['rule_id']}] {r['description'][:50]} "
                         f"(级别{r['level']}, {r['count']}条)")
        lines.append("=" * 60)
        return "\n".join(lines)
