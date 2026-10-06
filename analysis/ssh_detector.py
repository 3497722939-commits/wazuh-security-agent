"""
SSH 暴力破解检测：分析登录失败事件，判断风险等级。
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from analysis.event_parser import parse_alert, is_ssh_failure, is_ssh_success

logger = logging.getLogger(__name__)


class SSHBruteForceDetector:
    # 阈值
    FAILURE_THRESHOLD = 5           # 短时间内失败次数阈值
    FAILURE_WINDOW_MINUTES = 5      # 时间窗口
    RARE_USERS = {"root", "admin", "oracle", "postgres", "mysql"}

    def analyze(self, alerts):
        """
        分析 SSH 登录事件，返回检测结果。
        alerts: 原始 Wazuh 告警列表
        """
        parsed = [parse_alert(a) for a in alerts]
        failures = [p for p in parsed if is_ssh_failure(p)]
        successes = [p for p in parsed if is_ssh_success(p)]

        if not failures:
            return {
                "detected": False,
                "reason": "未检测到 SSH 登录失败事件",
                "failure_count": 0,
                "success_count": len(successes),
            }

        # 按 IP 分组
        by_ip = defaultdict(list)
        for f in failures:
            ip = f["srcip"] or "unknown"
            by_ip[ip].append(f)

        threats = []
        for ip, events in by_ip.items():
            if len(events) < 2 and ip == "unknown":
                continue
            analysis = self._analyze_ip(ip, events, successes)
            if analysis["risk_level"] != "无":
                threats.append(analysis)

        threats.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}.get(x["risk_level"], 3))
        return {
            "detected": len(threats) > 0,
            "failure_count": len(failures),
            "success_count": len(successes),
            "threats": threats,
        }

    def _analyze_ip(self, ip, failure_events, all_successes):
        users_tried = set()
        for f in failure_events:
            if f["dstuser"]:
                users_tried.add(f["dstuser"])

        times = sorted(datetime.fromisoformat(f["timestamp"]) for f in failure_events)
        duration_min = (times[-1] - times[0]).total_seconds() / 60 if len(times) > 1 else 0

        # 成功登录（同 IP）
        ip_successes = [s for s in all_successes if s["srcip"] == ip]
        success_after_fail = any(
            datetime.fromisoformat(s["timestamp"]) > times[0] for s in ip_successes
        )

        # 风险评估
        risk = "低"
        reasons = []
        host_targets = set(f["agent_name"] for f in failure_events)

        if len(failure_events) >= self.FAILURE_THRESHOLD and duration_min <= self.FAILURE_WINDOW_MINUTES:
            risk = "高"
            reasons.append(
                f"同一 IP 在 {duration_min:.0f} 分钟内产生 {len(failure_events)} 次登录失败"
            )
        elif len(failure_events) >= 3:
            risk = "中"
            reasons.append(
                f"同一 IP 累计 {len(failure_events)} 次登录失败"
            )

        if users_tried & self.RARE_USERS:
            risk = "高" if risk == "低" else risk
            reasons.append(f"尝试登录高权限账号: {', '.join(users_tried & self.RARE_USERS)}")

        if len(users_tried) >= 3:
            reasons.append(f"尝试了多个用户名: {', '.join(list(users_tried)[:5])}")

        if success_after_fail:
            risk = "高"
            reasons.append(f"失败后出现成功登录（{len(ip_successes)} 次），可能已被入侵")

        if len(host_targets) > 1:
            reasons.append(f"该 IP 访问了 {len(host_targets)} 台主机: {', '.join(host_targets)}")

        confidence = self._confidence(len(failure_events), duration_min, success_after_fail)

        return {
            "srcip": ip,
            "risk_level": risk,
            "confidence": confidence,
            "failure_count": len(failure_events),
            "users_tried": sorted(users_tried),
            "time_range": f"{times[0].isoformat()} ~ {times[-1].isoformat()}",
            "duration_minutes": round(duration_min, 1),
            "target_hosts": sorted(host_targets),
            "has_success_after_failure": success_after_fail,
            "success_logins": len(ip_successes),
            "reasons": reasons,
        }

    def _confidence(self, failure_count, duration_min, success_after):
        score = 0.5
        if failure_count >= 5:
            score += 0.2
        if duration_min <= 5 and failure_count >= 5:
            score += 0.15
        if success_after:
            score += 0.2
        return min(score, 0.98)
