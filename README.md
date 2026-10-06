# 蓝队安全分析 Agent

直接用自然语言对话查询 Wazuh 安全事件，自动分析并给出结论和建议。

## 快速开始

1. 设置环境变量（或创建 `.env` 文件）：

```powershell
$env:WAZUH_INDEXER_URL = "https://192.168.174.137:9200"
$env:WAZUH_USERNAME = "admin"
$env:WAZUH_PASSWORD = "你的indexer密码"
```

2. 交互式对话：
```powershell
python main.py
```

3. 单次提问：
```powershell
python main.py "检查最近的 SSH 登录失败"
```

## 支持的提问

- "最近告警概览"
- "检查一下最近的 SSH 登录失败"
- "昨天有没有异常登录？"
- "192.168.1.20 最近触发了什么告警？"
- "有没有失败登录后又成功登录的情况？"
- "帮助"

## 项目结构

```
blue-team-agent/
├── main.py              # 对话入口 + 意图识别
├── config.py            # 环境变量配置
├── indexer_client.py    # OpenSearch 搜索客户端
├── tools/
│   ├── alerts.py        # 告警查询工具
│   └── login_events.py   # 登录事件查询
├── analysis/
│   ├── event_parser.py   # 事件字段解析
│   └── ssh_detector.py   # SSH 暴力破解检测
├── report/
│   └── formatter.py      # 中文报告格式化
└── tests/
```

## 安全边界（第一阶段）

- ✅ 只读：查询告警、统计事件、分析风险
- ❌ 不自动处置：不封禁 IP、不禁用用户、不改配置
- ✅ 凭据不硬编码，从环境变量读取
- ✅ 查询有数量和时间范围限制
