"""
蓝队 Agent 网页服务：FastAPI + 简单聊天界面。
LLM 自动判断调用 Wazuh 查询工具，返回分析报告。
"""
import os
import json
import logging
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from config import Config
from llm_client import LLMClient
from wazuh_tools import TOOLS, execute_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("blue-team-web")

app = FastAPI(title="蓝队安全分析 Agent")
llm = LLMClient()

SYSTEM_PROMPT = """你是一个安全蓝队分析助手，负责分析 Wazuh SIEM 中的安全事件。

你的工作方式（必须遵守）：
1. 用户的问题只要涉及查询安全事件、告警、登录、IP、主机、风险或安全状况，你必须先调用合适的工具获取真实数据，再基于数据回答。
2. 禁止不调用工具就直接回答、猜测或反问澄清。即使问题模糊（例如"最近有什么事件""安全吗""有没有异常"），也先调用 alert_summary 获取概览，再针对性补充查询。
3. 调用工具获取真实事件数据后，进行分析并给出结论、风险等级、证据和建议。

问题与工具的对应：
- 问整体安全状况/最近告警/高危事件/异常事件/概览/有多少告警 → 调用 alert_summary
- 问 SSH 登录失败/暴力破解/爆破 → 调用 count_ssh_failures
- 问某个 IP/主机/用户的具体告警 → 调用 search_alerts
- 问某个 IP 是否被攻破/失败后成功登录 → 调用 check_ssh_success_after_failure
- 问有哪些监控主机/agent 状态 → 调用 list_agents

分析要求：
- 每个结论必须基于工具返回的真实数据，不能编造
- 如果没有查到数据，明确说"未查询到相关事件"
- 报告格式：结论 → 风险等级 → 关键证据 → 建议
- 风险等级分：高（疑似入侵/暴力破解成功）、中（多次失败/异常行为）、低（少量失败/正常事件）
- 你只做查询和分析，不会执行任何修改操作（封禁IP、改配置等）

当前监控环境：
- Wazuh 服务器：wazuh-server（Ubuntu 虚拟机，192.168.174.137）
- 监控主机：wazuh-server 自己 + MACHENIKE-PC（Windows 物理机）
- 时间：中国时区（UTC+8）
"""


class ChatRequest(BaseModel):
    message: str
    history: list = []  # [{"role": "user"/"assistant", "content": "..."}]


@app.post("/api/chat")
def chat(req: ChatRequest):
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(req.history[-10:])  # 保留最近10轮
    messages.append({"role": "user", "content": req.message})

    # function calling 循环
    max_rounds = 5
    tools_used = []
    for round_i in range(max_rounds):
        resp = llm.chat(messages, tools=TOOLS)
        msg = resp.choices[0].message
        logger.info("Round %d: finish_reason=%s, has_tool_calls=%s",
                     round_i, resp.choices[0].finish_reason, bool(msg.tool_calls))

        if not msg.tool_calls:
            # LLM 直接给出最终回答
            return {"reply": msg.content or "（无回复）", "tools_used": tools_used}

        # 有工具调用，执行后继续
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                }
                for tc in msg.tool_calls
            ]
        })

        for tc in msg.tool_calls:
            result = execute_tool(tc.function.name, tc.function.arguments)
            tools_used.append({"name": tc.function.name, "args": tc.function.arguments})
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result
            })
            logger.info("Tool %s(%s) -> %d chars", tc.function.name, tc.function.arguments[:50], len(result))

    # 超过轮数，直接再问一次不带 tools
    resp = llm.chat(messages)
    return {"reply": resp.choices[0].message.content or "分析超时", "tools_used": tools_used}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE


HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>蓝队安全分析 Agent</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #0f1419; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; }
.header { background: #1a1f2e; padding: 16px 24px; border-bottom: 1px solid #2a3040; }
.header h1 { font-size: 18px; color: #4fc3f7; }
.header p { font-size: 12px; color: #666; margin-top: 4px; }
.chat { flex: 1; overflow-y: auto; padding: 24px; max-width: 900px; width: 100%; margin: 0 auto; }
.msg { margin-bottom: 16px; max-width: 85%; }
.msg.user { margin-left: auto; }
.bubble { padding: 12px 16px; border-radius: 12px; line-height: 1.6; white-space: pre-wrap; }
.msg.user .bubble { background: #1e6fb8; color: #fff; }
.msg.assistant .bubble { background: #1e2530; border: 1px solid #2a3040; }
.tools { font-size: 11px; color: #666; margin-top: 6px; padding: 0 8px; }
.input-area { background: #1a1f2e; padding: 16px 24px; border-top: 1px solid #2a3040; }
.input-row { display: flex; gap: 12px; max-width: 900px; margin: 0 auto; }
input { flex: 1; padding: 12px 16px; border-radius: 8px; border: 1px solid #2a3040; background: #0f1419; color: #e0e0e0; font-size: 14px; outline: none; }
input:focus { border-color: #4fc3f7; }
button { padding: 12px 24px; border-radius: 8px; border: none; background: #1e6fb8; color: #fff; cursor: pointer; font-size: 14px; }
button:hover { background: #1e88d8; }
button:disabled { opacity: 0.5; }
.loading { color: #666; font-style: italic; }
</style>
</head>
<body>
<div class="header">
  <h1>蓝队安全分析 Agent</h1>
  <p>连接 Wazuh SIEM · 自然语言查询安全事件 · 只读分析</p>
</div>
<div class="chat" id="chat">
  <div class="msg assistant"><div class="bubble">你好，我是蓝队安全分析助手。你可以问我：
- 最近有没有高危安全事件？
- 检查一下最近的 SSH 登录失败
- 昨天有没有异常登录？
- 192.168.1.20 最近触发了什么告警？
- 有没有失败登录后又成功登录的情况？</div></div>
</div>
<div class="input-area">
  <div class="input-row">
    <input id="input" placeholder="输入你的安全问题..." onkeydown="if(event.key==='Enter')send()">
    <button id="btn" onclick="send()">发送</button>
  </div>
</div>
<script>
const chat = document.getElementById('chat');
const input = document.getElementById('input');
const btn = document.getElementById('btn');
const history = [];

async function send() {
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  btn.disabled = true;

  // 用户消息
  addMsg('user', text);
  history.push({role: 'user', content: text});

  // 加载中
  const loading = addMsg('assistant', '分析中...');

  try {
    const r = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: text, history: history.slice(-10)})
    });
    const data = await r.json();
    loading.querySelector('.bubble').textContent = data.reply;
    if (data.tools_used && data.tools_used.length) {
      const t = document.createElement('div');
      t.className = 'tools';
      t.textContent = '🔧 调用工具: ' + data.tools_used.map(x => x.name).join(', ');
      loading.appendChild(t);
    }
    history.push({role: 'assistant', content: data.reply});
  } catch (e) {
    loading.querySelector('.bubble').textContent = '错误: ' + e.message;
  }
  btn.disabled = false;
  input.focus();
}

function addMsg(role, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.innerHTML = '<div class="bubble"></div>';
  div.querySelector('.bubble').textContent = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}
</script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("AGENT_PORT", "8765"))
    print(f"蓝队 Agent 启动: http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
