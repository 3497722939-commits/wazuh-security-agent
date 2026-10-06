import json, urllib.request, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

base = "https://ai.lupoapi.com/v1"
key = "sk-6bb54df6cb3704fa32f317708b186ea707c69370d868d86d08e327eb4dc62b8b"

body = {
    "model": "gpt-5.5",
    "messages": [{"role": "user", "content": "北京天气怎么样？"}],
    "tools": [{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "查询城市天气",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }
        }
    }],
    "tool_choice": "auto"
}

req = urllib.request.Request(
    base + "/chat/completions",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
)
r = json.loads(urllib.request.urlopen(req, context=ctx, timeout=30).read())
msg = r["choices"][0]["message"]
print("content:", msg.get("content"))
print("tool_calls:", json.dumps(msg.get("tool_calls"), indent=2, ensure_ascii=False))
