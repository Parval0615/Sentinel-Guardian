"""Prompt注入攻击载荷数据库 — 内部 payload + benchmark 内化 payload"""

from .environment import ENVIRONMENT_CONTEXT_PAYLOADS
from .injection import INJECTION_PAYLOADS
from .jailbreak import JAILBREAK_PAYLOADS
from .leakage import LEAKAGE_PAYLOADS
from .obfuscation import OBFUSCATION_PAYLOADS
from .agentdojo import AGENTDOJO_PAYLOADS
from .injecagent import INJECAGENT_PAYLOADS
from .agentharm import AGENTHARM_PAYLOADS

ALL_PAYLOADS = (
    INJECTION_PAYLOADS
    + JAILBREAK_PAYLOADS
    + LEAKAGE_PAYLOADS
    + OBFUSCATION_PAYLOADS
    + ENVIRONMENT_CONTEXT_PAYLOADS
)

# benchmark 内化 payload（按来源分开，不混入 ALL_PAYLOADS 以保持向后兼容）
ALL_BENCHMARK_PAYLOADS = AGENTDOJO_PAYLOADS + INJECAGENT_PAYLOADS + AGENTHARM_PAYLOADS

CATEGORIES = {
    "direct_injection": "直接注入",
    "jailbreak": "越狱攻击",
    "prompt_leakage": "提示泄露",
    "obfuscation": "混淆绕过",
    "environment_context_poisoning": "环境感知污染",
}

BENCHMARK_SOURCES = {
    "agentdojo": "AgentDojo (NeurIPS 2024, MIT)",
    "injecagent": "InjecAgent (MIT)",
    "agentharm": "AgentHarm (MIT)",
}
