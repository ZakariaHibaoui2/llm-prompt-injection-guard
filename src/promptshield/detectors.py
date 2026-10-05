"""Heuristic detectors, grouped by attack technique (OWASP LLM01: Prompt Injection)."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    id: str
    category: str
    weight: float
    pattern: re.Pattern


# Near-certain indicators: counted at full weight whatever the ML model says.
STRONG = {"override_en", "override_fr", "override_es", "template_tokens", "md_image_exfil", "prompt_leak", "dan",
          "no_policy", "imagine_no_rules", "pivot_override", "first_message"}


def _p(rx: str) -> re.Pattern:
    return re.compile(rx, re.I)


SIGNATURES = [
    # instruction override
    Signature("override_en", "instruction_override", 0.6, _p(
        r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,30}\b(previous|prior|above|earlier|all|any|your|the)\b"
        r".{0,25}\b(instructions?|rules?|prompts?|guidelines?|directions?|context|polic(y|ies))")),
    Signature("override_fr", "instruction_override", 0.6, _p(
        r"\b(ignore[rz]?|oublie[rz]?)\b.{0,30}\b(instructions?|consignes?|r[eè]gles?)\b")),
    Signature("override_es", "instruction_override", 0.6, _p(
        r"\b(ignora|olvida)\b.{0,30}\b(instrucciones|reglas|indicaciones)\b")),
    Signature("new_instructions", "instruction_override", 0.35, _p(
        r"\b(new|updated|real|actual|true)\s+(instructions?|task|objective)\s*[:\-]")),
    # jailbreak personas / role play
    Signature("dan", "jailbreak", 0.6, _p(r"\b(you are (now )?dan|do anything now|developer mode|jailbreak mode|jailbroken|god mode|unfiltered mode)\b")),
    Signature("no_limits", "jailbreak", 0.45, _p(
        r"\b(without|no|free from|ignore)\b.{0,20}\b(restrictions?|limitations?|filters?|censorship|guardrails?|ethic(s|al))\b")),
    Signature("no_policy", "jailbreak", 0.55, _p(
        r"\b(no|without|has no|have no|free of)\s+(content|safety|usage|moderation)\s+(polic(y|ies)|filters?|rules)\b")),
    Signature("imagine_no_rules", "jailbreak", 0.5, _p(
        r"\b(imagine|pretend|suppose|assume)\b.{0,40}\b(polic(y|ies)|rules|guidelines|filters?|restrictions)\b.{0,25}"
        r"\b(do(es)?\s?n[o']?t|no longer|never|did not)\s+(exist|apply)")),
    Signature("stay_in_character", "jailbreak", 0.3, _p(r"\bstay in character\b.{0,30}\b(no matter what|whatever|always)\b")),
    Signature("pivot_override", "instruction_override", 0.6, _p(
        r"\b(actually|instead|but first|wait|scratch that)\b[,.!]?\s+(ignore|forget|disregard|skip)\s+(that|this|it|the above)\b")),
    Signature("first_message", "prompt_extraction", 0.55, _p(
        r"(\b(first|initial|original|opening|earliest)\s+(message|prompt|instructions?)\b.{0,60}\b(quote|verbatim|word for word|exactly)\b)"
        r"|(\b(quote|verbatim|word for word)\b.{0,60}\b(first|initial|original)\s+(message|prompt|instructions?)\b)")),
    Signature("persona_switch", "jailbreak", 0.3, _p(
        r"\b(you are now|from now on you|pretend (to be|you are)|act as|roleplay as)\b")),
    # system prompt extraction
    Signature("prompt_leak", "prompt_extraction", 0.6, _p(
        r"\b(reveal|show|print|repeat|output|display|tell me|what (is|are))\b.{0,20}\b(your|the|its)\s+"
        r"(system|initial|hidden|secret|original)\s+(prompt|instructions?|message|rules)")),
    Signature("repeat_above", "prompt_extraction", 0.45, _p(
        r"\b(repeat|print|output)\b.{0,20}\b(everything|all|the text|words)\b.{0,20}\b(above|before|so far)\b")),
    # chat-template / delimiter injection
    Signature("template_tokens", "delimiter_injection", 0.6, _p(
        r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?inst\]|<</?sys>>|</?system>|^###\s*(system|instruction))")),
    Signature("fake_role", "delimiter_injection", 0.4, _p(r"(^|\n)\s*(system|assistant)\s*:\s*\S")),
    # data exfiltration through rendered markdown / links
    Signature("md_image_exfil", "exfiltration", 0.6, _p(r"!\[[^\]]*\]\(https?://[^)]*[?&][^)]*=")),
    Signature("send_data", "exfiltration", 0.45, _p(
        r"\b(send|post|upload|exfiltrate|forward|leak)\b.{0,40}\b(conversation|chat history|api keys?|password|credentials|"
        r"secrets?|personal data|emails?)\b.{0,40}\b(to|at|via)\b")),
    # tool / agent abuse
    Signature("tool_abuse", "tool_abuse", 0.5, _p(
        r"\b(run|execute|call|invoke)\b.{0,20}\b(shell|bash|powershell|cmd|os\.system|subprocess|rm -rf|curl|wget)\b")),
    Signature("indirect_marker", "indirect_injection", 0.35, _p(
        r"\b(ai|assistant|llm|chatbot|language model)\b.{0,15}\b(reading|processing|summari[sz]ing) this\b")),
]


@dataclass
class Hit:
    signature: str
    category: str
    weight: float
    excerpt: str


def scan_text(normalized: str) -> list[Hit]:
    hits = []
    for sig in SIGNATURES:
        m = sig.pattern.search(normalized)
        if m:
            start = max(m.start() - 15, 0)
            hits.append(Hit(sig.id, sig.category, sig.weight, normalized[start:m.end() + 15]))
    return hits
