"""
Simple rule‑based detector for common prompt‑injection patterns.
You can expand PATTERNS with additional regex rules as needed.
"""

import re

class PromptInjectionDetector:
    # Add or refine patterns to suit your security policy
    PATTERNS = [
        r"(?:ignore|override|forget)[\s\S]{0,40}instruction",   # e.g. "Ignore your previous instruction"
        r"(?:system|developer)\s+prompt",                       # attempts to read system prompt
        r"<\!--[\s\S]*?-->",                                    # HTML comment escape trick
        r"```[\s\S]*?```",                                      # fenced‑code blocks that may hide instructions
    ]

    @classmethod
    def is_malicious(cls, prompt: str) -> bool:
        """Return True if any known malicious pattern is found."""
        prompt_lc = prompt.lower()
        return any(re.search(pattern, prompt_lc) for pattern in cls.PATTERNS)