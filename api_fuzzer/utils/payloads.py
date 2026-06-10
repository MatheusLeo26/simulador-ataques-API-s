# Payloads for Fuzzing and Input Validation Tests

LOGIC_BREAKING_PAYLOADS = [
    # Special and invalid characters
    "'", '"', "`", "\\", "/", "NULL", "\x00",
    # SQLi simple logic breaks
    "' OR '1'='1",
    "' OR 1=1 --",
    # Command injection or breaking patterns
    "| ls -la",
    "; sleep 5",
    # XSS injection
    "<script>alert(1)</script>",
    # Path Traversal
    "../../../../etc/passwd",
    # Exceedingly large numeric inputs / boundary values
    999999999999999999,
    -1,
    0,
    # Type mismatch (will be replaced dynamically depending on target parameter type)
    "NOT_AN_INTEGER",
    "",
]

# IDOR test replacements (e.g., if we see ID=5, we try some of these)
IDOR_PATTERNS = [
    # Increments/Decrements
    lambda x: str(int(x) + 1) if str(x).isdigit() else None,
    lambda x: str(int(x) - 1) if str(x).isdigit() and int(x) > 1 else None,
    # Standard testing administrative IDs or boundary values
    lambda x: "1" if str(x).isdigit() and x != "1" else None,
    lambda x: "0" if str(x).isdigit() else None,
    # Guid patterns if relevant
    lambda x: "00000000-0000-0000-0000-000000000000" if len(str(x)) == 36 else None,
]
