"""
AI-powered analysis helpers for security findings validation

This module provides functions that Claude Desktop can use to intelligently
analyze security findings and make validation decisions.
"""

from typing import Dict, Any, List


def analyze_issue_for_validation(issue: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare issue data for AI analysis

    Returns structured data that Claude can analyze to determine:
    - Is this likely a true positive or false positive?
    - What validation tests should be run?
    - What payloads are most effective?
    - Is this exploitable?
    """

    analysis_context = {
        "issue_summary": {
            "name": issue.get("name"),
            "type": issue.get("issue_type"),
            "severity": issue.get("severity"),
            "confidence": issue.get("confidence"),
            "path": issue.get("path"),
        },

        "description": issue.get("description", "")[:500],

        "evidence": {
            "has_request": bool(issue.get("evidence", [{}])[0].get("request")),
            "has_response": bool(issue.get("evidence", [{}])[0].get("response")),
            "request_sample": issue.get("evidence", [{}])[0].get("request", "")[:300],
            "response_sample": issue.get("evidence", [{}])[0].get("response", "")[:300],
        },

        "validation_recommendations": {
            "sql_injection": [
                "Test with time-based payloads (SLEEP, WAITFOR)",
                "Test with boolean-based payloads",
                "Check for database error messages",
                "Try UNION-based injection",
                "Test with sqlmap for confirmation"
            ],
            "xss": [
                "Test payload reflection in HTML context",
                "Try different encoding bypasses",
                "Test in script context",
                "Check CSP headers",
                "Verify if payload executes in browser"
            ],
            "ssrf": [
                "Test with Collaborator callback",
                "Try internal IP ranges",
                "Test cloud metadata endpoints",
                "Check DNS resolution",
                "Verify out-of-band interaction"
            ],
            "xxe": [
                "Test with external entity callbacks",
                "Use Collaborator for OOB detection",
                "Try file disclosure payloads",
                "Test SSRF via XXE"
            ],
            "command_injection": [
                "Test with time delays (sleep, ping)",
                "Use Collaborator for DNS exfiltration",
                "Try command chaining",
                "Test with different separators"
            ],
            "path_traversal": [
                "Test with ../../../etc/passwd",
                "Try Windows paths",
                "Test with URL encoding",
                "Try absolute paths"
            ]
        },

        "exploitation_context": {
            "impact": {
                "sql_injection": "Data breach, authentication bypass, data modification",
                "xss": "Session hijacking, phishing, defacement",
                "ssrf": "Internal network access, cloud metadata access",
                "xxe": "File disclosure, SSRF, DoS",
                "command_injection": "Remote code execution, full system compromise",
                "path_traversal": "Arbitrary file read, source code disclosure"
            }.get(issue.get("issue_type", "").lower(), "Security vulnerability"),

            "requires_authentication": "authenticated" in issue.get("path", "").lower(),
            "affected_url": issue.get("path"),
        }
    }

    return analysis_context


def create_validation_plan(issue_type: str, confidence: str, evidence: Dict) -> List[Dict[str, Any]]:
    """
    Create a validation plan based on issue type

    Returns a list of validation steps Claude should execute
    """

    plans = {
        "sql_injection": [
            {
                "step": 1,
                "action": "test_time_based",
                "payloads": ["' OR SLEEP(5)--", "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"],
                "success_criteria": "Response time > 4 seconds",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 2,
                "action": "test_boolean_based",
                "payloads": ["' AND '1'='1", "' AND '1'='2"],
                "success_criteria": "Different responses for true/false conditions",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 3,
                "action": "test_error_based",
                "payloads": ["'", "''", "' OR 1=1--"],
                "success_criteria": "SQL error messages in response",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 4,
                "action": "confirm_with_sqlmap",
                "tool": "sqlmap_integration",
                "note": "Use sqlmap for definitive confirmation"
            }
        ],

        "xss": [
            {
                "step": 1,
                "action": "test_basic_reflection",
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "success_criteria": "Payload reflected without encoding",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 2,
                "action": "test_encoding_bypass",
                "payloads": ["<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>"],
                "success_criteria": "Bypass filters and reflect",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 3,
                "action": "check_csp",
                "tool": "burp_send_to_repeater",
                "note": "Check Content-Security-Policy header"
            }
        ],

        "ssrf": [
            {
                "step": 1,
                "action": "test_collaborator_callback",
                "tool": "burp_collaborator_generate",
                "note": "Generate unique subdomain"
            },
            {
                "step": 2,
                "action": "send_request_with_collaborator",
                "tool": "burp_send_to_repeater",
                "success_criteria": "DNS/HTTP interaction detected"
            },
            {
                "step": 3,
                "action": "test_internal_ips",
                "payloads": ["http://169.254.169.254/", "http://127.0.0.1/", "http://localhost/"],
                "tool": "burp_send_to_repeater"
            }
        ],

        "command_injection": [
            {
                "step": 1,
                "action": "test_time_delay",
                "payloads": ["; sleep 5", "| sleep 5", "& timeout 5"],
                "success_criteria": "Response delay of ~5 seconds",
                "tool": "burp_send_to_repeater"
            },
            {
                "step": 2,
                "action": "test_collaborator_dns",
                "tool": "burp_collaborator_generate",
                "payloads": ["; nslookup {collaborator}", "| ping -c 1 {collaborator}"],
                "success_criteria": "DNS query detected"
            }
        ]
    }

    return plans.get(issue_type.lower().replace(" ", "_"), [])


def assess_exploitability(validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Assess exploitability based on validation results

    Returns an exploitability assessment that Claude can use for reporting
    """

    confirmed_tests = sum(1 for r in validation_results if r.get("confirmed", False))
    total_tests = len(validation_results)

    if confirmed_tests == 0:
        verdict = "FALSE_POSITIVE"
        confidence = "high"
        reason = "No validation tests confirmed the vulnerability"
    elif confirmed_tests < total_tests / 2:
        verdict = "LIKELY_FALSE_POSITIVE"
        confidence = "medium"
        reason = f"Only {confirmed_tests}/{total_tests} tests confirmed"
    elif confirmed_tests >= total_tests / 2:
        verdict = "LIKELY_TRUE_POSITIVE"
        confidence = "medium"
        reason = f"{confirmed_tests}/{total_tests} tests confirmed"

    if confirmed_tests == total_tests and total_tests > 0:
        verdict = "TRUE_POSITIVE"
        confidence = "high"
        reason = "All validation tests confirmed the vulnerability"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "confirmed_tests": confirmed_tests,
        "total_tests": total_tests,
        "recommendation": {
            "TRUE_POSITIVE": "Immediate remediation required",
            "LIKELY_TRUE_POSITIVE": "Investigate and remediate if confirmed",
            "LIKELY_FALSE_POSITIVE": "Review configuration, likely not exploitable",
            "FALSE_POSITIVE": "No action needed, finding is incorrect"
        }.get(verdict)
    }


def generate_poc(issue_type: str, successful_payload: str, evidence: Dict) -> str:
    """
    Generate proof-of-concept for validated finding
    """

    poc_templates = {
        "sql_injection": f"""
Proof of Concept - SQL Injection

URL: {evidence.get('url')}
Parameter: {evidence.get('parameter')}
Method: {evidence.get('method', 'GET')}

Successful Payload:
{successful_payload}

Evidence:
- Response Time: {evidence.get('response_time', 'N/A')}s
- Confirmed: Time-based blind SQL injection

Exploitation Steps:
1. Inject payload in vulnerable parameter
2. Observe time delay in response
3. Use sqlmap for further exploitation:
   sqlmap -u "{evidence.get('url')}" -p {evidence.get('parameter')} --batch

Impact: Complete database compromise possible
""",

        "xss": f"""
Proof of Concept - Cross-Site Scripting

URL: {evidence.get('url')}
Parameter: {evidence.get('parameter')}
Type: {evidence.get('xss_type', 'Reflected')}

Successful Payload:
{successful_payload}

Evidence:
- Payload reflected without encoding
- CSP: {evidence.get('csp', 'Not present')}

Exploitation Steps:
1. Craft malicious URL with payload
2. Send to victim
3. Payload executes in victim's browser

Impact: Session hijacking, credential theft, phishing
"""
    }

    return poc_templates.get(issue_type.lower().replace(" ", "_"),
                            f"Successful payload: {successful_payload}")
