"""
Test getting issues from a completed scan
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from burp_cli.api.client import BurpClient
from burp_cli.utils.config import get_settings


async def test_get_issues():
    """Get issues from scan ID 7"""

    settings = get_settings()
    scan_id = "7"

    print(f"[*] Getting issues from scan {scan_id}")
    print("=" * 60)

    async with BurpClient(
        api_url=settings.burp_api_url,
        api_key=settings.burp_api_key,
        timeout=settings.request_timeout
    ) as client:

        # Get scan status
        print(f"\n[+] Checking scan status...")
        details = await client.get_scan_status(scan_id)
        print(f"   Status: {details.status.value}")
        if details.issue_counts:
            print(f"   Issue counts: {details.issue_counts}")

        # Get issues
        print(f"\n[+] Retrieving issues...")
        issues = await client.get_scan_issues(scan_id)
        print(f"   Total issues: {issues.total_count}")

        if issues.issues:
            print("\n" + "=" * 60)
            print("ISSUES FOUND:")
            print("=" * 60)

            # Group by severity
            high = [i for i in issues.issues if i.severity.value == 'high']
            medium = [i for i in issues.issues if i.severity.value == 'medium']
            low = [i for i in issues.issues if i.severity.value == 'low']
            info = [i for i in issues.issues if i.severity.value == 'info']

            if high:
                print(f"\n[HIGH] {len(high)} issues:")
                for issue in high:
                    print(f"  - {issue.name}")
                    print(f"    Path: {issue.path}")
                    print(f"    Confidence: {issue.confidence.value}")
                    print()

            if medium:
                print(f"\n[MEDIUM] {len(medium)} issues:")
                for issue in medium[:10]:
                    print(f"  - {issue.name} at {issue.path}")

            if low:
                print(f"\n[LOW] {len(low)} issues:")
                for issue in low[:5]:
                    print(f"  - {issue.name}")

            if info:
                print(f"\n[INFO] {len(info)} issues")

        print("\n" + "=" * 60)
        print("[SUCCESS] Test completed!")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_get_issues())
