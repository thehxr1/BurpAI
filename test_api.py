"""
Quick test script to validate Burp API client end-to-end
"""

import asyncio
import sys
from pathlib import Path

# Add burp_cli to path
sys.path.insert(0, str(Path(__file__).parent))

from burp_cli.api.client import BurpClient
from burp_cli.utils.config import get_settings


async def test_burp_api():
    """Test Burp API client functionality"""

    settings = get_settings()

    print(f"[*] Testing Burp API at: {settings.burp_api_url}")
    print(f"[*] Using API key: {settings.burp_api_key[:10]}...")
    print("-" * 60)

    async with BurpClient(
        api_url=settings.burp_api_url,
        api_key=settings.burp_api_key,
        timeout=settings.request_timeout
    ) as client:

        # Test 1: Health Check
        print("\n[+] Test 1: Health Check")
        try:
            version = await client.get_version()
            print(f"   [OK] Connected to {version.product} v{version.version}")
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            import traceback
            traceback.print_exc()
            return

        # Test 2: List Scans
        print("\n[+] Test 2: List Scans")
        scans = []
        try:
            scans = await client.list_scans()
            print(f"   [OK] Found {len(scans)} scan(s)")
            for scan in scans:
                print(f"     - Scan ID: {scan.scan_id}, Status: {scan.status.value}")
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            import traceback
            traceback.print_exc()

        # Test 3: Get Scan Status (if scans exist)
        if scans:
            print("\n[+] Test 3: Get Scan Status")
            for scan in scans[:3]:  # Test first 3 scans
                try:
                    details = await client.get_scan_status(scan.scan_id)
                    print(f"   [OK] Scan {details.scan_id}:")
                    print(f"     - Status: {details.status.value}")
                    if details.issue_counts:
                        print(f"     - Issues: {details.issue_counts}")
                    if details.scan_metrics:
                        print(f"     - Metrics: {details.scan_metrics}")
                except Exception as e:
                    print(f"   [FAIL] Scan {scan.scan_id}: {e}")

        # Test 4: Get Scan Issues (if completed scans exist)
        print("\n[+] Test 4: Get Scan Issues")
        completed_scans = [s for s in scans if s.status.value in ['succeeded', 'failed', 'cancelled']]
        if completed_scans:
            try:
                scan_id = completed_scans[0].scan_id
                issues = await client.get_scan_issues(scan_id)
                print(f"   [OK] Scan {scan_id} has {issues.total_count} issue(s)")
                for issue in issues.issues[:5]:  # Show first 5 issues
                    print(f"     - {issue.severity.value.upper()}: {issue.name}")
            except Exception as e:
                print(f"   [FAIL] Error: {e}")
        else:
            print("   [WARN] No completed scans to check for issues")

    print("\n" + "=" * 60)
    print("[SUCCESS] All tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_burp_api())
