import os
import sys
import tempfile
from datetime import datetime, timezone

os.chdir(tempfile.mkdtemp())
sys.path.insert(0, r"E:\чит\justice_bot")

import evidence
import protector
import osint
import reporter

class Msg:
    def __init__(self, content, author="Test"):
        self.content = content
        self.author = author
        self.created_at = datetime.now(timezone.utc)

rec = evidence.snapshot_user("Test", 123456, [Msg("test msg"), Msg("address leaked")])
print("EVIDENCE:", rec["case"], rec["sha256"][:12], "verify:", evidence.verify_case(rec["case"])["ok"])

protector.add_watch("someone@example.com", "Olya")
print("WATCH:", protector.is_watching("someone@example.com"), list(protector.load_watchlist().keys()))

d = osint.lookup_ip("8.8.8.8")
print("IP:", d.get("country"), "|", d.get("isp"))
d2 = osint.lookup_ip("not-an-ip")
print("IP-invalid:", d2.get("error"))

print("PASS:", osint.password_breached("123456"))

tpl = reporter.report_template("Discord", "https://x", "case_1", "threats")
print("REPORT ok:", "ЖАЛОБА" in tpl)