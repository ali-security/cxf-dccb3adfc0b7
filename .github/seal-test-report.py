"""Print surefire totals and every skipped test with its reason (seal-build.yml)."""
import glob
import re
import xml.etree.ElementTree as ET

total = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
for f in sorted(glob.glob("**/target/surefire-reports/TEST-*.xml", recursive=True)):
    root = ET.parse(f).getroot()
    for k in total:
        total[k] += int(root.get(k, 0))
    for tc in root.iter("testcase"):
        sk = tc.find("skipped")
        if sk is None:
            continue
        cls, name = tc.get("classname") or "", tc.get("name") or ""
        reason = sk.get("message") or ""
        if not reason:
            for src in glob.glob("**/src/test/java/" + cls.replace(".", "/") + ".java", recursive=True):
                text = open(src, encoding="utf-8", errors="replace").read()
                m = re.search(r"(@(?:org\.junit\.)?Ignore[^\n]*)\s*(?:\n\s*@[^\n]*)*\n\s*public void "
                              + re.escape(name) + r"\b", text)
                if not m:
                    m = re.search(r"(@(?:org\.junit\.)?Ignore[^\n]*)\s*(?:\n\s*@[^\n]*)*\n\s*public (?:abstract |final )?class ", text)
                if m:
                    reason = "upstream annotation in source: " + m.group(1).strip()
                elif "Assume" in text or "assume" in text:
                    reason = "JUnit Assume precondition in test source not met on this runner"
        print(f"SKIPPED {cls}.{name}: {reason or 'no reason given by runner'}")
print("SUREFIRE TOTAL:", total, "passed =",
      total["tests"] - total["failures"] - total["errors"] - total["skipped"])
