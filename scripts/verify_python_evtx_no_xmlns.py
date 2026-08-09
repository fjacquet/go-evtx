#!/usr/bin/env python3
"""Parse the task 9d xmlns-free single-record fixture with python-evtx and
confirm the PREDICTED effect of removing <Event>'s xmlns attribute (F8):
a namespaced XPath query (the convention verify_python_evtx.py and every
other measurement in this release use) finds nothing, while the identical
query with no namespace applied does find the record's own Data/ObjectName
content — proving the file itself parses fine and the miss is specifically
about the namespace, not a corrupt or unparseable fixture.

This is not scripts/verify_python_evtx.py adapted: that script compares
against generator-produced expected.json (record_count, object_names),
which cmd/gen-ladder-no-xmlns (a single hand-built record, no such
manifest) has no equivalent of. This script instead asserts a prediction
directly, so CI is red if reality does not match what task-9d-report.md
predicts -- not merely descriptive output.
"""
import sys
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def main(evtx_path: str) -> int:
    with evtx.Evtx(evtx_path) as log:
        records = list(log.records())
        if len(records) != 1:
            print(f"FAIL: expected exactly 1 record, got {len(records)}")
            return 1
        xml_text = records[0].xml()

    root = ET.fromstring(xml_text)

    namespaced = [d for d in root.iterfind(".//e:Data", NS) if d.get("Name") == "ObjectName"]
    plain = [d for d in root.iter("Data") if d.get("Name") == "ObjectName"]

    print(f"namespaced query (.//e:Data): {len(namespaced)} match(es)")
    print(f"plain query (.//Data, no namespace): {len(plain)} match(es)")

    failures = []
    if len(plain) != 1:
        failures.append(
            f"plain (unnamespaced) query found {len(plain)} ObjectName Data elements, want 1 -- "
            "if this is 0, the fixture itself is broken, not just missing a namespace"
        )
    if len(namespaced) != 0:
        failures.append(
            f"namespaced query unexpectedly found {len(namespaced)} match(es), want 0 -- "
            "task-9d-report.md's prediction (removing xmlns breaks namespaced XPath) did NOT hold; "
            "this is itself a finding, not just a broken assertion"
        )

    if failures:
        print("FAIL (prediction not confirmed)")
        for f in failures:
            print("  -", f)
        return 1

    print("OK: fixture parses, plain query finds ObjectName, namespaced query finds nothing -- "
          "prediction confirmed (F8/xmlns is required for namespace-aware XPath, independently "
          "confirmed by removal, not just by task 8's original addition)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
