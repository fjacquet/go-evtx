#!/usr/bin/env python3
"""Parse a go-evtx-generated file with python-evtx and check it against the
generator's own expectations.

This is the differential the v0.6.0 audit found missing: the Go test suite
round-trips go-evtx against go-evtx, so any shared misunderstanding of the
format is invisible. python-evtx is an independent implementation.
"""
import json
import sys
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx


def main(evtx_path: str, expected_path: str) -> int:
    with open(expected_path) as fh:
        expected = json.load(fh)

    object_names = []
    count = 0
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            for data in root.iterfind(".//e:Data", ns):
                if data.get("Name") == "ObjectName":
                    object_names.append(data.text or "")
            count += 1

    failures = []
    if count != expected["record_count"]:
        failures.append(f"record count: got {count}, want {expected['record_count']}")
    if object_names != expected["object_names"]:
        for i, (got, want) in enumerate(zip(object_names, expected["object_names"])):
            if got != want:
                failures.append(f"record {i} ObjectName: got {got!r}, want {want!r}")
                break
        if len(object_names) != len(expected["object_names"]):
            failures.append(
                f"ObjectName count: got {len(object_names)}, want {len(expected['object_names'])}"
            )

    # Checksums: python-evtx exposes them, and a wrong CRC is exactly the kind
    # of damage a self-round-trip cannot see.
    with evtx.Evtx(evtx_path) as log:
        fh = log.get_file_header()
        for i, chunk in enumerate(fh.chunks()):
            if not chunk.check_magic():
                break
            if chunk.calculate_header_checksum() != chunk.header_checksum():
                failures.append(f"chunk {i}: header checksum mismatch")
            if chunk.calculate_data_checksum() != chunk.data_checksum():
                failures.append(f"chunk {i}: data checksum mismatch")

    if failures:
        print("FAIL")
        for f in failures:
            print("  -", f)
        return 1

    print(f"OK: {count} records, all chunk checksums verify")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
