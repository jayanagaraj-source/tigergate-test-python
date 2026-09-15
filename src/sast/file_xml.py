"""SAST fixture: filesystem and XML parsing flaws (CWE-22, CWE-377, CWE-611, CWE-732)."""
import os
import tarfile
import tempfile
import xml.dom.minidom
import xml.etree.ElementTree as ET

from lxml import etree


def scratch_file() -> str:
    # tg-expect: SAST-090 | medium | CWE-377 | tempfile.mktemp race condition
    return tempfile.mktemp()


def publish_report(path: str) -> None:
    # tg-expect: SAST-091 | high | CWE-732 | World-writable file permissions (0o777)
    os.chmod(path, 0o777)


def unpack_upload(archive_path: str) -> None:
    with tarfile.open(archive_path) as archive:
        # tg-expect: SAST-092 | high | CWE-22 | tarfile.extractall without member validation (tar-slip)
        archive.extractall("/srv/extracted")


def parse_invoice(xml_text: str):
    # tg-expect: SAST-093 | medium | CWE-611 | xml.etree parsing of untrusted XML
    return ET.fromstring(xml_text)


def parse_feed(xml_bytes: bytes):
    # tg-expect: SAST-094 | high | CWE-611 | XXE: lxml parser with entity resolution and network access enabled
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml_bytes, parser)


def parse_legacy(xml_text: str):
    # tg-expect: SAST-095 | medium | CWE-611 | xml.dom.minidom parsing of untrusted XML
    return xml.dom.minidom.parseString(xml_text)


def cache_path() -> str:
    # tg-expect: SAST-096 | low | CWE-377 | Hard-coded shared temp directory
    return "/tmp/tigergate-cache.json"
