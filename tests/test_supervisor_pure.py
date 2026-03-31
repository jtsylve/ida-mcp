# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for supervisor.py pure utility functions.

These tests cover _prefix_uri and _extract_db_prefix — URI manipulation
functions that can run without idalib loaded.
"""

from __future__ import annotations

from ida_mcp.supervisor import _extract_db_prefix, _prefix_uri

# ---------------------------------------------------------------------------
# _prefix_uri
# ---------------------------------------------------------------------------


def test_prefix_uri_basic():
    assert _prefix_uri("ida://idb/metadata", "mybin") == "ida://mybin/idb/metadata"


def test_prefix_uri_nested_path():
    assert _prefix_uri("ida://functions/0x401000", "db1") == "ida://db1/functions/0x401000"


def test_prefix_uri_non_ida_scheme():
    assert _prefix_uri("https://example.com", "mybin") == "https://example.com"


def test_prefix_uri_template_placeholder():
    assert _prefix_uri("ida://types/{name}", "{database}") == "ida://{database}/types/{name}"


# ---------------------------------------------------------------------------
# _extract_db_prefix
# ---------------------------------------------------------------------------


def test_extract_db_prefix_basic():
    db, worker_uri = _extract_db_prefix("ida://mybin/idb/metadata")
    assert db == "mybin"
    assert worker_uri == "ida://idb/metadata"


def test_extract_db_prefix_nested():
    db, worker_uri = _extract_db_prefix("ida://db1/functions/0x401000")
    assert db == "db1"
    assert worker_uri == "ida://functions/0x401000"


def test_extract_db_prefix_non_ida_scheme():
    db, uri = _extract_db_prefix("https://example.com/path")
    assert db is None
    assert uri == "https://example.com/path"


def test_extract_db_prefix_no_path_segment():
    """URI like ``ida://databases`` has no slash after the first segment."""
    db, uri = _extract_db_prefix("ida://databases")
    assert db is None
    assert uri == "ida://databases"


def test_extract_db_prefix_empty_segment():
    """URI like ``ida:///path`` has an empty segment before the slash."""
    db, uri = _extract_db_prefix("ida:///path")
    assert db is None
    assert uri == "ida:///path"


def test_extract_roundtrip():
    """_prefix_uri and _extract_db_prefix are inverses for ida:// URIs."""
    original = "ida://idb/segments"
    db_id = "testdb"
    prefixed = _prefix_uri(original, db_id)
    extracted_db, extracted_uri = _extract_db_prefix(prefixed)
    assert extracted_db == db_id
    assert extracted_uri == original
