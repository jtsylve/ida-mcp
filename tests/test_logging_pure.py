# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for log-path resolution and run-ID propagation."""

from __future__ import annotations

import os

import pytest
from re_mcp import _sanitize_label, ensure_run_id, resolve_log_file


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("RE_MCP_LOG_RUN", raising=False)
    monkeypatch.delenv("RE_MCP_LOG_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_LOG_RUN", raising=False)
    monkeypatch.delenv("IDA_MCP_LOG_DIR", raising=False)


def test_resolve_log_file_unset_returns_none():
    assert resolve_log_file("supervisor") is None


def test_resolve_log_file_builds_path(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("supervisor")
    assert result is not None
    assert os.path.dirname(result) == str(tmp_path)
    assert result.endswith("-supervisor.log")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}-supervisor.log"


def test_resolve_log_file_custom_suffix(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("worker-abc", suffix=".stderr")
    assert result.endswith("-worker-abc.stderr")


def test_resolve_log_file_creates_missing_directory(monkeypatch, tmp_path):
    target = tmp_path / "nested" / "logs"
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(target))
    result = resolve_log_file("supervisor")
    assert os.path.isdir(target)
    assert result.startswith(str(target))


def test_resolve_log_file_sanitizes_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    # Path separators must not leak into the filename — the resolved path
    # must stay inside the configured directory.
    result = resolve_log_file("worker-../evil/db")
    assert os.path.dirname(result) == str(tmp_path)
    assert os.sep not in os.path.basename(result)


def test_resolve_log_file_empty_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}.log"


def test_resolve_log_file_shares_run_id_across_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    first = resolve_log_file("supervisor")
    second = resolve_log_file("worker-x")
    prefix_first = os.path.basename(first).split("-supervisor")[0]
    prefix_second = os.path.basename(second).split("-worker-x")[0]
    assert prefix_first == prefix_second


def test_ensure_run_id_respects_preexisting_env(monkeypatch):
    monkeypatch.setenv("RE_MCP_LOG_RUN", "preset-run-id")
    assert ensure_run_id() == "preset-run-id"


def test_ensure_run_id_generates_and_persists():
    run_id = ensure_run_id()
    assert run_id
    assert os.environ["RE_MCP_LOG_RUN"] == run_id
    assert ensure_run_id() == run_id


def test_sanitize_label_replaces_unsafe_chars():
    # Dots are kept (safe in a leaf filename); separators are scrubbed.
    assert _sanitize_label("worker/db.i64") == "worker_db.i64"
    assert _sanitize_label("safe-label_1.2") == "safe-label_1.2"
    assert _sanitize_label("a b:c") == "a_b_c"
    assert "/" not in _sanitize_label("../evil/x")
