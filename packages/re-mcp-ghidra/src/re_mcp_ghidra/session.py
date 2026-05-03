# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database session manager for Ghidra via pyhidra.

Tracks whether a program is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
import shutil
import signal

from re_mcp_ghidra.exceptions import GhidraError

log = logging.getLogger(__name__)

_PROJECT_SUBDIR = ".ghidra_projects"


class Session:
    """Singleton managing the Ghidra program session."""

    def __init__(self):
        self._program = None
        self._project = None
        self._project_location = None
        self._current_path: str | None = None
        self._flat_api = None
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self._current_path is not None and self._program is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    @property
    def program(self):
        return self._program

    @property
    def flat_api(self):
        return self._flat_api

    def open(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
    ) -> dict:
        """Open a binary for analysis.

        Returns a status dict on success.  Raises :class:`GhidraError` on failure.
        """
        from ghidra.base.project import GhidraProject  # noqa: PLC0415
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: PLC0415
        from ghidra.program.model.lang import (  # noqa: PLC0415
            CompilerSpecID,
            LanguageID,
        )
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415
        from java.io import File  # noqa: PLC0415

        path = os.path.realpath(os.path.expanduser(file_path))

        if not os.path.isfile(path):
            raise GhidraError(f"File not found: {path}", error_type="FileNotFoundError")

        if self.is_open():
            self.close(save=True)

        # Create project directory alongside the binary
        binary_dir = os.path.dirname(path)
        binary_name = os.path.basename(path)
        project_dir = os.path.join(binary_dir, _PROJECT_SUBDIR)
        project_name = binary_name

        os.makedirs(project_dir, exist_ok=True)
        project_location = project_dir
        project_file = os.path.join(project_dir, project_name + ".gpr")

        warnings: list[str] = []

        try:
            if force_new and os.path.exists(project_file):
                gpr_path = project_file
                rep_path = os.path.join(project_dir, project_name + ".rep")
                if os.path.isfile(gpr_path):
                    os.remove(gpr_path)
                if os.path.isdir(rep_path):
                    shutil.rmtree(rep_path)
                log.info("force_new: removed existing project files")

            if os.path.exists(project_file):
                project = GhidraProject.openProject(project_location, project_name)
                program = project.openProgram("/", binary_name, False)
                if program is None:
                    program = project.importProgram(File(path))
                    if program is None:
                        project.close()
                        raise GhidraError(
                            f"Failed to import {path} into existing project",
                            error_type="ImportFailed",
                        )
            else:
                project = GhidraProject.createProject(project_location, project_name, False)
                lang_svc = None
                lang = None
                cspec = None

                if language:
                    lang_svc = _get_language_service()
                    try:
                        lang = lang_svc.getLanguage(LanguageID(language))
                    except Exception as e:
                        project.close()
                        raise GhidraError(
                            f"Unknown language: {language!r}. Use list_targets to see available languages.",
                            error_type="InvalidArgument",
                        ) from e

                    if compiler_spec:
                        try:
                            cspec = lang.getCompilerSpecByID(CompilerSpecID(compiler_spec))
                        except Exception as e:
                            project.close()
                            raise GhidraError(
                                f"Unknown compiler spec: {compiler_spec!r} for language {language!r}",
                                error_type="InvalidArgument",
                            ) from e

                if lang is not None:
                    if cspec is not None:
                        program = project.importProgram(File(path), lang, cspec)
                    else:
                        program = project.importProgramFast(File(path), lang)
                else:
                    program = project.importProgram(File(path))

                if program is None:
                    project.close()
                    raise GhidraError(
                        f"Failed to import binary: {path}",
                        error_type="ImportFailed",
                    )

            if run_auto_analysis:
                from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415

                GhidraProgramUtilities.setAnalyzedFlag(program, False)
                GhidraProject.analyze(program)

        except GhidraError:
            raise
        except Exception as exc:
            log.exception("Failed to open database: %s", path)
            raise GhidraError(f"Failed to open database: {exc}", error_type="RuntimeError") from exc

        self._program = program
        self._project = project
        self._project_location = project_location
        self._current_path = path
        self._flat_api = FlatProgramAPI(program, TaskMonitor.DUMMY)
        self.capabilities = self._probe_capabilities()
        log.info("Opened database: %s (capabilities: %s)", path, self.capabilities)
        return {"status": "ok", "path": path, "warnings": warnings}

    def _probe_capabilities(self) -> dict[str, bool]:
        """Detect which optional features are available."""
        return {
            "decompiler": True,
        }

    def close(self, save: bool = True) -> dict:
        """Close the current database.

        Raises :class:`GhidraError` on failure.
        """
        if not self.is_open():
            return {"status": "no_database_open"}

        path = self._current_path
        try:
            if save and self._program is not None and self._project is not None:
                self._project.save(self._program)
            if self._project is not None:
                self._project.close()
        except Exception as exc:
            log.exception("Error closing database %s", path)
            raise GhidraError(f"Error closing database {path}", error_type="CloseFailed") from exc
        finally:
            self._program = None
            self._project = None
            self._project_location = None
            self._current_path = None
            self._flat_api = None

        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that raises :class:`GhidraError` if no database is open."""

        def _check():
            if not self.is_open():
                raise GhidraError(
                    "No database is open. Use open_database first.",
                    error_type="NoDatabase",
                )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

                await call_ghidra(_check)
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check()
            return fn(*args, **kwargs)

        return wrapper


# Module-level singleton
session = Session()


def _get_language_service():
    """Get Ghidra's default language service."""

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415

        return AutoAnalysisManager.getLanguageService()
    except Exception:
        from ghidra.program.util import DefaultLanguageService  # noqa: PLC0415

        return DefaultLanguageService.getLanguageService()


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately."""
    raise SystemExit(0)


# SIGTERM — hard shutdown
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
