# Natural Language Toolkit: pathsec special-file and exact-text tests
#
# Copyright (C) 2001-2026 NLTK Project
# URL: <https://www.nltk.org/>
# For license information, see LICENSE.TXT

import os

import pytest

import nltk.pathsec as pathsec


class TestByNameLinkCheckForNonPosixOpens:
    def test_non_posix_tool_path_branch_refuses_a_hardlink(
        self, pathsec_sandbox, monkeypatch
    ):
        """The tool-path open check has a stat-only branch off POSIX; it must
        refuse a multiply-linked file like the fstat branch does (the weka -l
        read of a hardlinked model was accepted on Windows without it)."""
        root, _ = pathsec_sandbox
        real = str(root / "model.bin")
        with open(real, "wb") as f:
            f.write(b"m")
        hard = str(root / "alias.bin")
        os.link(real, hard)
        monkeypatch.setattr(pathsec.os, "name", "nt")
        with pytest.raises(PermissionError, match="multiply-linked"):
            pathsec._reject_unsafe_open(hard, "test", must_exist=True)
        os.unlink(hard)
        pathsec._reject_unsafe_open(real, "test", must_exist=True)  # single link passes
        pathsec._reject_unsafe_open(str(root / "absent"), "test", must_exist=False)
