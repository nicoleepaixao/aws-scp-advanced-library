"""Rules every SCP in this repository must follow."""
import json

import pytest

from scp_eval import POLICIES

FILES = sorted(POLICIES.glob("*/*.json"))
SCP_MAX_CHARS = 10_240  # AWS Organizations quota for an SCP document


def test_every_policy_folder_has_a_readme():
    for folder in sorted(p for p in POLICIES.iterdir() if p.is_dir()):
        assert (folder / "README.md").exists(), f"{folder.name} has no README.md"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.parent.name)
def test_valid_scp_shape(path):
    policy = json.loads(path.read_text())
    assert policy["Version"] == "2012-10-17"
    sids = [s["Sid"] for s in policy["Statement"]]
    assert len(sids) == len(set(sids)), "duplicate Sid"
    for statement in policy["Statement"]:
        assert statement["Effect"] == "Deny", "this library only ships deny-list SCPs"
        assert "Principal" not in statement and "NotPrincipal" not in statement
        assert ("Action" in statement) != ("NotAction" in statement)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.parent.name)
def test_fits_scp_size_limit_when_minified(path):
    minified = json.dumps(json.loads(path.read_text()), separators=(",", ":"))
    assert len(minified) <= SCP_MAX_CHARS, f"{len(minified)} characters"
