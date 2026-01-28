"""Contract tests for GitHub branch protection ruleset JSON.

This test suite treats `docs/rulesets.json` as the source-of-truth snapshot for
what is enforced on `refs/heads/main`.

It is intentionally API-free: it validates the JSON structure and cross-checks
required status-check contexts against the repo's CI workflow definition.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def _load_ruleset() -> dict:
    path = Path(__file__).resolve().parents[1] / "docs" / "rulesets.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _rules_by_type(rules: list[dict]) -> dict[str, dict]:
    rules_map: dict[str, dict] = {}
    for rule in rules:
        rule_type = rule.get("type")
        assert isinstance(rule_type, str) and rule_type
        assert rule_type not in rules_map, f"duplicate rule type: {rule_type}"
        rules_map[rule_type] = rule
    return rules_map


def _read_ci_workflow_lines() -> list[str]:
    ci_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
    return ci_path.read_text(encoding="utf-8").splitlines()


def _extract_matrix_versions(lines: list[str]) -> list[str]:
    versions: list[str] = []
    for i, line in enumerate(lines):
        if re.match(r"^\s*python-version\s*:\s*$", line):
            base_indent = len(line) - len(line.lstrip(" "))
            for next_line in lines[i + 1 :]:
                if not next_line.strip():
                    continue
                indent = len(next_line) - len(next_line.lstrip(" "))
                if indent <= base_indent:
                    break
                m = re.match(r"^\s*-\s*['\"]?([^'\"]+)['\"]?\s*$", next_line)
                if m:
                    versions.append(m.group(1).strip())
            if versions:
                break
    return versions


def _extract_gate_job_name_template(lines: list[str]) -> str | None:
    for line in lines:
        m = re.match(r"^\s*name\s*:\s*(.+)\s*$", line)
        if not m:
            continue
        candidate = m.group(1).strip()
        if candidate.startswith("Gate (Python"):
            return candidate
    return None


def _derive_gate_contexts_from_ci_workflow() -> list[str]:
    lines = _read_ci_workflow_lines()

    versions = _extract_matrix_versions(lines)
    assert versions, "could not derive python matrix versions from ci.yml"

    name_template = _extract_gate_job_name_template(lines)
    assert name_template, "could not find Gate job name in ci.yml"

    placeholder = "${{ matrix.python-version }}"
    assert placeholder in name_template, "Gate job name is not matrix-derived"

    contexts = [name_template.replace(placeholder, v) for v in versions]
    return sorted(set(contexts))


def test_ruleset_contract_main_protection() -> None:
    ruleset = _load_ruleset()

    assert ruleset.get("enforcement") == "active"

    conditions = ruleset.get("conditions")
    assert isinstance(conditions, dict)
    ref_name = conditions.get("ref_name")
    assert isinstance(ref_name, dict)

    include = ref_name.get("include")
    exclude = ref_name.get("exclude")
    assert include == ["refs/heads/main"]
    assert exclude == []

    bypass_actors = ruleset.get("bypass_actors")
    assert bypass_actors == []

    rules = ruleset.get("rules")
    assert isinstance(rules, list)
    rules_map = _rules_by_type(rules)

    pull_request = rules_map["pull_request"]
    pr_params = pull_request.get("parameters")
    assert isinstance(pr_params, dict)

    assert pr_params.get("required_approving_review_count") == 1
    assert pr_params.get("dismiss_stale_reviews_on_push") is True
    assert pr_params.get("require_last_push_approval") is True

    required_status_checks = rules_map["required_status_checks"]
    rsc_params = required_status_checks.get("parameters")
    assert isinstance(rsc_params, dict)

    assert rsc_params.get("strict_required_status_checks_policy") is True

    required = rsc_params.get("required_status_checks")
    assert isinstance(required, list)

    contexts = [item.get("context") for item in required]
    assert all(isinstance(c, str) and c for c in contexts)

    expected_contexts = _derive_gate_contexts_from_ci_workflow()
    assert contexts == expected_contexts

    assert "required_signatures" in rules_map
