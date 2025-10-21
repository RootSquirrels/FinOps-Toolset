"""Generic, fast tests for all checkers (no real AWS).

- Discovers modules under finops_toolset.checkers.
- Captures any CSV rows written via config.WRITE_ROW.
- Validates a minimal CSV schema and enforces OwnerId safety.
- Uses simple heuristics to scan AST for inline WRITE_ROW({...}) cases and
  ensure OwnerId uses safely_text() (catches common regressions quickly).

For deeper coverage, see the optional integration test that runs with moto.
"""

from __future__ import annotations

from importlib import import_module
import inspect
import pkgutil
import re
import ast
from typing import Dict, List, Set, Tuple
import pytest

CHECKERS_PACKAGE = "aws_checkers"
CONFIG_MODULE = "aws_checkers.config"

REQUIRED_KEYS: Set[str] = {
    "Resource_ID",
    "Name",
    "ResourceType",
    "OwnerId",
    "Region",
    "Estimated_Cost_USD",
}


def _discover_checker_modules() -> List[str]:
    """Find all checker modules beneath CHECKERS_PACKAGE (skip __init__/config)."""
    modules: List[str] = []
    pkg = import_module(CHECKERS_PACKAGE)
    for modinfo in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        name = modinfo.name
        tail = name.rsplit(".", maxsplit=1)[-1]
        if tail in {"__init__", "config"}:
            continue
        modules.append(name)
    return sorted(modules)


def _assert_row_schema_invariants(row: Dict[str, object]) -> None:
    """Assert basic schema contract for a single row."""
    missing = REQUIRED_KEYS - set(row.keys())
    assert not missing, f"Missing keys: {missing}"

    assert isinstance(row["Resource_ID"], str), "Resource_ID must be a string"
    assert isinstance(row["Name"], str), "Name must be a string"
    assert isinstance(row["ResourceType"], str), "ResourceType must be a string"
    assert isinstance(row["OwnerId"], str), "OwnerId must be a string"
    assert isinstance(row["Region"], str), "Region must be a string"

    cost = row["Estimated_Cost_USD"]
    assert isinstance(cost, (int, float)), "Estimated_Cost_USD must be numeric"
    assert row["Resource_ID"], "Resource_ID should not be empty"


def _assert_owner_id_safe(value: str, account_id: str, safely_text) -> None:
    """Ensure OwnerId is spreadsheet-safe (uses safely_text for 12-digit ids)."""
    looks_12_digits = bool(re.fullmatch(r"[0-9]{12}", str(account_id)))
    if looks_12_digits:
        expected = safely_text(str(account_id))
        assert value == expected, "OwnerId must use safely_text(account_id)"
    else:
        assert value == str(account_id), "OwnerId must match the configured account id"


def _ast_enforce_owner_id_safety(module_obj) -> None:
    """Static check: WRITE_ROW({ ... 'OwnerId': <value> ... }) uses safely_text().

    This catches the common inline dict literal pattern:
    WRITE_ROW({
        'OwnerId': account_id,  # <- should be safely_text(str(account_id))
        ...
    })
    """
    try:
        source = inspect.getsource(module_obj)
    except OSError:
        # Source may not be available (e.g., C extensions). Skip gracefully.
        return

    tree = ast.parse(source)

    def is_write_row_call(node: ast.Call) -> bool:
        target = node.func
        if isinstance(target, ast.Name):
            return target.id == "WRITE_ROW"
        if isinstance(target, ast.Attribute):
            return target.attr == "WRITE_ROW"
        return False

    def value_is_safely_text(call_value: ast.AST) -> bool:
        # Accept safely_text(...), possibly with str(account_id) inside.
        if isinstance(call_value, ast.Call):
            func = call_value.func
            if isinstance(func, ast.Name) and func.id == "safely_text":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "safely_text":
                return True
        return False

    offenses: List[Tuple[int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not is_write_row_call(node):
            continue

        if not node.args:
            # Non-positional or dynamic build; static pass.
            continue

        arg0 = node.args[0]
        if isinstance(arg0, ast.Dict):
            # Inline dict literal passed to WRITE_ROW({...})
            for key_node, val_node in zip(arg0.keys, arg0.values):
                if isinstance(key_node, ast.Constant) and key_node.value == "OwnerId":
                    if not value_is_safely_text(val_node):
                        offenses.append(
                            (node.lineno, "OwnerId not wrapped in safely_text()")
                        )

    assert not offenses, (
        "Static OwnerId safety check failed at lines: " + ", ".join(
            f"{ln}:{msg}" for ln, msg in offenses
        )
    )


@pytest.fixture(name="captured_rows")
def fixture_captured_rows(monkeypatch) -> List[Dict[str, object]]:
    """Capture rows the checkers write via config.WRITE_ROW."""
    cfg = import_module(CONFIG_MODULE)
    rows: List[Dict[str, object]] = []
    monkeypatch.setattr(cfg, "WRITE_ROW", lambda r: rows.append(r), raising=True)
    return rows


@pytest.fixture(name="fake_account_id")
def fixture_fake_account_id(monkeypatch) -> str:
    """Force a deterministic 12-digit account id in config."""
    cfg = import_module(CONFIG_MODULE)
    account_id = "123456789012"
    monkeypatch.setattr(cfg, "account_id", account_id, raising=True)
    return account_id


def test_static_owner_id_safety_across_all_checkers() -> None:
    """AST guardrail: inline WRITE_ROW({...}) must safely_text OwnerId."""
    for modname in _discover_checker_modules():
        module_obj = import_module(modname)
        _ast_enforce_owner_id_safety(module_obj)


def test_runtime_rows_invariants_no_aws(
    captured_rows: List[Dict[str, object]],
    fake_account_id: str,
) -> None:
    """If any rows are emitted on import/quick-run code paths, validate them.

    This test does not call AWS and does not attempt to execute entrypoints.
    It simply guards against accidental row writes violating invariants.
    """
    cfg = import_module(CONFIG_MODULE)

    # Importing modules after hooking WRITE_ROW ensures we capture any eager writes.
    for modname in _discover_checker_modules():
        import_module(modname)

    for row in captured_rows:
        _assert_row_schema_invariants(row)
        _assert_owner_id_safe(row["OwnerId"], fake_account_id, cfg.safely_text)
