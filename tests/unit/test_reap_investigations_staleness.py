"""Idle timing uses launch-specific definitions, not transient stopped-task history."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'lambda' / 'reap-investigations'))
from close_finalization import Finalizer


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def definition(hours_ago, timeout):
    return {'registeredAt': NOW - timedelta(hours=hours_ago), 'containerDefinitions': [
        {'name': 'rosa-boundary', 'environment': [{'name': 'TASK_TIMEOUT', 'value': timeout}]}]}


@pytest.mark.parametrize('definitions,expected', [
    ([], None),  # No task ever launched: caller uses investigation creation.
    ([definition(9, '3600')], NOW - timedelta(hours=8)),
    # The newest launch wins even when the older task had a later deadline.
    ([definition(10, '28800'), definition(9, '3600')], NOW - timedelta(hours=8)),
    ([definition(9, '3600'), definition(10, '28800')], NOW - timedelta(hours=8)),
])
def test_idle_anchor(definitions, expected):
    finalizer = MagicMock()
    finalizer.workspace_definitions.return_value = definitions
    assert Finalizer.latest_session_deadline(finalizer, 'c', 'i', 'ap') == expected
    finalizer.workspace_definitions.assert_called_once_with('c', 'i', 'ap')


@pytest.mark.parametrize('td', [definition(1, 'bad'), {'containerDefinitions': []},
                                {'registeredAt': NOW, 'containerDefinitions': []}])
def test_incomplete_launch_timing_is_not_no_launch(td):
    finalizer = MagicMock()
    finalizer.workspace_definitions.return_value = [td]
    with pytest.raises((KeyError, ValueError)):
        Finalizer.latest_session_deadline(finalizer, 'c', 'i', 'ap')
