"""
Unit tests for investigation reaper staleness logic.

Tests the is_investigation_stale() function's behavior with various
combinations of running tasks, CreatedAt timestamps, and grace periods.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Add lambda directory to path for imports
lambda_dir = Path(__file__).parent.parent.parent / 'lambda' / 'reap-investigations'
sys.path.insert(0, str(lambda_dir))

# Import the entire handler module to ensure consistent patching
import handler as reaper_handler


class TestIsInvestigationStale:
    """Test suite for is_investigation_stale() function."""

    @pytest.fixture
    def now(self):
        """Current timestamp for testing."""
        return datetime.now(timezone.utc)

    @pytest.fixture
    def running_tasks_empty(self):
        """No running tasks."""
        return []

    @pytest.fixture
    def running_tasks_with_match(self):
        """Running tasks including one for the test investigation."""
        return [
            {
                'arn': 'arn:aws:ecs:us-east-1:123:task/abc',
                'cluster_id': 'test-cluster',
                'investigation_id': 'test-inv'
            }
        ]

    @pytest.fixture
    def running_tasks_no_match(self):
        """Running tasks for different investigation."""
        return [
            {
                'arn': 'arn:aws:ecs:us-east-1:123:task/xyz',
                'cluster_id': 'other-cluster',
                'investigation_id': 'other-inv'
            }
        ]

    def test_with_running_tasks_is_not_stale(self, now, running_tasks_with_match):
        """Investigation with running tasks should never be stale."""
        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=now - timedelta(days=365),  # Very old
            now=now,
            running_tasks=running_tasks_with_match
        )

        assert result['is_stale'] is False
        assert '1 running task(s)' in result['reason']
        assert result['running_tasks'] == 1

    def test_legacy_investigation_no_tasks_is_stale(self, now, running_tasks_empty):
        """Legacy investigation (missing CreatedAt) with no tasks should be stale."""
        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=None,  # Missing CreatedAt tag
            now=now,
            running_tasks=running_tasks_empty
        )

        assert result['is_stale'] is True
        assert 'legacy investigation (missing CreatedAt tag)' in result['reason']
        assert result['running_tasks'] == 0

    def test_legacy_investigation_with_tasks_is_not_stale(self, now, running_tasks_with_match):
        """Legacy investigation with running tasks should NOT be stale (safety check)."""
        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=None,  # Missing CreatedAt tag
            now=now,
            running_tasks=running_tasks_with_match
        )

        assert result['is_stale'] is False
        assert '1 running task(s)' in result['reason']
        assert result['running_tasks'] == 1

    def test_old_investigation_beyond_grace_period_is_stale(self, now, running_tasks_empty, monkeypatch):
        """Investigation older than grace period with no tasks should be stale."""
        # Patch GRACE_PERIOD_HOURS constant using the module-level import
        monkeypatch.setattr(reaper_handler, 'GRACE_PERIOD_HOURS', 168)

        # Created 200 hours ago (beyond 168h grace period)
        created_at = now - timedelta(hours=200)

        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=created_at,
            now=now,
            running_tasks=running_tasks_empty
        )

        assert result['is_stale'] is True
        assert 'no tasks' in result['reason']
        assert '200h old' in result['reason']
        assert result['running_tasks'] == 0

    def test_new_investigation_within_grace_period_is_not_stale(self, now, running_tasks_empty, monkeypatch):
        """Investigation within grace period should NOT be stale."""
        # Patch GRACE_PERIOD_HOURS constant using the module-level import
        monkeypatch.setattr(reaper_handler, 'GRACE_PERIOD_HOURS', 168)

        # Created 100 hours ago (within 168h grace period)
        created_at = now - timedelta(hours=100)

        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=created_at,
            now=now,
            running_tasks=running_tasks_empty
        )

        assert result['is_stale'] is False
        assert 'within grace period' in result['reason']
        assert result['running_tasks'] == 0

    def test_tasks_for_different_investigation_dont_affect_staleness(self, now, running_tasks_no_match, monkeypatch):
        """Running tasks for different investigation should not prevent staleness."""
        # Patch GRACE_PERIOD_HOURS constant using the module-level import
        monkeypatch.setattr(reaper_handler, 'GRACE_PERIOD_HOURS', 168)

        # Created 200 hours ago
        created_at = now - timedelta(hours=200)

        result = reaper_handler.is_investigation_stale(
            cluster_id='test-cluster',
            investigation_id='test-inv',
            access_point_created_at=created_at,
            now=now,
            running_tasks=running_tasks_no_match  # Tasks for different investigation
        )

        # Should be stale because tasks don't match this investigation
        assert result['is_stale'] is True
        assert result['running_tasks'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
