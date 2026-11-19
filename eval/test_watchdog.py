"""Hang protection: the per-alert time limit cannot be swallowed by 'except Exception', and says where it was."""
import signal
import time

import pytest

import worker


def test_overrun_is_not_swallowed_and_names_the_place():
    def stuck_in_a_tool():
        try:
            time.sleep(10)
        except Exception:
            return "swallowed"

    worker._hard_limit(1)
    try:
        with pytest.raises(worker.Overrun) as exc:
            stuck_in_a_tool()
    finally:
        signal.alarm(0)
    assert "stuck_in_a_tool" in str(exc.value)


def test_watchdog_waits_longer_than_one_investigation():
    assert worker.watchdog_limit() > worker.config.MAX_WALL_SECONDS + worker.config.LLM_TIMEOUT
