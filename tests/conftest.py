"""Shared test fixtures and configuration."""

import warnings

import pytest


@pytest.fixture(autouse=True)
def _suppress_asyncio_task_warnings():
    """Suppress 'Task was destroyed but it is pending' warnings in tests.

    These come from EventReporter._flush_loop when tests create a callback
    that calls _ensure_started() but don't fully shut down the event loop.
    Not a production concern — in production there's always a running loop.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*Task was destroyed.*")
        yield
