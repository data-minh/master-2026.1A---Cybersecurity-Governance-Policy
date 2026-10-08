import os

import pytest


@pytest.fixture
def redis_test_url():
    return os.getenv("VTS_TEST_REDIS_URL", "redis://localhost:16379/15")
