import pytest
from fakes import make_config


@pytest.fixture
def cfg(tmp_path):
    return make_config(tmp_path)
