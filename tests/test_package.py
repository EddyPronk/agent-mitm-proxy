import agent_mitm_proxy


def test_version_comes_from_the_installed_metadata():
    assert agent_mitm_proxy.__version__ == "0.1.0"
