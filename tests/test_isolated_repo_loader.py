from tests._isolated_repo_loader import TESTS_ROOT, load_test_module


def test_load_test_module_imports_integration_conftest():
    mod = load_test_module("integration/conftest.py", module_name="_integration_conftest_loader_test")

    assert mod.__file__ == str(TESTS_ROOT / "integration" / "conftest.py")
    assert hasattr(mod, "IDARunner")
    assert callable(mod.ida_is_available)
