import json

from ida_pro_mcp.host.server.server_runtime import ida_child_environment


def test_ida_child_environment_drops_provider_credentials_and_config(monkeypatch):
    monkeypatch.setenv("IDA_MCP_INTELLIGENCE_MODE", "jev")
    monkeypatch.setenv("IDA_MCP_CUSTOM_API_KEY_ENV", "VENDOR_TOKEN")
    monkeypatch.setenv("IDA_MCP_JEV_MODEL", "jev-latest")
    monkeypatch.setenv("TYPESAFE_API_KEY", "secret-one")
    monkeypatch.setenv("TYPESAFE_API_KEY_FILE", "/tmp/jev-key")
    monkeypatch.setenv("VENDOR_TOKEN", "secret-two")
    monkeypatch.setenv("CUSTOM_PROVIDER_API_KEY", "secret-three")
    monkeypatch.setenv("GEMINI_API_KEY", "retired-secret")
    parent = {
        "PATH": "/usr/bin",
        "IDA_MCP_PORT": "0",
        "IDA_MCP_INTELLIGENCE_MODE": "jev",
        "IDA_MCP_INTELLIGENCE_CONFIG": "/tmp/provider.json",
        "IDA_MCP_CUSTOM_API_KEY_ENV": "VENDOR_TOKEN",
        "IDA_MCP_JEV_MODEL": "jev-latest",
        "TYPESAFE_API_KEY": "secret-one",
        "TYPESAFE_API_KEY_FILE": "/tmp/jev-key",
        "VENDOR_TOKEN": "secret-two",
        "CUSTOM_PROVIDER_API_KEY": "secret-three",
        "GEMINI_API_KEY": "retired-secret",
    }

    child = ida_child_environment(parent)

    assert child["PATH"] == "/usr/bin"
    assert child["IDA_MCP_PORT"] == "0"
    for name in (
        "IDA_MCP_INTELLIGENCE_MODE",
        "IDA_MCP_INTELLIGENCE_CONFIG",
        "IDA_MCP_CUSTOM_API_KEY_ENV",
        "IDA_MCP_JEV_MODEL",
        "TYPESAFE_API_KEY",
        "TYPESAFE_API_KEY_FILE",
        "VENDOR_TOKEN",
        "CUSTOM_PROVIDER_API_KEY",
        "GEMINI_API_KEY",
    ):
        assert name not in child


def test_ida_child_environment_drops_custom_secret_named_in_provider_config(monkeypatch, tmp_path):
    config_path = tmp_path / "intelligence.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "custom",
                "provider": {
                    "id": "operator-provider",
                    "base_url": "https://provider.example.test",
                    "allowed_origins": ["https://provider.example.test"],
                    "auth": {"source": "env", "env_var": "CUSTOM_INTEGRATION_TOKEN"},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("IDA_MCP_INTELLIGENCE_MODE", "custom")
    monkeypatch.setenv("IDA_MCP_INTELLIGENCE_CONFIG", str(config_path))
    monkeypatch.setenv("CUSTOM_INTEGRATION_TOKEN", "secret")

    child = ida_child_environment(
        {
            "IDA_MCP_INTELLIGENCE_CONFIG": str(config_path),
            "CUSTOM_INTEGRATION_TOKEN": "secret",
            "IDA_MCP_PORT": "0",
        }
    )

    assert "CUSTOM_INTEGRATION_TOKEN" not in child
    assert "IDA_MCP_INTELLIGENCE_CONFIG" not in child
    assert child["IDA_MCP_PORT"] == "0"
