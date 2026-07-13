from __future__ import annotations

from ida_pro_mcp.host.intelligence.embeddings import build_decomp_document


def test_decomp_document_is_bounded_and_preserves_whole_function_signals():
    middle = "\n".join(f"v{i} = helper_{i}(v{i - 1});" for i in range(1, 400))
    pseudocode = f'''int decode_payload(char *buffer) {{
{middle}
send_to_command_server(buffer, "TAIL_C2_MARKER");
return 0xDEADBEEF;
}}'''

    document = build_decomp_document("decode_payload", pseudocode, max_chars=2048)

    assert len(document) <= 2048
    assert "decode_payload" in document
    assert "send_to_command_server" in document
    assert "TAIL_C2_MARKER" in document
    assert "0xDEADBEEF" in document


def test_short_decomp_document_keeps_the_complete_pseudocode():
    pseudocode = 'int save_file(void) { return WriteFile(handle, "report.bin", 10); }'

    document = build_decomp_document("save_file", pseudocode, max_chars=4096)

    assert document == f"function: save_file\n{pseudocode}"


def test_decomp_document_translates_code_operators_to_behavior_terms():
    pseudocode = "int pick(int value) { state += table[value % 96]; return state; }"

    document = build_decomp_document("pick", pseudocode, max_chars=1024)

    assert "operations: modulo array_index state_update" in document
    assert pseudocode in document
