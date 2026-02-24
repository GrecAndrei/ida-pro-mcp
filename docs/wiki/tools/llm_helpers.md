# LLM_HELPERS Tool Manual

## What It Does
Builds compact, analysis-oriented summaries and guidance for LLM workflows: context windows, digests, progress tracking, next-step suggestions, and question routing.

## Actions
- `context_window`: Build token-budgeted context for one function.
- `function_digest`: One-line function summary (size/APIs/strings/prototype).
- `binary_digest`: Compact high-level binary overview.
- `explain_address`: Human-readable explanation of what lives at an address.
- `suggest_next`: Suggest next analysis targets from optional history.
- `progress_report`: Estimate analysis coverage from history list.
- `focus_area`: Score and rank high-value functions to inspect.
- `question_answer`: Keyword-routed binary Q/A from available DB facts.
- `guided_analysis`: Return suggested step-by-step analysis workflow.
- `cheatsheet`: Return command cheat sheet tailored by file type.

## Key Parameters
- `action`: One of the ten actions above.
- `addr`: Required for `context_window`, `function_digest`, `explain_address`.
- `query`: Required for `question_answer`; optional context topic elsewhere.
- `max_tokens`: Budget target for `context_window` (character budget derived from it).
- `limit`: Result cap for ranked/suggestion outputs.
- `history`: Comma-separated analyzed addresses used by `suggest_next` and `progress_report`.

## Examples
```python
llm_helpers(action="binary_digest")
llm_helpers(action="function_digest", addr="0x401000")
llm_helpers(action="context_window", addr="0x401000", max_tokens=3000)
llm_helpers(action="explain_address", addr="0x401123")
llm_helpers(action="suggest_next", history="0x401000,0x402100", limit=8)
llm_helpers(action="progress_report", history="0x401000,0x402100")
llm_helpers(action="focus_area", limit=10)
llm_helpers(action="question_answer", query="what network imports are present?")
llm_helpers(action="guided_analysis")
llm_helpers(action="cheatsheet")
```

## Failure Modes
- Missing required `addr`/`query` per action.
- Invalid addresses in `history` are skipped silently.
- Heuristic scoring/routing can be incomplete for stripped or unusual binaries.
- Some suggested downstream steps may depend on optional tools/actions in your environment.
