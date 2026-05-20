# workflow
- Commit and push periodically without asking for confirmation. Confidence: 0.85
- Run long-running tasks (tests, evals) in the background and keep working; do not monitor them. Confidence: 0.85
- Do not ask for permission or elevation; full access is granted. Confidence: 0.80
- Prefer integration tests that use actual IDA over LLM evals for catching infrastructure and tool bugs. Confidence: 0.70

# codebase
- The antigravity CLI binary is called "agy". Confidence: 0.70
- The secret key file is at .claude/secretkey.txt in the project root, not in home directory. Confidence: 0.75
