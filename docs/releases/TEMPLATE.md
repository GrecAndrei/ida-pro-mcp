# IDA Pro MCP {VERSION}

{ONE_SENTENCE_CORE_VALUE_PROPOSITION}

### Highlights
- **{FEATURE_1_TITLE}**: {Concise description of the capability and impact}
- **{FEATURE_2_TITLE}**: {Concise description of the capability and impact}
- **{FEATURE_3_TITLE}**: {Concise description of the capability and impact}
- **{FEATURE_4_TITLE}**: {Concise description of the capability and impact}

---

### 🚀 Instant Auto-Installation (No Manual Extraction Needed)

#### Linux & macOS (One-Line Install)
```bash
curl -fsSL https://github.com/GrecAndrei/ida-pro-mcp/releases/download/{TAG}/install.sh | bash
```
*Or download `install.sh` from the release assets below and run `./install.sh`.*

#### Windows (One-Click Install)
Download **`install.bat`** from the release assets below and **double-click it**. It auto-detects Python, configures IDA Pro, sets up your AI coding tools, and installs skills automatically.

#### Standalone Executable
Download the native binary for your architecture from the release assets below (e.g. `ida-pro-mcp-installer-linux-x86_64`), make it executable (`chmod +x`), and run it directly.

---

### 📦 Manual / Offline Installation
If installing offline or in an air-gapped environment:
1. Download the `ida-pro-mcp-{VERSION}-bundle.tar.gz` (or `.zip`) from the assets below.
2. Extract the archive and execute:
   ```bash
   python install.py --auto
   ```

---

### 🔒 Verification & Provenance
Verify release integrity using the checksums manifest and GitHub provenance attestations:
```bash
sha256sum -c SHA256SUMS
gh attestation verify ida_pro_mcp-{VERSION}-py3-none-any.whl --repo GrecAndrei/ida-pro-mcp
```

---

### Links
- 📖 [Official Wiki & Documentation](https://github.com/GrecAndrei/ida-pro-mcp/wiki)
- 📋 [Operations Reference](docs/TOOLS_REFERENCE.md)
- 🛡️ [Safety & Mutation Policy](docs/guide/safety-model.md)
- 📝 [Full Changelog](CHANGELOG.md)
