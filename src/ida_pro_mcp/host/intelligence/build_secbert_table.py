"""Build a SecBERT-backed static token embedding table.

The output is a single ``.npz`` file stored at
``~/.ida-pro-mcp/secbert_table_v1.npz`` containing:

* ``tokens``  : ``object`` array of byte strings (the corpus vocabulary)
* ``vectors`` : ``float32`` array of shape ``(V, 768)`` (SecBERT hidden size)

The runtime :class:`SecBertStaticEmbedder` in
:mod:`ida_pro_mcp.host.intelligence.core` reads this file and projects
unknown tokens into the same 768-D space using a deterministic
hash-bucketed fallback (so the embedder can run without a torch model
at runtime — only the table is needed).

This is a build-time tool, not runtime. Run once after
``download_bron_corpus`` to materialize the table, then commit/ship the
``.npz`` if desired. If the file is missing, the runtime falls back to
TF-IDF automatically.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.config import _default_runtime_dir  # noqa: E402

DEFAULT_MODEL = "jackaduma/SecBERT"
DEFAULT_OUTPUT = "secbert_table_v1.npz"
DEFAULT_MAX_TOKENS = 80_000
BATCH_SIZE = 32
MAX_SEQ_LEN = 64


def _output_path() -> Path:
    return Path(_default_runtime_dir()) / DEFAULT_OUTPUT


def _security_tokenize(text: str) -> list[str]:
    """Tokenization for security/corpus text. Splits on non-alphanumeric
    boundaries, drops very short tokens, lowercases."""
    out: list[str] = []
    for raw in re.split(r"[^A-Za-z0-9_\-\.]+", str(text or "")):
        if not raw:
            continue
        low = raw.lower()
        if len(low) < 2 or len(low) > 32:
            continue
        if low.isdigit():
            continue
        out.append(low)
    return out


def collect_corpus_texts(corpus: object | None = None) -> Iterable[str]:
    """Yield raw text lines for embedding. Tries the loaded threat corpus
    first, then falls back to a built-in seed list."""
    if corpus is not None:
        for entry in getattr(corpus, "cwe", []) or []:
            text = " ".join(
                str(p) for p in (
                    entry.get("name"),
                    entry.get("description"),
                    " ".join(entry.get("aliases") or []),
                ) if p
            )
            if text.strip():
                yield text
        for entry in getattr(corpus, "attack_patterns", []) or []:
            text = " ".join(
                str(p) for p in (
                    entry.get("name"),
                    entry.get("description"),
                ) if p
            )
            if text.strip():
                yield text
        for entry in (getattr(corpus, "malware", []) or [])[:2000]:
            text = " ".join(
                str(p) for p in (
                    entry.get("name"),
                    entry.get("description"),
                    " ".join(entry.get("aliases") or []),
                ) if p
            )
            if text.strip():
                yield text
        for entry in (getattr(corpus, "intrusion_sets", []) or [])[:500]:
            text = " ".join(
                str(p) for p in (
                    entry.get("name"),
                    entry.get("description"),
                    " ".join(entry.get("aliases") or []),
                ) if p
            )
            if text.strip():
                yield text
        for entry in (getattr(corpus, "tools", []) or [])[:500]:
            text = " ".join(
                str(p) for p in (
                    entry.get("name"),
                    entry.get("description"),
                ) if p
            )
            if text.strip():
                yield text


# Built-in seed list — used when no corpus is available. Covers core RE
# and security vocabulary so the table is useful even before the user
# downloads the BRON corpus.
SEED_SECURITY_TEXTS: list[str] = (
    "buffer overflow heap stack out-of-bounds write read memory corruption",
    "use after free dangling pointer double free heap spray",
    "format string vulnerability printf sprintf vsprintf",
    "command injection shell system execve popen posix spawn",
    "sql injection database query parameter sanitization",
    "cross-site scripting xss reflected stored dom based",
    "race condition time-of-check time-of-use toctou",
    "integer overflow signedness truncation underflow",
    "path traversal directory traversal dot dot slash back",
    "cryptographic weakness weak algorithm des md5 rc4",
    "advanced encryption standard aes block cipher mode",
    "secure hash algorithm sha-1 sha-256 sha-3 message digest",
    "rsa elliptic curve diffie-hellman key exchange",
    "public key infrastructure certificate authority x509 pki",
    "transport layer security tls ssl handshake renegotiation",
    "ransomware encryption bitcoin payment decryptor",
    "remote access trojan rat command and control c2 beacon",
    "spear phishing email attachment malicious document macro",
    "credential dumping mimikatz lsass sam database",
    "lateral movement pass-the-hash pass-the-ticket kerberos",
    "privilege escalation sudo uac setuid capability",
    "persistence registry run key scheduled task service",
    "process injection reflective dll hollowing apc",
    "anti-debugging anti-vm sandbox evasion check",
    "obfuscation packer crypter themida vmprotect upx",
    "shellcode payload exploit zero-day nday",
    "heap spray nop sled rop return oriented programming",
    "rop chain gadget stack pivot jop cop",
    "windows ntdll kernel32 advapi32 wininet winhttp",
    "linux glibc posix syscall read write recv send",
    "network socket tcp udp http https dns",
    "firewall intrusion detection system ids ips",
    "vulnerability cve cvss score exploit mitigation",
    "common weakness enumeration cwe buffer copy",
    "attack pattern mitre att&ck technique tactic procedure",
    "initial access execution persistence defense evasion",
    "credential access discovery lateral movement collection",
    "exfiltration impact command and control",
    "scada plc hmi industrial control system",
    "firmware embedded iot mcu bootloader u-boot",
    "uart spi i2c jtag swd debug interface",
    "memory mapped io mmio direct register access",
    "dma direct memory access bus master peripheral",
    "interrupt service routine isr vector table",
    "real-time operating system rtos freertos vxworks",
    "arm cortex-m risc-v mips avr xtensa",
    "trustzone secure world non-secure world",
    "bootrom secure boot verified boot chain of trust",
    "side channel timing power analysis cache",
    "speculative execution meltdown spectre bounds check bypass",
    "rowhammer bit flip dram disturbance error",
    "fuzzing libfuzzer afl honggfuzz coverage guided",
    "symbolic execution klee angr mayhem concolic",
    "taint analysis flow sensitive context sensitive",
    "static analysis data flow control flow graph",
    "decompilation disassembly binary reverse engineering",
    "anti-reversing control flow flattening opaque predicate",
    "string obfuscation xor base64 stack string",
    "api hashing dynamic api resolution",
    "process hollowing process doppelganging herpaderping",
    "image file execution options ifeo debugger",
    "com hijacking com object persistence",
    "wmi event subscription persistence",
    "bitsadmin download cradle",
    "powershell encoded command obfuscation bypass",
    "scheduled task xml trigger persistence",
    "service failure actions recovery reset",
    "registry persistence run key runonce startup",
    "boot execute registry key bootup",
    "appinit dll lsa security package",
    "winlogon notify",
    "userinit shell",
    "ifeo silent process exit",
    "com object hijacking",
    "scheduled task backdoor",
    "mshta javascript protocol handler",
    "rundll32 dll export",
    "regsvr32 sct file",
    "certutil download",
    "bitsadmin transfer",
    "certreq download",
    "wmic process call create",
    "forfiles command execution",
    "cmstp install",
    "msbuild inline task",
    "installutil uninstall",
    "mshta hta",
    "control panel applet",
    "screensaver abuse",
    "winexe service install",
    "psexec lateral",
    "wmi event subscription persistence permanent",
    "registry autorun keys",
    "userland rootkit hooking",
    "kernel rootkit driver load",
    "bootkit mbr modification",
    "file system filter driver minifilter",
    "network driver winsock lsp",
    "ssdt hook service descriptor table",
    "iat import address table patching",
    "inline hook trampoline",
    "api detour hook",
    "direct kernel object manipulation",
    "process security descriptor modification",
    "token impersonation primary token",
    "logon session manipulation",
    "kerberos ticket extraction",
    "lsass memory read",
    "sam database read",
    "security account manager",
    "active directory reconnaissance",
    "ldap enumeration",
    "smb enumeration",
    "rpc enumeration",
    "snmp enumeration",
    "network scanning port scan nmap masscan",
    "service discovery",
    "vulnerability scanning nessus openvas qualys",
    "exploit framework metasploit cobalt strike",
    "command and control framework covenant posh",
    "remote access tool sliver havoc bruteratel",
    "macros document office excel word",
    "dde dynamic data exchange",
    "template injection office",
    "exploit guard controlled folder access",
    "credential guard",
    "device guard",
    "hypervisor enforced code integrity hvci",
    "memory integrity",
    "kernel mode hardware enforced stack protection",
    "arbitrary code guard",
    "control flow guard cfg",
    "shadow stack",
    "intel cet control flow enforcement",
    "return flow guard",
    "acg arbitrary code guard",
    "smep smep supervisor mode execution prevention",
    "smap supervisor mode access prevention",
    "kaslr kernel address space layout randomization",
    "kpti kernel page table isolation",
    "amd sev secure encrypted virtualization",
    "intel tdx trust domain extensions",
    "confidential computing",
    "homomorphic encryption fhe",
    "secure multi-party computation smpc",
    "differential privacy",
    "zero knowledge proof zk snark",
    "post quantum cryptography",
    "lattice based cryptography kyber dilithium",
    "code based cryptography mceliece",
    "hash based signature slh-dsa sphincs",
    "multivariate polynomial cryptography rainbow",
    "isogeny based cryptography csidh",
    "quantum key distribution bb84 e91",
    "side channel attack fault injection glitch",
    "voltage glitching clock glitching em probe",
    "differential fault analysis",
    "power analysis dpa spa",
    "electromagnetic emanation tempest van eyck",
    "optical emission analysis",
    "cache timing attack",
    "spectre variant 1 2 3 4 meltdown",
    "foreshadow l1 terminal fault",
    "ridl rogue in flight data load",
    "fallout store-to-leak forwarding",
    "zombieload microarchitectural data sampling",
    "downfall gather data sampling",
    "reptar invalid processor trace decode",
    "augury microarchitectural",
    "sga spectre based",
    "data dependent prefetcher attack",
    "retbleed return address branch target",
    "branch history injection bhi",
    "cross thread return address prediction",
    "branch target injection spectre v2",
    "speculative store bypass",
    "speculative load hardening",
    "speculative execution attacks",
    "out of order execution side channel",
    "load value injection lvi",
    "lvi null pointer dereference",
    "lvi load value injection",
    "fault injection voltage clock",
    "rowhammer bit flip",
    "drama dram address remapping attack",
    "half double rowhammer",
    "samsung rsa key extraction rowhammer",
    "remote rowhammer",
    "netcat reverse shell",
    "bash reverse shell",
    "powershell reverse shell",
    "python reverse shell",
    "java reverse shell",
    "perl reverse shell",
    "ruby reverse shell",
    "c sharp reverse shell",
    "php reverse shell",
    "aspx reverse shell",
    "jsp reverse shell",
    "war reverse shell",
    "ear reverse shell",
    "hta reverse shell",
    "vba macro reverse shell",
    "office macro reverse shell",
    "word macro reverse shell",
    "excel macro reverse shell",
    "powerpoint macro reverse shell",
    "publisher macro reverse shell",
    "outlook macro reverse shell",
    "one note macro reverse shell",
    "mshta reverse shell",
    "regsvr32 reverse shell",
    "rundll32 reverse shell",
    "certutil reverse shell",
    "bitsadmin reverse shell",
    "wmic reverse shell",
    "msbuild reverse shell",
    "installutil reverse shell",
    "cmstp reverse shell",
    "odbcconf reverse shell",
    "wscript reverse shell",
    "cscript reverse shell",
    "msiexec reverse shell",
    "mshta url handler",
    "control panel applet abuse",
    "screensaver abuse",
    "remote services remote desktop protocol rdp",
    "vnc virtual network computing",
    "ssh secure shell",
    "telnet reverse shell",
    "smb server message block",
    "rpc remote procedure call",
    "winrm windows remote management",
    "wmi windows management instrumentation",
    "powershell remoting",
    "dcom distributed com",
    "wmi subscription persistence",
    "wmi event filter consumer",
    "wmi event consumer active script",
    "wmi event consumer command line",
    "wmi persistence",
    "task scheduler persistence",
    "service persistence",
    "registry run persistence",
    "registry runonce persistence",
    "registry userinit shell persistence",
    "registry winlogon shell persistence",
    "registry notify persistence",
    "registry appinit dll persistence",
    "registry ifeo debugger persistence",
    "registry silent process exit persistence",
    "registry com hijacking persistence",
    "registry scheduled task backdoor persistence",
    "registry file association hijacking persistence",
    "registry boot execute persistence",
    "registry lsa security package persistence",
    "registry network provider persistence",
    "registry print provider persistence",
    "registry time provider persistence",
    "registry wmi persistence",
    "registry bootup persistence",
    "registry session manager persistence",
    "registry subsystem persistence",
    "registry smb server persistence",
    "registry driver load persistence",
    "registry file system filter driver persistence",
    "registry minifilter persistence",
    "registry windows error reporting persistence",
    "registry application compatibility cache persistence",
    "registry shim database persistence",
    "registry app compat persistence",
    "registry bypass",
    "registry vulnerability",
    "registry hive",
    "registry key",
    "registry value",
    "registry transaction",
    "registry notification",
    "registry callback",
    "registry edit",
    "registry export",
    "registry import",
    "registry backup",
    "registry restore",
    "registry compare",
    "registry merge",
    "registry search",
    "registry replace",
    "registry delete",
    "registry load",
    "registry unload",
    "registry save",
    "security identifier sid",
    "access control list acl",
    "discretionary access control list dacl",
    "system access control list sacl",
    "security descriptor",
    "privilege escalation",
    "privilege abuse",
    "privilege check",
    "privilege adjustment",
    "privilege token",
    "impersonation token",
    "delegation token",
    "filtering token",
    "restricted token",
    "sandbox token",
    "low integrity level",
    "medium integrity level",
    "high integrity level",
    "system integrity level",
    "trusted installer",
    "nt authority system",
    "local system",
    "local service",
    "network service",
    "user account control uac",
    "bypass uac",
    "uac bypass",
    "fodhelper uac bypass",
    "computerdefaults uac bypass",
    "eventvwr uac bypass",
    "sdclt uac bypass",
    "diskcleanup uac bypass",
    "silentcleanup uac bypass",
    "ms-settings uac bypass",
    "wsreset uac bypass",
    "slui uac bypass",
    "easinvoker uac bypass",
    "perfcpl uac bypass",
    "colorcpl uac bypass",
    "sysprep uac bypass",
    "cliconfg uac bypass",
    "mstsc uac bypass",
    "cleanmgr uac bypass",
    "dccw uac bypass",
    "odbcad32 uac bypass",
    "dfrgui uac bypass",
    "lpksetup uac bypass",
    "mshta uac bypass",
    "wusa uac bypass",
    "msiexec uac bypass",
    "inprocserver32 uac bypass",
    "treatas uac bypass",
    "autoelevate uac bypass",
    "manifest uac bypass",
    "appcompat shim uac bypass",
    "com elevation moniker uac bypass",
    "script moniker uac bypass",
    "execution alias uac bypass",
    "windows sandbox",
    "windows defender",
    "windows defender atp",
    "windows defender smartscreen",
    "windows defender application control",
    "windows defender exploit guard",
    "windows defender credential guard",
    "windows defender application guard",
    "windows defender device guard",
    "windows defender system guard",
    "windows defender network protection",
    "windows defender web protection",
    "windows defender exploit protection",
    "windows defender controlled folder access",
    "windows defender ransomware protection",
    "windows defender attack surface reduction",
    "windows defender next gen protection",
    "microsoft defender for cloud",
    "microsoft defender for endpoint",
    "microsoft defender for identity",
    "microsoft defender for office",
    "microsoft defender for cloud apps",
    "microsoft defender for servers",
    "microsoft defender for storage",
    "microsoft defender for containers",
    "microsoft defender for iot",
    "microsoft sentinel",
    "microsoft intune endpoint protection",
    "microsoft intune app protection",
    "microsoft intune device compliance",
    "microsoft intune configuration",
    "microsoft intune windows autopilot",
    "active directory domain services",
    "active directory federation services",
    "active directory certificate services",
    "active directory rights management",
    "active directory lightweight directory",
    "active directory schema",
    "active directory domain controller",
    "active directory replication",
    "active directory topology",
    "active directory forest",
    "active directory tree",
    "active directory site",
    "active directory subnet",
    "active directory site link",
    "active directory site link bridge",
    "active directory partition",
    "active directory naming context",
    "active directory global catalog",
    "active directory operations master",
    "active directory fsmo",
    "active directory pdc emulator",
    "active directory rid master",
    "active directory infrastructure master",
    "active directory schema master",
    "active directory domain naming master",
    "active directory trust",
    "active directory transitive trust",
    "active directory shortcut trust",
    "active directory external trust",
    "active directory forest trust",
    "active directory realm trust",
    "active directory kerberos trust",
    "active directory ntlm trust",
    "active directory authentication",
    "active directory authorization",
    "active directory group policy",
    "active directory group policy object",
    "active directory organizational unit",
    "active directory container",
    "active directory built-in",
    "active directory users",
    "active directory computers",
    "active directory groups",
    "active directory service accounts",
    "active directory managed service accounts",
    "active directory group managed service accounts",
    "active directory fine grained password policy",
    "active directory password settings object",
    "active directory protected users",
    "active directory admin tiering",
    "active directory privileged identity management",
    "active directory authentication policy silo",
    "active directory claims",
    "active directory compound identity",
    "active directory kerberos arming",
    "active directory flexible single master operations",
)


def build_secbert_table(
    output_path: Path | None = None,
    *,
    model_name: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    corpus: object | None = None,
    verbose: bool = True,
) -> Path:
    """Download SecBERT, embed the security corpus, and persist the table.

    Returns the path to the saved ``.npz`` file. Requires ``transformers``
    and ``torch`` to be installed (build-time only).
    """
    try:
        import torch  # noqa: F401
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "build_secbert_table requires `transformers` and `torch`. "
            "Install with: pip install transformers torch --index-url "
            "https://download.pytorch.org/whl/cpu"
        ) from exc

    import numpy as np

    if output_path is None:
        output_path = _output_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    if verbose:
        print(f"[secbert-table] loading {model_name} …", flush=True)
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    model.eval()
    if hasattr(model, "to"):
        try:
            import torch as _torch
            model.to(_torch.device("cpu"))
        except Exception:
            pass
    if verbose:
        print("[secbert-table] tokenizing corpus …", flush=True)
    texts = list(collect_corpus_texts(corpus))
    texts.extend(SEED_SECURITY_TEXTS)
    # Collect unique tokens with frequency
    token_counts: dict = {}
    for text in texts:
        for t in _security_tokenize(text):
            token_counts[t] = token_counts.get(t, 0) + 1
    # Sort by frequency, take top N
    sorted_tokens = sorted(token_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if max_tokens and len(sorted_tokens) > max_tokens:
        sorted_tokens = sorted_tokens[:max_tokens]
    tokens = [t for t, _ in sorted_tokens]
    if not tokens:
        raise RuntimeError("No tokens to embed; corpus and seeds both empty.")
    if verbose:
        print(f"[secbert-table] embedding {len(tokens)} tokens …", flush=True)
    vectors = np.zeros((len(tokens), model.config.hidden_size), dtype=np.float32)
    with __import__("torch").no_grad():
        for batch_start in range(0, len(tokens), BATCH_SIZE):
            batch = tokens[batch_start:batch_start + BATCH_SIZE]
            encoded = tok(
                batch,
                padding=True,
                truncation=True,
                max_length=MAX_SEQ_LEN,
                return_tensors="pt",
            )
            outputs = model(**encoded)
            hidden = outputs.last_hidden_state  # (B, T, H)
            mask = encoded["attention_mask"].unsqueeze(-1).float()
            summed = (hidden * mask).sum(dim=1)
            counts = mask.sum(dim=1).clamp(min=1.0)
            mean = summed / counts
            mean = torch.nn.functional.normalize(mean, p=2, dim=1)
            vectors[batch_start:batch_start + len(batch)] = mean.cpu().numpy()
            if verbose and (batch_start // BATCH_SIZE) % 32 == 0:
                print(
                    f"[secbert-table]   embedded {min(batch_start + BATCH_SIZE, len(tokens))} / {len(tokens)}",
                    flush=True,
                )
    if verbose:
        print(f"[secbert-table] saving to {output_path} …", flush=True)
    # tokens stored as bytes to avoid np.object_ unicode gotchas
    token_bytes = np.asarray([t.encode("utf-8") for t in tokens], dtype=object)
    np.savez_compressed(
        output_path,
        tokens=token_bytes,
        vectors=vectors,
        model_name=model_name,
        hidden_size=int(model.config.hidden_size),
        n_tokens=int(len(tokens)),
        source_fingerprint=_source_fingerprint(token_counts),
    )
    elapsed = time.time() - start
    if verbose:
        print(
            f"[secbert-table] done: {len(tokens)} tokens, "
            f"hidden_size={model.config.hidden_size}, "
            f"output={output_path} ({output_path.stat().st_size // 1024} KB, "
            f"{elapsed:.1f}s)",
            flush=True,
        )
    return output_path


def _source_fingerprint(token_counts: dict) -> str:
    """Stable SHA-256 of the (token, count) tuples so a stale table can be
    detected and rebuilt."""
    import hashlib
    items = sorted(token_counts.items())
    h = hashlib.sha256()
    for t, c in items:
        h.update(t.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(c).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()[:16]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"HuggingFace model id (default: {DEFAULT_MODEL})")
    parser.add_argument("--output", default=None,
                        help=f"Output .npz path (default: {_output_path()})")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS,
                        help=f"Max tokens to embed (default: {DEFAULT_MAX_TOKENS})")
    parser.add_argument("--corpus-cache", default=None,
                        help="Optional threat corpus cache path to seed vocabulary")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args(argv)
    corpus = None
    if args.corpus_cache:
        try:
            from ida_pro_mcp.host.intelligence.threat_corpus import load_corpus
            corpus = load_corpus(args.corpus_cache)
        except Exception as exc:
            print(f"[secbert-table] could not load corpus: {exc}", file=sys.stderr)
    output = Path(args.output) if args.output else _output_path()
    try:
        build_secbert_table(
            output_path=output,
            model_name=args.model,
            max_tokens=args.max_tokens,
            corpus=corpus,
            verbose=not args.quiet,
        )
    except Exception as exc:
        print(f"[secbert-table] FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
