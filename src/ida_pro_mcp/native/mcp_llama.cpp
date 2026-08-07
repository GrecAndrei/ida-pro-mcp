// mcp_llama.cpp — in-process embedding + cross-encoder rerank via llama.cpp.
//
// A minimal C-ABI driver over the llama.cpp public API (llama.h).  Replaces
// the two full llama-server HTTP subprocesses the retrieval pipeline used to
// shell out to:
//
//   - mcp_embed_encode()  : pooled embeddings for N texts in ONE llama_encode
//                           batch.  Prefixes are applied Python-side (the
//                           profile owns query/document prefixes); C++ adds
//                           nothing but the model's add_bos flag.
//   - mcp_rerank_score()  : cross-encoder relevance scores for N (query, doc)
//                           pairs in ONE llama_encode batch.  The prompt uses
//                           the model's named "rerank" chat template (same as
//                           the server's format_prompt_rerank) and the score
//                           is pooled-embeddings[0] of the RANK-pooled
//                           classifier (same as the server's send_rerank).
//
// Everything lives in the calling process: no HTTP, no JSON, no per-request
// graph allocation.  Each handle owns one llama_context split into n_seq_max
// per-sequence KV streams; sequences are decoded in greedy batches (one
// llama_decode per batch, distinct seq_ids) against a compute graph allocated
// once and reused.  The KV cache is q8_0-quantized so a batch of 16 x 2048
// tokens fits in ~0.5 GiB.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <functional>
#include <new>
#include <string>
#include <vector>

#include "llama.h"

#if defined(_WIN32)
#define MCP_EXPORT __declspec(dllexport)
#else
#define MCP_EXPORT __attribute__((visibility("default")))
#endif

// ── error codes ────────────────────────────────────────────────────────────
enum {
    MCP_OK = 0,
    MCP_ERR_ALLOC = -1,       // out of memory
    MCP_ERR_LOAD = -3,        // model load failed
    MCP_ERR_CTX = -4,         // context creation failed
    MCP_ERR_INPUT = -5,       // null/invalid input
    MCP_ERR_TOKENIZE = -6,    // tokenization produced nothing
    MCP_ERR_ENCODE = -7,      // llama_encode failed
    MCP_ERR_NOMEMB = -8,      // embeddings not produced for a sequence
    MCP_ERR_OVERSIZE = -9,    // a single sequence exceeded n_ctx
};

static const char * mcp_err_str(int code) {
    switch (code) {
        case MCP_OK:           return "ok";
        case MCP_ERR_ALLOC:    return "out of memory";
        case MCP_ERR_LOAD:     return "model load failed";
        case MCP_ERR_CTX:      return "context creation failed";
        case MCP_ERR_INPUT:    return "invalid input";
        case MCP_ERR_TOKENIZE: return "tokenization produced no tokens";
        case MCP_ERR_ENCODE:   return "llama_encode failed";
        case MCP_ERR_NOMEMB:   return "no embeddings for sequence";
        case MCP_ERR_OVERSIZE: return "sequence exceeds context";
        default:               return "unknown";
    }
}

// ── common handle plumbing ─────────────────────────────────────────────────

struct mcp_llama_common {
    llama_model *  model = nullptr;
    llama_context *ctx  = nullptr;
    int            n_threads = 1;
    int            n_ctx = 2048;        // total KV cells
    int            n_ctx_seq = 2048;    // per-sequence token budget
    int            n_seq_max = 1;       // max sequences in one decode

    // Decode batch capacity.  We default to 16 sequences; each gets its own
    // KV stream (kv_unified=false), so n_ctx = n_ctx_seq * n_seq_max.  The KV
    // cache is quantized (q8_0) to halve the ~28 KiB/token a 0.6B Qwen3 model
    // would otherwise need in f16, letting a batch of 16 x 2048-token
    // sequences fit in ~0.5 GiB.
    static constexpr int   kSeqMaxDefault = 16;
    static constexpr int   kCtxSeqDefault = 2048;

    bool load(const char * model_path, int threads, int ctx_size) {
        n_threads = threads > 0 ? threads : 1;
        llama_model_params mparams = llama_model_default_params();
        mparams.n_gpu_layers = 0;  // CPU only in this pass
        model = llama_model_load_from_file(model_path, mparams);
        if (!model) return false;
        const int train_ctx = static_cast<int>(llama_model_n_ctx_train(model));
        // ctx_size is the PER-SEQUENCE token budget: the Python side passes
        // IDA_MCP_EMBED_CTX / IDA_MCP_RERANK_CTX, which are per-input
        // budgets.  With kv_unified=false each sequence owns its own KV
        // stream, so the total context is n_ctx_seq * n_seq_max.  The
        // previous interpretation (total ctx / n_seq_max) silently capped
        // every prompt at ctx_size/16 tokens — 128 for the 2048 default —
        // truncating embedding documents and rerank pairs to a fraction of
        // their intended signal.
        // MCP_NSEQ overrides the batch width (diagnostic / tuning knob).
        n_seq_max = kSeqMaxDefault;
        if (const char * e = getenv("MCP_NSEQ")) {
            const int v = atoi(e);
            if (v >= 1 && v <= 64) n_seq_max = v;
        }
        n_ctx_seq = ctx_size > 0 ? ctx_size : train_ctx;
        if (n_ctx_seq <= 0) n_ctx_seq = kCtxSeqDefault;
        if (n_ctx_seq < 64) n_ctx_seq = 64;          // never starve a sequence
        if (n_ctx_seq > kCtxSeqDefault) n_ctx_seq = kCtxSeqDefault;
        n_ctx = n_ctx_seq * n_seq_max;

        llama_context_params cparams = llama_context_default_params();
        cparams.n_ctx = static_cast<uint32_t>(n_ctx);
        cparams.n_seq_max = static_cast<uint32_t>(n_seq_max);
        cparams.n_threads = n_threads;
        cparams.n_threads_batch = n_threads;
        // Quantized KV halves the per-token KV footprint, the binding
        // constraint for batching many sequences into one decode on a
        // memory-tight box.  Scores are stable: KV quantization only rounds
        // the cache, the classifier head reads the pooled hidden state.
        cparams.type_k = GGML_TYPE_Q8_0;
        cparams.type_v = GGML_TYPE_Q8_0;
        // Must be set at context creation (not just llama_set_embeddings):
        // the server does the same and the graph/KV setup differs when it's
        // known up front.  Without it, encoding a Qwen3 embedding model
        // segfaults in build_input_k_idxs.
        cparams.embeddings = true;
        // pooling_type left UNSPECIFIED so the context adopts the model's
        // metadata pooling (qwen3.pooling_type: 3=LAST for the embedder,
        // 4=RANK for the reranker) — verified in llama-context.cpp.
        ctx = llama_init_from_model(model, cparams);
        if (!ctx) {
            llama_model_free(model);
            model = nullptr;
            return false;
        }
        llama_set_embeddings(ctx, true);
        return true;
    }

    ~mcp_llama_common() {
        if (ctx)  llama_free(ctx);
        if (model) llama_model_free(model);
    }
};

// ── tokenize helpers ───────────────────────────────────────────────────────

// Encode `seqs` (already tokenized) in greedy batches through the KV cache,
// writing each pooled embedding via `write(i, emb)`.
//
// Note on llama_encode vs llama_decode: llama_encode passes a null memory
// context into the graph builder, and decoder architectures (Qwen3) build
// attention-KV unconditionally — dereferencing it segfaults (verified).  The
// HTTP server avoids this by using llama_decode with the KV cache, so we do
// the same.  Where the previous driver decoded ONE sequence per llama_decode
// (clearing the whole KV first), this version packs many sequences into one
// decode with distinct seq_ids — each gets its own KV stream (n_ctx_seq
// tokens) — clearing the KV once per batch.
//
// Why batching wins: the decode graph is built over an ubatch of up to
// n_ubatch tokens, so a short sequence alone wastes most of a 512-token
// ubatch (weights streamed for 512 slots, ~150 computed).  Packing several
// sequences fills the ubatch and streams the weights far fewer times per
// useful token — the dominant CPU cost for a bandwidth-bound 0.6B Q8 model.
//
// Pooled embeddings are read per-sequence (llama_get_embeddings_seq) after
// the decode; llama.cpp fills embd_seq per ubatch and the last ubatch a
// sequence appears in wins, so a sequence spanning ubatches still yields its
// final pooled vector.  For Qwen3 the RANK pool is a LAST-token pool, and the
// hidden state of a sequence's last token is identical batched vs alone
// (attention is masked per KV stream), so scores match the HTTP path.
static int encode_batched(mcp_llama_common & h,
                          const std::vector<std::vector<llama_token>> & seqs,
                          int n,
                          const std::function<void(int, const float *)> & write) {
    llama_memory_t mem = llama_get_memory(h.ctx);

    // Cap every sequence to its KV stream budget, keeping the HEAD (query and
    // document prefix carry the rerank/embedding signal; the previous tail
    // truncation could drop the query for long docs).  The HTTP server also
    // keeps the head when a prompt overflows its slot.
    std::vector<std::vector<llama_token>> capped(static_cast<size_t>(n));
    std::vector<int> order;  // origin indices, longest first
    order.reserve(n);
    for (int i = 0; i < n; ++i) {
        const auto & full = seqs[static_cast<size_t>(i)];
        if (full.empty()) return MCP_ERR_TOKENIZE;
        const size_t budget = std::min(full.size(), static_cast<size_t>(h.n_ctx_seq));
        capped[static_cast<size_t>(i)].assign(full.begin(), full.begin() + budget);
        order.push_back(i);
    }
    // Longest-first packing keeps big sequences in the same batch and leaves
    // stragglers of similar small size to share a final decode.
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return capped[static_cast<size_t>(a)].size() > capped[static_cast<size_t>(b)].size();
    });

    std::vector<int> batch;  // origin indices in the current chunk

    auto flush_batch = [&]() -> int {
        if (batch.empty()) return MCP_OK;
        int32_t total = 0;
        for (int idx : batch) total += static_cast<int32_t>(capped[static_cast<size_t>(idx)].size());

        if (mem) llama_memory_clear(mem, true);
        llama_batch lb = llama_batch_init(total, 0, 1);
        if (lb.token == nullptr) return MCP_ERR_ALLOC;

        int32_t slot = 0;
        for (size_t k = 0; k < batch.size(); ++k) {
            const int        idx = batch[k];
            const auto &     toks = capped[static_cast<size_t>(idx)];
            const llama_seq_id sid = static_cast<llama_seq_id>(k);
            for (size_t j = 0; j < toks.size(); ++j, ++slot) {
                lb.token[slot] = toks[j];
                lb.pos[slot] = static_cast<llama_pos>(j);   // 0-based per stream
                lb.n_seq_id[slot] = 1;
                lb.seq_id[slot][0] = sid;
                lb.logits[slot] = (j == toks.size() - 1) ? 1 : 0;
            }
        }
        lb.n_tokens = total;

        int rc = llama_decode(h.ctx, lb);
        if (rc != 0) {
            if (rc == 1) {  // could not find a KV slot — retry once after clear
                if (mem) llama_memory_clear(mem, true);
                int32_t retry_total = 0;
                for (int idx : batch) retry_total += static_cast<int32_t>(capped[static_cast<size_t>(idx)].size());
                llama_batch rb = llama_batch_init(retry_total, 0, 1);
                if (rb.token == nullptr) {
                    llama_batch_free(lb);
                    return MCP_ERR_ALLOC;
                }
                slot = 0;
                for (size_t k = 0; k < batch.size(); ++k) {
                    const int    idx = batch[k];
                    const auto & toks = capped[static_cast<size_t>(idx)];
                    const llama_seq_id sid = static_cast<llama_seq_id>(k);
                    for (size_t j = 0; j < toks.size(); ++j, ++slot) {
                        rb.token[slot] = toks[j];
                        rb.pos[slot] = static_cast<llama_pos>(j);
                        rb.n_seq_id[slot] = 1;
                        rb.seq_id[slot][0] = sid;
                        rb.logits[slot] = (j == toks.size() - 1) ? 1 : 0;
                    }
                }
                rb.n_tokens = retry_total;
                const int rc2 = llama_decode(h.ctx, rb);
                llama_batch_free(rb);
                llama_batch_free(lb);
                if (rc2 != 0) return MCP_ERR_ENCODE;
            } else {
                llama_batch_free(lb);
                return MCP_ERR_ENCODE;
            }
        } else {
            llama_batch_free(lb);
        }

        // Read the pooled embedding per sequence.  The server reads
        // llama_get_embeddings_seq (pooled classifier / pooled vector); the
        // ith variant returns the raw per-token hidden state (garbage for
        // scoring).  Verified: ith[0] gave 0.0/raw logits, seq gave the
        // server-matching scores (0.983 for a relevant doc).
        for (size_t k = 0; k < batch.size(); ++k) {
            const float * emb = llama_get_embeddings_seq(h.ctx, static_cast<llama_seq_id>(k));
            if (!emb) return MCP_ERR_NOMEMB;
            write(batch[k], emb);
        }
        batch.clear();
        return MCP_OK;
    };

    for (int idx : order) {
        const int32_t len = static_cast<int32_t>(capped[static_cast<size_t>(idx)].size());
        if (!batch.empty() &&
            (static_cast<int>(batch.size()) >= h.n_seq_max ||
             len > h.n_ctx_seq)) {
            const int rc = flush_batch();
            if (rc != MCP_OK) return rc;
        }
        batch.push_back(idx);
    }
    return flush_batch();
}

static int mcp_tokenize(const llama_vocab * vocab, const std::string & text,
                        std::vector<llama_token> & out, bool add_special) {
    // parse_special=true matches the server's tokenize_input_subprompt(..., false,
    // true): chat-marker tokens like <|im_start|> / <|im_end|> must become their
    // special token ids or the rerank prompt (and any special-token prefixes)
    // tokenize to garbage and the classifier scores are meaningless.
    out.resize(text.size() + 8);
    int n = llama_tokenize(vocab, text.c_str(), static_cast<int32_t>(text.size()),
                           out.data(), static_cast<int32_t>(out.size()),
                           add_special, true);
    if (n < 0) {  // buffer too small
        out.resize(static_cast<size_t>(-n));
        n = llama_tokenize(vocab, text.c_str(), static_cast<int32_t>(text.size()),
                           out.data(), static_cast<int32_t>(out.size()),
                           add_special, true);
    }
    if (n <= 0) {
        out.clear();
        return MCP_ERR_TOKENIZE;
    }
    out.resize(static_cast<size_t>(n));
    return MCP_OK;
}

// ── embedding handle ───────────────────────────────────────────────────────

struct mcp_embed_handle {
    mcp_llama_common base;
    int dim = 0;

    bool load(const char * model_path, int threads, int ctx_size) {
        if (!base.load(model_path, threads, ctx_size)) return false;
        dim = static_cast<int>(llama_model_n_embd_out(base.model));
        return true;
    }
};

extern "C" {

MCP_EXPORT const char * mcp_llama_version(void) {
    // llama.h has no version macro; identify the source commit this driver
    // targets (the llama.cpp checkout it was built against).
    return "llama.cpp 99111b1 / mcp_llama 1";
}

MCP_EXPORT const char * mcp_err_message(int code) {
    return mcp_err_str(code);
}

// ── embed ──────────────────────────────────────────────────────────────────

MCP_EXPORT mcp_embed_handle * mcp_embed_new(const char * model_path,
                                            int n_threads, int n_ctx) {
    if (!model_path) return nullptr;
    mcp_embed_handle * h = new (std::nothrow) mcp_embed_handle();
    if (!h) return nullptr;
    if (!h->load(model_path, n_threads, n_ctx)) {
        delete h;
        return nullptr;
    }
    return h;
}

MCP_EXPORT void mcp_embed_free(mcp_embed_handle * h) { delete h; }

MCP_EXPORT int mcp_embed_dim(const mcp_embed_handle * h) {
    return h ? h->dim : 0;
}

// Encodes `n` texts into `out` (caller-allocated, n * dim floats, row-major).
// Prefixes are the caller's responsibility (the MCP profile applies its
// query/document prefixes before this call, same as the HTTP path does).
MCP_EXPORT int mcp_embed_encode(mcp_embed_handle * h,
                                const char * const * texts,
                                int n,
                                float * out) {
    if (!h || !texts || !out || n <= 0) return MCP_ERR_INPUT;
    const llama_vocab * vocab = llama_model_get_vocab(h->base.model);

    std::vector<std::vector<llama_token>> seqs(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        if (!texts[i]) return MCP_ERR_INPUT;
        int rc = mcp_tokenize(vocab, texts[i], seqs[static_cast<size_t>(i)],
                              llama_vocab_get_add_bos(vocab));
        if (rc != MCP_OK) return rc;
        if (seqs[static_cast<size_t>(i)].empty()) return MCP_ERR_TOKENIZE;
    }

    return encode_batched(h->base, seqs, n, [&](int i, const float * emb) {
        std::memcpy(out + static_cast<size_t>(i) * h->dim, emb,
                    static_cast<size_t>(h->dim) * sizeof(float));
    });
}

// ── rerank ─────────────────────────────────────────────────────────────────

struct mcp_rerank_handle {
    mcp_llama_common base;

    bool load(const char * model_path, int threads, int ctx_size) {
        return base.load(model_path, threads, ctx_size);
    }
};

MCP_EXPORT mcp_rerank_handle * mcp_rerank_new(const char * model_path,
                                              int n_threads, int n_ctx) {
    if (!model_path) return nullptr;
    mcp_rerank_handle * h = new (std::nothrow) mcp_rerank_handle();
    if (!h) return nullptr;
    if (!h->load(model_path, n_threads, n_ctx)) {
        delete h;
        return nullptr;
    }
    return h;
}

MCP_EXPORT void mcp_rerank_free(mcp_rerank_handle * h) { delete h; }

// Build the (query, doc) pair token sequence exactly like the server's
// format_prompt_rerank(): prefer the model's named "rerank" chat template
// with {query}/{document} substitution; fall back to bos/sep/eos framing.
static int build_rerank_prompt(const mcp_rerank_handle * h,
                               const llama_vocab * vocab,
                               const std::string & query,
                               const std::string & doc,
                               std::vector<llama_token> & out) {
    const char * tpl = llama_model_chat_template(h->base.model, "rerank");
    if (tpl) {
        std::string p = tpl;
        auto replace_all = [&p](const std::string & from, const std::string & to) {
            if (from.empty()) return;
            size_t pos = 0;
            while ((pos = p.find(from, pos)) != std::string::npos) {
                p.replace(pos, from.size(), to);
                pos += to.size();
            }
        };
        replace_all("{query}", query);
        replace_all("{document}", doc);
        return mcp_tokenize(vocab, p, out, false);
    }

    // Fallback without a rerank template (the Qwen3 GGUF carries one, so this
    // is belt-and-suspenders): query + doc framed with bos/eos/sep tokens.
    std::vector<llama_token> q;
    std::vector<llama_token> d;
    int rc = mcp_tokenize(vocab, query, q, false);
    if (rc != MCP_OK) return rc;
    rc = mcp_tokenize(vocab, doc, d, false);
    if (rc != MCP_OK) return rc;

    llama_token eos = llama_vocab_eos(vocab);
    if (eos == LLAMA_TOKEN_NULL) eos = llama_vocab_sep(vocab);

    out.clear();
    if (llama_vocab_get_add_bos(vocab)) {
        llama_token bos = llama_vocab_bos(vocab);
        if (bos != LLAMA_TOKEN_NULL) out.push_back(bos);
    }
    out.insert(out.end(), q.begin(), q.end());
    if (llama_vocab_get_add_eos(vocab) && eos != LLAMA_TOKEN_NULL) out.push_back(eos);
    if (llama_vocab_get_add_sep(vocab)) {
        llama_token sep = llama_vocab_sep(vocab);
        if (sep != LLAMA_TOKEN_NULL) out.push_back(sep);
    }
    out.insert(out.end(), d.begin(), d.end());
    if (llama_vocab_get_add_eos(vocab) && eos != LLAMA_TOKEN_NULL) out.push_back(eos);
    return MCP_OK;
}

// Scores `n` (query, doc) pairs.  out[i] receives pair i's relevance score
// (pooled embeddings[0] of the RANK-pooled classifier, matching the server).
MCP_EXPORT int mcp_rerank_score(mcp_rerank_handle * h,
                                const char * query,
                                const char * const * docs, int n,
                                float * out) {
    if (!h || !query || !docs || !out || n <= 0) return MCP_ERR_INPUT;
    const llama_vocab * vocab = llama_model_get_vocab(h->base.model);
    const std::string query_str = query;

    std::vector<std::vector<llama_token>> seqs(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        if (!docs[i]) return MCP_ERR_INPUT;
        int rc = build_rerank_prompt(h, vocab, query_str, docs[i],
                                     seqs[static_cast<size_t>(i)]);
        if (rc != MCP_OK) return rc;
        if (seqs[static_cast<size_t>(i)].empty()) return MCP_ERR_TOKENIZE;
    }

    return encode_batched(h->base, seqs, n, [&](int i, const float * emb) {
        out[i] = emb[0];
    });
}

}  // extern "C"
