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
// graph allocation.  Each handle owns one llama_context; llama_encode splits
// large batches into ubatches internally against that context's compute
// graph, which is allocated once and reused.

#include <cstdint>
#include <cstdlib>
#include <cstring>
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
    int            n_ctx = 2048;

    bool load(const char * model_path, int threads, int ctx_size) {
        n_threads = threads > 0 ? threads : 1;
        llama_model_params mparams = llama_model_default_params();
        mparams.n_gpu_layers = 0;  // CPU only in this pass
        model = llama_model_load_from_file(model_path, mparams);
        if (!model) return false;
        n_ctx = ctx_size > 0 ? ctx_size
                             : static_cast<int>(llama_model_n_ctx_train(model));
        if (n_ctx <= 0) n_ctx = 2048;
        llama_context_params cparams = llama_context_default_params();
        cparams.n_ctx = static_cast<uint32_t>(n_ctx);
        cparams.n_threads = n_threads;
        cparams.n_threads_batch = n_threads;
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

// Encode `seqs` (already tokenized) one sequence at a time through the KV
// cache and write each pooled embedding via `write(i, emb)`.
//
// Note on llama_encode vs llama_decode: llama_encode passes a null memory
// context into the graph builder, and decoder architectures (Qwen3) build
// attention-KV unconditionally — dereferencing it segfaults (verified).  The
// HTTP server avoids this by using llama_decode with the KV cache, so we do
// the same: one sequence per decode call, KV cache cleared first (public
// llama_memory_clear), giving each sequence the full n_ctx and no cross-seq
// interference.  This is the server's proven embedding path.
static int encode_one_shot(mcp_llama_common & h,
                           const std::vector<std::vector<llama_token>> & seqs,
                           int n,
                           const std::function<void(int, const float *)> & write) {
    llama_memory_t mem = llama_get_memory(h.ctx);
    for (int i = 0; i < n; ++i) {
        // Truncate over-long sequences to n_ctx instead of failing, matching
        // the HTTP server (it truncates each prompt to fit the context).
        // Keeping the LAST n_ctx tokens preserves the pooled output position.
        const auto & full = seqs[static_cast<size_t>(i)];
        if (full.empty()) return MCP_ERR_TOKENIZE;
        size_t start = full.size() > static_cast<size_t>(h.n_ctx)
                       ? full.size() - static_cast<size_t>(h.n_ctx) : 0;
        const std::vector<llama_token> toks(full.begin() + start, full.end());
        if (mem) llama_memory_clear(mem, true);

        llama_batch batch = llama_batch_init(static_cast<int32_t>(toks.size()), 0, 1);
        if (batch.token == nullptr) return MCP_ERR_ALLOC;
        for (size_t j = 0; j < toks.size(); ++j) {
            batch.token[j] = toks[j];
            batch.pos[j] = static_cast<llama_pos>(j);
            batch.n_seq_id[j] = 1;
            batch.seq_id[j][0] = 0;
            batch.logits[j] = (j == toks.size() - 1) ? 1 : 0;
        }
        batch.n_tokens = static_cast<int32_t>(toks.size());

        const int rc = llama_decode(h.ctx, batch);
        llama_batch_free(batch);
        if (rc != 0) {
            if (rc == 1) {  // could not find a KV slot — retry once after clear
                if (mem) llama_memory_clear(mem, true);
                llama_batch retry = llama_batch_init(static_cast<int32_t>(toks.size()), 0, 1);
                if (retry.token == nullptr) return MCP_ERR_ALLOC;
                for (size_t j = 0; j < toks.size(); ++j) {
                    retry.token[j] = toks[j];
                    retry.pos[j] = static_cast<llama_pos>(j);
                    retry.n_seq_id[j] = 1;
                    retry.seq_id[j][0] = 0;
                    retry.logits[j] = (j == toks.size() - 1) ? 1 : 0;
                }
                retry.n_tokens = static_cast<int32_t>(toks.size());
                const int rc2 = llama_decode(h.ctx, retry);
                llama_batch_free(retry);
                if (rc2 != 0) return MCP_ERR_ENCODE;
            } else {
                return MCP_ERR_ENCODE;
            }
        }
        // Read the pooled embedding BY SEQUENCE (not by token index): the
        // server reads llama_get_embeddings_seq first, and llama_get_embeddings_ith
        // returns the raw 1024-dim per-token hidden state, NOT the pooled
        // classifier output.  For a RANK-pooled reranker the seq embedding is
        // the 2-class softmax — score = seq[0]; for a LAST/MEAN-pooled embedder
        // it is the pooled vector.  Verified: ith[0] gives garbage (0.0 / raw
        // logits) while seq gives the server-matching scores (0.983 for a
        // relevant doc).
        const float * emb = llama_get_embeddings_seq(h.ctx, 0);
        if (!emb) {
            emb = llama_get_embeddings_ith(h.ctx, 0);
        }
        if (!emb) return MCP_ERR_NOMEMB;
        write(i, emb);
    }
    return MCP_OK;
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

    return encode_one_shot(h->base, seqs, n, [&](int i, const float * emb) {
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

    return encode_one_shot(h->base, seqs, n, [&](int i, const float * emb) {
        out[i] = emb[0];
    });
}

}  // extern "C"
