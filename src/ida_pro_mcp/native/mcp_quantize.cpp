// mcp_quantize.cpp — minimal GGUF quantizer driver.
//
// Calls llama_model_quantize() against the same static llama.cpp libs the
// retrieval backend uses, so the Q4_K_M models can be produced without
// building the full llama-quantize tool (which pulls in llama-common).
//
// Usage: mcp_quantize <in.gguf> <out.gguf> [Q4_K_M|Q8_0] [threads]
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "llama.h"

int main(int argc, char ** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <in.gguf> <out.gguf> [Q4_K_M|Q8_0] [threads]\n", argv[0]);
        return 2;
    }
    const char * ftype_name = argc > 3 ? argv[3] : "Q4_K_M";
    int nthread = argc > 4 ? atoi(argv[4]) : 0;

    enum llama_ftype ftype;
    if (std::strcmp(ftype_name, "Q8_0") == 0) {
        ftype = LLAMA_FTYPE_MOSTLY_Q8_0;
    } else {
        ftype = LLAMA_FTYPE_MOSTLY_Q4_K_M;
    }

    llama_model_quantize_params qp = llama_model_quantize_default_params();
    qp.nthread = nthread;
    qp.ftype = ftype;
    qp.allow_requantize = true;

    const uint32_t rc = llama_model_quantize(argv[1], argv[2], &qp);
    if (rc != 0) {
        fprintf(stderr, "quantize failed with code %u\n", rc);
        return 1;
    }
    fprintf(stderr, "ok: %s -> %s (%s)\n", argv[1], argv[2], ftype_name);
    return 0;
}
