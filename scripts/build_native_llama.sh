#!/usr/bin/env bash
# Build a trimmed llama.cpp — only what the in-process retrieval backend needs
# (ggml + ggml-cpu + llama + tokenizer).  No HTTP server, no UI, no tools,
# no vision/mtmd, no SSL/curl, no GPU backends.
#
# Produces static libraries the C++ driver (src/ida_pro_mcp/native) links
# against, giving one self-contained libmcp_llama.so.
#
# Usage:
#   LLAMA_CPP_SRC=/path/to/llama.cpp ./scripts/build_native_llama.sh [build_dir]
#   INSTALL_BIN=... ./scripts/build_native_llama.sh   # copy libmcp_llama.so here
# Defaults: source=/tmp/llama.cpp, build=/tmp/llama.cpp/build-mcp
set -euo pipefail

SRC="${LLAMA_CPP_SRC:-/tmp/llama.cpp}"
# The driver (mcp_llama.cpp) targets this exact llama.cpp commit.  The CI
# native-build workflow pins the same hash and verifies this default stays
# in sync — bump both together when the driver needs a newer llama.cpp.
LLAMA_CPP_COMMIT="${LLAMA_CPP_COMMIT:-99111b19ce482f081e92ec6c6cdbe6a4c815c515}"
BUILD="${1:-${SRC}/build-mcp}"
JOBS="${JOBS:-$(nproc)}"
INSTALL_BIN="${INSTALL_BIN:-}"
DRIVER="${DRIVER:-$(cd "$(dirname "$0")/../src/ida_pro_mcp/native" && pwd)}"

if [ ! -d "$SRC" ]; then
    echo "llama.cpp source not found at $SRC (set LLAMA_CPP_SRC)" >&2
    exit 1
fi
echo "llama.cpp source: $SRC"
echo "build dir:        $BUILD"

if [ -d "$SRC/.git" ]; then
    HEAD="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)"
    if [ -n "$HEAD" ] && [ "$HEAD" != "$LLAMA_CPP_COMMIT" ]; then
        echo "WARNING: llama.cpp HEAD is $HEAD" >&2
        echo "         pinned LLAMA_CPP_COMMIT is $LLAMA_CPP_COMMIT" >&2
        echo "         the driver targets the pinned commit; other versions may fail or misbehave." >&2
    fi
fi

cmake -S "$SRC" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DLLAMA_BUILD_APP=OFF \
    -DLLAMA_BUILD_SERVER=OFF \
    -DLLAMA_BUILD_EXAMPLES=OFF \
    -DLLAMA_BUILD_TOOLS=OFF \
    -DLLAMA_BUILD_UI=OFF \
    -DLLAMA_BUILD_MTMD=OFF \
    -DLLAMA_BUILD_TESTS=OFF \
    -DLLAMA_BUILD_COMMON=OFF \
    -DLLAMA_SUBPROCESS=OFF \
    -DLLAMA_OPENSSL=OFF \
    -DLLAMA_CURL=OFF \
    -DGGML_CPU=ON \
    -DGGML_OPENMP=ON \
    -DGGML_LLAMAFILE=ON \
    -DGGML_NATIVE=ON \
    -DGGML_BACKEND_DL=OFF \
    -DGGML_BUILD_EXAMPLES=OFF \
    -DGGML_BUILD_TESTS=OFF \
    -DGGML_VULKAN=OFF \
    -DGGML_CUDA=OFF \
    -DGGML_METAL=OFF \
    -DGGML_BLAS=OFF

cmake --build "$BUILD" -j "$JOBS"

echo "---"
ls -la "$BUILD"/src/libllama.a "$BUILD"/ggml/src/libggml*.a 2>/dev/null || true

# Build the C++ driver into one self-contained libmcp_llama.so (static
# llama.cpp folded in).  The linker group resolves the llama<->ggml cycle.
echo "building libmcp_llama.so ..."
g++ -std=c++17 -O3 -fPIC -shared -fvisibility=hidden \
    -I"$SRC/include" -I"$SRC/ggml/include" \
    -o "$BUILD/libmcp_llama.so" "$DRIVER/mcp_llama.cpp" \
    -Wl,--start-group \
    "$BUILD/src/libllama.a" \
    "$BUILD/ggml/src/libggml-cpu.a" \
    "$BUILD/ggml/src/libggml.a" \
    "$BUILD/ggml/src/libggml-base.a" \
    -Wl,--end-group \
    -fopenmp -lpthread -ldl -lrt -lm

# Build the minimal GGUF quantizer (Q8_0 -> Q4_K_M for faster CPU streaming).
echo "building mcp_quantize ..."
g++ -std=c++17 -O2 -o "$BUILD/mcp_quantize" "$DRIVER/mcp_quantize.cpp" \
    -I"$SRC/include" -I"$SRC/ggml/include" \
    -Wl,--start-group \
    "$BUILD/src/libllama.a" \
    "$BUILD/ggml/src/libggml-cpu.a" \
    "$BUILD/ggml/src/libggml.a" \
    "$BUILD/ggml/src/libggml-base.a" \
    -Wl,--end-group \
    -fopenmp -lpthread -ldl -lrt -lm

if [ -n "$INSTALL_BIN" ]; then
    mkdir -p "$INSTALL_BIN"
    cp "$BUILD/libmcp_llama.so" "$INSTALL_BIN/"
    cp "$BUILD/mcp_quantize" "$INSTALL_BIN/"
    echo "installed: $INSTALL_BIN/libmcp_llama.so $INSTALL_BIN/mcp_quantize"
fi
echo "driver ready: $BUILD/libmcp_llama.so"
echo "quantizer ready: $BUILD/mcp_quantize  (usage: mcp_quantize in.gguf out.gguf Q4_K_M [threads])"
