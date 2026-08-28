# Build libmcp_llama.so — the in-process retrieval backend.
#
# Links against a trimmed llama.cpp build (scripts/build_native_llama.sh).
# Point LLAMA_CPP_BUILD at that build tree. Example:
#
#   cmake -S src/ida_pro_mcp/native -B build/native -DLLAMA_CPP_BUILD=/path/to/llama.cpp/build-mcp
#   cmake --build build/native
#
# The output libmcp_llama.so is a single self-contained shared object (the
# llama.cpp static libs are folded in).  Only system libs (libgomp, libstdc++)
# remain.

cmake_minimum_required(VERSION 3.20)
project(mcp_llama LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT DEFINED LLAMA_CPP_BUILD OR LLAMA_CPP_BUILD STREQUAL "")
    message(FATAL_ERROR "Set -DLLAMA_CPP_BUILD=/path/to/llama.cpp/build-mcp")
endif()

# Headers live in the llama.cpp source tree.
get_filename_component(LLAMA_CPP_SRC "${LLAMA_CPP_BUILD}/.." ABSOLUTE)

set(MCP_LLAMA_SRCS mcp_llama.cpp)

add_library(mcp_llama SHARED ${MCP_LLAMA_SRCS})
target_include_directories(mcp_llama PRIVATE
    "${LLAMA_CPP_SRC}/include"
    "${LLAMA_CPP_SRC}/ggml/include"
)

# Static llama.cpp libs from the trimmed build tree.  They live in
# subdirectories (src/, ggml/src/), so search those too.
find_library(LLAMA_STATIC llama PATHS "${LLAMA_CPP_BUILD}" "${LLAMA_CPP_BUILD}/src" NO_DEFAULT_PATH)
find_library(GGML_STATIC ggml PATHS "${LLAMA_CPP_BUILD}" "${LLAMA_CPP_BUILD}/ggml/src" NO_DEFAULT_PATH)
find_library(GGML_BASE_STATIC ggml-base PATHS "${LLAMA_CPP_BUILD}" "${LLAMA_CPP_BUILD}/ggml/src" NO_DEFAULT_PATH)
find_library(GGML_CPU_STATIC ggml-cpu PATHS "${LLAMA_CPP_BUILD}" "${LLAMA_CPP_BUILD}/ggml/src" NO_DEFAULT_PATH)

if(NOT LLAMA_STATIC OR NOT GGML_STATIC OR NOT GGML_BASE_STATIC OR NOT GGML_CPU_STATIC)
    message(FATAL_ERROR "llama.cpp static libs not found in ${LLAMA_CPP_BUILD}. "
                        "Run scripts/build_native_llama.sh first.")
endif()

# Static llama <-> ggml have circular references; a linker group resolves them.
set(MCP_LLAMA_STATIC_LIBS
    "${LLAMA_STATIC}" "${GGML_CPU_STATIC}" "${GGML_STATIC}" "${GGML_BASE_STATIC}")
if(UNIX AND NOT APPLE)
    set(MCP_LLAMA_STATIC_LIBS -Wl,--start-group ${MCP_LLAMA_STATIC_LIBS} -Wl,--end-group)
endif()
target_link_libraries(mcp_llama PRIVATE ${MCP_LLAMA_STATIC_LIBS})

# OpenMP threadpool used by ggml-cpu.
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(mcp_llama PRIVATE OpenMP::OpenMP_CXX)
endif()

if(NOT MSVC)
    target_compile_options(mcp_llama PRIVATE -fvisibility=hidden -O3)
endif()

install(TARGETS mcp_llama LIBRARY DESTINATION bin)
