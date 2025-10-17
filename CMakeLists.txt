cmake_minimum_required(VERSION 3.30)
project(cryptoAPI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CRYPTO_PREFIX "$ENV{HOME}/crypto_libs" CACHE PATH "Path to the root directory where liboqs, liboqs-cpp, wolfSSL, Botan were installed.")
set(MLKEM_NATIVE_PARAM_SET "512" CACHE STRING "Parameter set for pq-code-package/mlkem-native (e.g., 512, 768, 1024). Must match the install script.")

# === liboqs path config ===
set(LIBOQS_ROOT "$ENV{HOME}/crypto_libs/liboqs/install")
set(LIBOQS-CPP_ROOT "$ENV{HOME}/crypto_libs/liboqs-cpp/include")

# === mlkem-native path config ===
set(MLKEM_NATIVE_ROOT "$ENV{HOME}/crypto_libs/mlkem-native")
set(MLKEM_ROOT "${MLKEM_NATIVE_ROOT}/mlkem")
set(MLKEM_TEST_ROOT "${MLKEM_NATIVE_ROOT}/test")

# === wolfSSL path config ===
set(WOLFSSL_ROOT "$ENV{HOME}/crypto_libs/wolfssl/install")

# === botan3 path config ===
set(BOTAN_ROOT "$ENV{HOME}/crypto_libs/botan")

# === ml-kem library path config ===
set(ML_KEM_LIB_ROOT "$ENV{HOME}/crypto_libs/ml-kem")

# === ml-dsa library path config ===
set(ML_DSA_LIB_ROOT "$ENV{HOME}/crypto_libs/ml-dsa")


# === Add mlkem-native ===
file(GLOB_RECURSE MLKEM_SOURCES
        "${MLKEM_ROOT}/*.c"
        "${MLKEM_ROOT}/**/*.c"
)

list(APPEND MLKEM_SOURCES "${MLKEM_TEST_ROOT}/notrandombytes/notrandombytes.c")
add_library(mlkem_native STATIC ${MLKEM_SOURCES})
target_compile_definitions(mlkem_native PRIVATE MLK_CONFIG_PARAMETER_SET=512)
target_include_directories(mlkem_native PUBLIC ${MLKEM_ROOT})
target_include_directories(mlkem_native PRIVATE ${MLKEM_TEST_ROOT}/notrandombytes)

find_package(Botan 3 REQUIRED)

# === Declare executable target ===
add_executable(cryptoAPI
        main.cpp
        Typestate.h
        "kyber examples/liboqs_ml_kem.h"
        "dilithium examples/liboqs_ml_dsa.h"
        "kyber examples/ml-kem_native.h"
        "kyber examples/wolfCrypt_ml_kem.h"
        "dilithium examples/wolfCrypt_ml_dsa.h"
        "dilithium examples/botan_ml_dsa.h"
        "kyber examples/botan_ml_kem.h"
        "sphincs examples/botan_slh_dsa.h"
        "kyber examples/abu_dhabi_ml_kem.h"
        "dilithium examples/abu_dhabi_ml_dsa.h"
        Halstead_metrics.h
)

# === Include paths for cryptoAPI target
target_include_directories(cryptoAPI PRIVATE
        ${LIBOQS_ROOT}/include
        ${LIBOQS-CPP_ROOT}
        ${MLKEM_ROOT}
        ${WOLFSSL_ROOT}/include
        ${ML_KEM_LIB_ROOT}/include
        ${ML_KEM_LIB_ROOT}/sha3/include
        ${ML_KEM_LIB_ROOT}/RandomShake/include
        ${ML_KEM_LIB_ROOT}/subtle/include
        ${ML_DSA_LIB_ROOT}/include
        ${ML_DSA_LIB_ROOT}/sha3/include
        ${ML_DSA_LIB_ROOT}/RandomShake/include
        #${BOTAN_ROOT}/build/include
)

# === Link and define for cryptoAPI target only
target_compile_definitions(cryptoAPI PRIVATE
        LIBOQS_CPP_VERSION="0.13.0"
        MLK_CONFIG_PARAMETER_SET=512
        MLK_CONFIG_API_PARAMETER_SET=MLK_CONFIG_PARAMETER_SET
        MLK_CONFIG_API_NAMESPACE_PREFIX=PQCP_MLKEM_NATIVE_MLKEM512
)

target_link_directories(cryptoAPI PRIVATE
        ${LIBOQS_ROOT}/lib
        ${WOLFSSL_ROOT}/lib
)

target_link_libraries(cryptoAPI PRIVATE
        oqs # liboqs
        mlkem_native
        wolfssl
        Botan::Botan
)