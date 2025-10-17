#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Define the root directory for all crypto libraries
CRYPTO_LIBS_ROOT="$HOME/crypto_libs"

# Helper function for colored output
info() {
    echo -e "\n\033[1;34m--- $1 ---\033[0m" # Blue color
}

error() {
    echo -e "\n\033[1;31mERROR: $1\033[0m" # Red color
    exit 1
}

check_command() {
    command -v "$1" >/dev/null 2>&1 || { error "Command '$1' is required but not installed. Aborting."; }
}

# --- 0. Prerequisites ---
info "Checking prerequisites..."
check_command "git"
check_command "cmake"
check_command "make"
check_command "autoreconf" # For wolfSSL's autogen.sh
check_command "nproc"      # For parallel make, if available

# Create the root directory for all crypto libraries
info "Creating root crypto libraries directory: $CRYPTO_LIBS_ROOT"
mkdir -p "$CRYPTO_LIBS_ROOT"

# Navigate to the root directory for cloning and building
cd "$CRYPTO_LIBS_ROOT" || error "Failed to change directory to $CRYPTO_LIBS_ROOT"

# --- 1. liboqs ---
info "Installing liboqs..."
if [ ! -d "liboqs" ]; then
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs
else
    info "liboqs directory already exists. Skipping clone, updating."
    cd liboqs && git pull && cd ..
fi
cd liboqs || error "Failed to change directory to liboqs"
mkdir -p build install # Create build and install directories inside liboqs
# Configure with the correct install prefix (relative to liboqs directory)
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build --parallel $(nproc)
cmake --build build --target install
cd .. # Go back to CRYPTO_LIBS_ROOT

# --- 2. liboqs-cpp ---
info "Installing liboqs-cpp..."
if [ ! -d "liboqs-cpp" ]; then
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs-cpp
else
    info "liboqs-cpp directory already exists. Skipping clone, updating."
    cd liboqs-cpp && git pull && cd ..
fi
cd liboqs-cpp || error "Failed to change directory to liboqs-cpp"
mkdir -p build install # Create build and install directories inside liboqs-cpp
# Configure with the correct install prefix (relative to liboqs-cpp directory)
cmake -S . -B build -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build --parallel $(nproc)
cmake --build build --target install
cd .. # Go back to CRYPTO_LIBS_ROOT

# --- 3. wolfSSL ---
info "Installing wolfSSL (wolfCrypt)..."
WOLFSSL_REPO="https://github.com/wolfSSL/wolfssl.git"
if [ ! -d "wolfssl" ]; then
    git clone --depth=1 "$WOLFSSL_REPO"
else
    info "wolfssl directory already exists. Skipping clone, updating."
    cd wolfssl && git pull && cd ..
fi
cd wolfssl || error "Failed to change directory to wolfssl"
if [ -e "install" ]; then # Check if 'install' exists as a file or directory
    info "Removing existing 'install' directory/file in wolfssl..."
    rm -rf install
fi
mkdir -p install
./autogen.sh # Required to generate the configure script
# Configure with the correct install prefix and enable post-quantum, linking to liboqs
# The --with-liboqs path now correctly points to the liboqs installation within CRYPTO_LIBS_ROOT
./configure --prefix="$PWD/install" \
            --enable-kyber \
            --enable-dilithium
make -j$(nproc) # Use all available cores for make
make install
cd .. # Go back to CRYPTO_LIBS_ROOT

# --- 4. Botan 3 ---
info "Installing Botan 3..."
BOTAN_REPO="https://github.com/randombit/botan.git"
if [ ! -d "botan" ]; then
    git clone --depth=1 "$BOTAN_REPO" botan # Clone into 'botan' directory
else
    info "botan directory already exists. Skipping clone, updating."
    cd botan && git pull && cd ..
fi
cd botan || error "Failed to change directory to botan"
mkdir -p build install # Create build and install directories inside botan
# Configure Botan 3 using its configure script
# Use --prefix to set the installation directory
# --with-build-dir is used by Botan to specify the build output directory
./configure.py --prefix="$PWD/install"
make -j$(nproc) # Use all available cores for make
make install
cd .. # Go back to CRYPTO_LIBS_ROOT

# --- 5. pq-code-package/mlkem-native ---
info "Cloning and building pq-code-package/mlkem-native..."
if [ ! -d "mlkem-native" ]; then
    git clone --depth=1 https://github.com/pq-code-package/mlkem-native
else
    info "mlkem-native directory already exists. Skipping clone, updating."
    cd mlkem-native && git pull && cd ..
fi
cd mlkem-native || error "Failed to change directory to mlkem-native"
make build
make test
cd .. # Go back to CRYPTO_LIBS_ROOT

# --- 6. itzmeanjan/ml-kem (Header-Only) ---
info "Cloning itzmeanjan/ml-kem (Header-Only)..."
if [ ! -d "ml-kem" ]; then
    git clone https://github.com/itzmeanjan/ml-kem.git --recurse-submodules
else
    info "ml-kem directory already exists. Skipping clone, updating."
    cd ml-kem && git pull && cd ..
fi
# No build or install steps needed for header-only library

# --- 7. itzmeanjan/ml-dsa (Header-Only) ---
info "Cloning itzmeanjan/ml-dsa (Header-Only)..."
if [ ! -d "ml-dsa" ]; then
    git clone https://github.com/itzmeanjan/ml-dsa.git --recurse-submodules
else
    info "ml-dsa directory already exists. Skipping clone, updating."
    cd ml-dsa && git pull && cd ..
fi
# No build or install steps needed for header-only library

info "All specified cryptographic libraries have been cloned and installed in: $CRYPTO_LIBS_ROOT"