# Post-Quantum Cryptography Research Project
This repository contains C and C++ code for the research project, Developer-centred security challenges in post-quantum cryptographic APIs. The project was done at the IT University in Copenhagen under supervision of Oksana Kulyk in 2025. Find the paper in the repository (Report.pdf).

The following cryptographic APIs were used

- Wolfcrypt
- botan
- mlkem-native
- liboqs

Below is a simple guide on how to install the cryptographic APIs and code examples.


## Prerequisites
Before you begin, ensure you have the following tools installed on your system:

- Git
- CMake (3.20 or higher): For building the project.
- Make
- A C++ Compiler: (e.g., GCC, Clang) supporting C++20.
- Python 3: Required for configuring Botan.
- autoreconf: (Part of autotools) Required for wolfSSL's autogen.sh.
- nproc: (Linux/macOS) Used by the install script for parallel compilation.

## Getting Started
Follow these steps to set up the project and install the required cryptographic libraries.

1. Clone the Repository

First, clone this project repository to local machine:

```bash
git clone https://github.itu.dk/jave/Post_quantum_cryptography_research_project.git
cd Post_quantum_cryptography_research_project
```

2. Install Crypto APIs

Run the installation script from project root directory:

```bash
chmod +x installCryptoAPI.sh
./installCryptoAPI.sh
```

What the script does:

It creates a directory $HOME/crypto_libs (if it doesn't exist).

Inside $HOME/crypto_libs, it clones each required API into its own subdirectory (e.g., liboqs, liboqs-cpp, wolfssl, botan, mlkem-native, ml-kem, ml-dsa).

For each API that requires building and installation (liboqs, liboqs-cpp, wolfssl, botan), it compiles the library and installs its headers and binaries into a dedicated install subdirectory within that API's cloned folder (e.g., $HOME/crypto_libs/liboqs/install).

pq-code-package/mlkem-native is cloned and built, with its static library residing in mlkem-native/test/build.

itzmeanjan/ml-kem and itzmeanjan/ml-dsa are header-only libraries, so they are just cloned.

3. Configure the Project (CMake / CLion)

This project uses CMake to manage its build process. The CMakeLists.txt file is configured to find the libraries installed by the installCryptoAPI.sh script, assuming they are located under $HOME/crypto_libs.

## If you are using CLion:

1. Open the Post_quantum_cryptography_research_project directory in CLion.

2. CLion should automatically detect the CMakeLists.txt and attempt to configure the project.

3. Crucially, after running the installCryptoAPI.sh script, you must force CLion to re-read its CMake configuration:

    - Go to Tools -> CMake -> Reset Cache and Reload Project.

    - If you still encounter issues, try File -> Invalidate Caches / Restart....

## If you are building from the command line:

1. Create a build directory:

```bash
mkdir build
cd build
```

2. Run CMake to configure the project. The CMakeLists.txt expects the CRYPTO_LIBS_ROOT variable to be set to $HOME/crypto_libs. Since it's set as a default in the CMakeLists.txt itself, you typically don't need to pass it via -D unless your crypto_libs directory is in a non-standard location.

```bash
cmake ..
```

(If your crypto_libs is not in $HOME/crypto_libs, you can specify it: cmake .. -DCRYPTO_LIBS_ROOT=/path/to/your/crypto_libs)

## Build the project:

```bash
cmake --build .
# Or, on Unix-like systems:
# make
```

## Expected Directory Structure
After running the installCryptoAPI.sh script, the $HOME/crypto_libs directory should be similar to this structure:

```python
$HOME/crypto_libs/
├── botan/
│   ├── build/
│   └── install/
├── liboqs/
│   ├── build/
│   └── install/
├── liboqs-cpp/
│   ├── build/
│   └── install/
├── ml-dsa/         (Header-only)
│   └── include/
├── ml-kem/         (Header-only)
│   └── include/
├── mlkem-native/
│   └── test/
│       └── build/  (Contains libmlkem*.a)
└── wolfssl/
    └── install/
```
