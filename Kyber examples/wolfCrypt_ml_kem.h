#ifndef WOLFCRYPT_ML_KEM_H
#define WOLFCRYPT_ML_KEM_H

#include <iostream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <string>
#include <span>

#include "../Typestate.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

constexpr int SECURITY_LEVEL = WC_ML_KEM_512;

namespace WOLFCRYPT_ML_KEM {
  using PublicKey = std::vector<unsigned char>;
  using SecretKey = std::vector<unsigned char>;
  using Ciphertext = std::vector<unsigned char>;
  using SharedSecret = std::vector<unsigned char>;

  inline auto mlkem_key_deleter = [](MlKemKey* key) {
    if (key) {
      wc_MlKemKey_Free(key);
      delete key;
    }
  };

  using MlKemKeyPtr = std::shared_ptr<MlKemKey>;

  struct ML_KEM_DATA {
    MlKemKeyPtr key_ptr {};
    PublicKey public_key {};
    SecretKey secret_key {};
    Ciphertext ciphertext {};
    SharedSecret shared_secret {};
  };

  // FSM states
  enum class FSMStates { START, RANDOM, KEYGEN, ENCAPSULATE };
  template <FSMStates> class ML_KEM_BuilderWrapper;

  // Key encapsulation mechanism builder
  class ML_KEM_Builder {
  public:

    void initialize_rng() {
      if (wc_InitRng(&rng) != 0) {
        throw std::runtime_error("ERROR: Failed to initialize wolfCrypt RNG.");
      }
    }

    void create_keypair() {
        int ret = 0;

        auto* raw_key = new (std::nothrow) MlKemKey;
        if (!raw_key) {
            throw std::runtime_error("ERROR: Failed to allocate memory for internal MlKemKey struct.");
        }
        MlKemKeyPtr temp_key_ptr(raw_key, mlkem_key_deleter);

        ret = wc_MlKemKey_Init(temp_key_ptr.get(), SECURITY_LEVEL, nullptr, INVALID_DEVID);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed to initialize new ML-KEM key structure: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        ret = wc_MlKemKey_MakeKey(temp_key_ptr.get(), &rng);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed to generate new ML-KEM keys: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        word32 pk_size = 0;
        word32 sk_size = 0;

        ret = wc_MlKemKey_PublicKeySize(temp_key_ptr.get(), &pk_size);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed get ML-KEM public key size: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        ret = wc_MlKemKey_PrivateKeySize(temp_key_ptr.get(), &sk_size);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed get ML-KEM private key size: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        try {
            data.public_key.resize(pk_size);
            data.secret_key.resize(sk_size);
        } catch (const std::bad_alloc& e) {
            throw std::runtime_error(std::string("ERROR: Failed to allocate memory for encoded keys: ") + e.what());
        }

        ret = wc_MlKemKey_EncodePublicKey(temp_key_ptr.get(), data.public_key.data(), pk_size);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed to encode public key: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        ret = wc_MlKemKey_EncodePrivateKey(temp_key_ptr.get(), data.secret_key.data(), sk_size);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed to encode private key: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        data.key_ptr = std::move(temp_key_ptr);
    }

    std::pair<Ciphertext, SharedSecret> encapsulate_secret(const MlKemKey& key) {
      const auto key_ptr = const_cast<MlKemKey*>(&key);

      int ret = 0;
      word32 ct_size = 0;
      word32 ss_size = 0;

      ret = wc_MlKemKey_CipherTextSize(key_ptr, &ct_size);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed get ciphertext size: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }
      ret = wc_MlKemKey_SharedSecretSize(key_ptr, &ss_size);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed get shared secret size: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      Ciphertext local_ciphertext;
      SharedSecret local_shared_secret;

      try {
        local_ciphertext.resize(ct_size);
        local_shared_secret.resize(ss_size);
      } catch (const std::bad_alloc& e) {
        throw std::runtime_error(std::string("ERROR: Failed to allocate memory for encapsulation outputs: ") + e.what());
      }

      // encapsulation
      ret = wc_MlKemKey_Encapsulate(key_ptr, local_ciphertext.data(),local_shared_secret.data(), &rng);
      if (ret != 0) {
        local_ciphertext.clear();
        local_shared_secret.clear();
        throw std::runtime_error("ERROR: Failed to encapsulate secret: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      data.ciphertext = std::move(local_ciphertext);
      data.shared_secret = std::move(local_shared_secret);

      return {data.ciphertext, data.shared_secret};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    [[nodiscard]]
    ML_KEM_DATA build() && { return std::move(data); }

  private:
    ML_KEM_Builder() = default;
    ML_KEM_DATA data = {};
    WC_RNG rng = {};
    template <FSMStates> friend class ML_KEM_BuilderWrapper;
  };

  using protocolInitialState = Typestate::InitialStates<FSMStates::START>;

  using protocolTransitions = Typestate::Transitions<
      Typestate::Transition<FSMStates::START, FSMStates::RANDOM,
          &ML_KEM_Builder::initialize_rng>,
      Typestate::Transition<FSMStates::RANDOM, FSMStates::KEYGEN,
          &ML_KEM_Builder::create_keypair>,
      Typestate::Transition<FSMStates::KEYGEN, FSMStates::ENCAPSULATE,
          &ML_KEM_Builder::encapsulate_secret>>;

  using protocolFinalTransitions =
      Typestate::FinalTransitions<Typestate::FinalTransition<
          FSMStates::ENCAPSULATE, &ML_KEM_Builder::build>>;

  using protocolValidQueries = Typestate::ValidQueries<Typestate::ValidQuery<
      FSMStates::KEYGEN, &ML_KEM_Builder::query_function>>;

  TYPESTATE_START_WRAPPER(ML_KEM_BuilderWrapper,
                          ML_KEM_Builder,
                          FSMStates, protocolInitialState,
                          protocolTransitions, protocolFinalTransitions,
                          protocolValidQueries);

  TYPESTATE_DECLARE_TRANSITION(initialize_rng);
  TYPESTATE_DECLARE_TRANSITION(create_keypair);
  TYPESTATE_DECLARE_TRANSITION(encapsulate_secret);
  TYPESTATE_DECLARE_FINAL_TRANSITION(build);
  TYPESTATE_DECLARE_QUERY_METHOD(query_function);

  TYPESTATE_END_WRAPPER;

  inline ML_KEM_BuilderWrapper<FSMStates::START>
  GetConnectionBuilder() { return {}; }

  class wolfCrypt_ml_kem {
  public:

    [[nodiscard]]
    static MlKemKeyPtr recipient() {
      int ret = 0;

      auto raw_key = new (std::nothrow) MlKemKey;
      if (!raw_key) {
        throw std::runtime_error("ERROR: Failed to allocate memory for new MlKemKey struct.");
      }
      MlKemKeyPtr key_ptr(raw_key, mlkem_key_deleter);

      ret = wc_MlKemKey_Init(key_ptr.get(), SECURITY_LEVEL, nullptr, INVALID_DEVID);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed to initialize new ML-KEM key structure: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      WC_RNG rand;
      ret = wc_InitRng(&rand);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed to initialize wolfCrypt RNG.");
      }

      ret = wc_MlKemKey_MakeKey(key_ptr.get(), &rand);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed to generate new ML-KEM keys: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      return key_ptr;
    }

    [[nodiscard]]
    static ML_KEM_DATA sender_protocol(const MlKemKey& recipient) {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair()
          .encapsulate_secret(recipient);
      return std::move(builder).build();
    }

    [[nodiscard]]
    static bool is_protocol_successful(const ML_KEM_DATA& sender_data, const MlKemKey& recipient) {
      const Ciphertext ciphertext = sender_data.ciphertext;
      const SharedSecret sender_secret = sender_data.shared_secret;

      try {
        const SharedSecret recipient_secret =
            decapsulate_secret(recipient, ciphertext);

        if (recipient_secret.size() != sender_secret.size()) {
          std::cout << "\n\n wolfCrypt ML-KEM-512" << " shared secret size mismatch. Protocol not successful.\n";
          return false;
        }

        if (recipient_secret == sender_secret) {
          std::cout << "\n\n wolfCrypt ML-KEM-512" << " shared secret is equal. Protocol ran successfully.\n";
          return true;
        }

        std::cout << "\n\n wolfCrypt ML-KEM-512" << " shared secret is not equal. Protocol not successful.\n";
        return false;

      } catch (const std::exception& e) {
        std::cout << "\nProtocol failed during decapsulation step or comparison: " << e.what() << std::endl;
        return false;
      } catch (...) {
        std::cout << "\nProtocol failed due to an unexpected error." << std::endl;
        return false;
      }
    }

    void print_protocol_data(
      const ML_KEM_DATA& sender_data,
      const MlKemKey& recipient) const {
      const auto alice_public_key = sender_data.public_key;
      const auto alice_shared_secret = sender_data.shared_secret;
      const auto ciphertext = sender_data.ciphertext;
      const auto bob_key = const_cast<MlKemKey*>(&recipient);

      // Encode public key representation
      int ret = 0;
      word32 pk_size_bytes = 0;

      ret = wc_MlKemKey_PublicKeySize(bob_key, &pk_size_bytes);
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed get ML-KEM public key size: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      PublicKey bob_public_key;
      try {
        bob_public_key.resize(pk_size_bytes);
      } catch (const std::bad_alloc& e) {
        throw std::runtime_error(std::string("ERROR: Failed to allocate memory for public key bytes: ") + e.what());
      }

      ret = wc_MlKemKey_EncodePublicKey(bob_key, bob_public_key.data(), bob_public_key.size());
      if (ret != 0) {
        throw std::runtime_error("ERROR: Failed to encode public key: "
                                 + std::string(wc_GetErrorString(ret))
                                 + " (" + std::to_string(ret) + ")");
      }

      SharedSecret bob_shared_secret = decapsulate_secret(recipient, ciphertext);

      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << kem_primitive << " PROTOCOL -------->";
      hex("\nBob public key:\n", std::as_bytes(std::span(bob_public_key)));
      hex("\nBob shared secret:\n", std::as_bytes(std::span(bob_shared_secret)));

      hex("\nAlice public key:\n", std::as_bytes(std::span(alice_public_key)));
      hex("\nAlice shared secret:\n", std::as_bytes(std::span(alice_shared_secret)));
      std::cout << "\n<--------- END DATA OF PARTICIPANTS IN THE " << kem_primitive << " PROTOCOL --------->";
    }

  private:
    std::string kem_primitive = "wolfCrypt ML-KEM-512";

    static void hex(const std::string_view label, const std::span<const std::byte> data) {
      std::cout << label << " (" << data.size() << " bytes): ";
      std::cout << std::hex << std::setfill('0');
      for (const auto& byte : data) {
        std::cout << std::setw(2) << static_cast<unsigned int>(byte);
      }
      std::cout << std::dec << std::endl;
    }

    [[nodiscard]]
    static SharedSecret decapsulate_secret(const MlKemKey& key, const Ciphertext& ciphertext) {
        int ret = 0;
        const auto key_ptr = const_cast<MlKemKey*>(&key);

        word32 ss_size = 0;
        ret = wc_MlKemKey_SharedSecretSize(key_ptr, &ss_size);
        if (ret != 0) {
            throw std::runtime_error("ERROR: Failed get shared secret size during decapsulation: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        SharedSecret shared_secret;

        try {
            shared_secret.resize(ss_size);
        } catch (const std::bad_alloc& e) {
            throw std::runtime_error(std::string("ERROR: Failed to allocate memory for recipient shared secret: ") + e.what());
        }

        ret = wc_MlKemKey_Decapsulate(key_ptr,
                                     shared_secret.data(),
                                     ciphertext.data(),
                                     ciphertext.size());
        if (ret != 0) {
            throw std::runtime_error("ERROR: wc_MlKemKey_Decapsulate failed: "
                                     + std::string(wc_GetErrorString(ret))
                                     + " (" + std::to_string(ret) + ")");
        }

        return shared_secret;
    }
  };
}

#endif //WOLFCRYPT_ML_KEM_H