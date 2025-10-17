#ifndef WOLFCRYPT_ML_DSA_H
#define WOLFCRYPT_ML_DSA_H

#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "../Typestate.h"
#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include <wolfssl/wolfcrypt/types.h>

namespace WOLFCRYPT_ML_DSA {
  #define WC_ML_DSA_44            2
  #define WC_ML_DSA_65            3
  #define WC_ML_DSA_87            5

  struct ML_DSA_DATA {
    std::vector<byte> public_key_bytes {};
    std::vector<byte> private_key_bytes {};
    std::string message {};
    std::vector<byte> signature {};
    int key_level {};
  };

  // DSA states
  enum class FSMStates { START, RANDOM, KEYGEN, SIGN };
  template <FSMStates> class ML_DSA_BuilderWrapper;

  // Digital signature builder
  class ML_DSA_Builder {
  public:
    void initialize_rng() {
      if (const int ret = wc_InitRng(&rng_ctx) != 0) {
        throw std::runtime_error("Failed to initialize wolfCrypt RNG: " + std::string(wc_GetErrorString(ret)));
      }
      rng_initialized = true;
      std::cout << "wolfCrypt RNG initialized successfully." << std::endl;
    }

    void create_keypair(const int level_id = WC_ML_DSA_44) {
        if (!rng_initialized) {
            throw std::runtime_error("RNG not initialized. Call initialize_rng() first.");
        }

        if (key_pair_ctx_initialized) {
            wc_MlDsaKey_Free(&key_pair_ctx);
            XMEMSET(&key_pair_ctx, 0, sizeof(MlDsaKey));
            key_pair_ctx_initialized = false;
        }

        int ret = wc_MlDsaKey_Init(&key_pair_ctx, nullptr, INVALID_DEVID);
        if (ret != 0) {
            throw std::runtime_error("Failed to initialize MlDsaKey: " + std::string(wc_GetErrorString(ret)));
        }
        key_pair_ctx_initialized = true;

        ret = wc_MlDsaKey_SetParams(&key_pair_ctx, level_id);
        if (ret != 0) {
            throw std::runtime_error("Failed to set MlDsaKey params/level " + std::to_string(level_id) + ": " + std::string(wc_GetErrorString(ret)));
        }
        data.key_level = level_id;

        ret = wc_MlDsaKey_MakeKey(&key_pair_ctx, &rng_ctx);
        if (ret != 0) {
            throw std::runtime_error("Failed to generate ML-DSA key pair (level " + std::to_string(level_id) + "): " + std::string(wc_GetErrorString(ret)));
        }
        std::cout << "wolfCrypt ML-DSA (Level " << level_id << ") key pair generated successfully." << std::endl;

        int pubKeySz_int = 0, privKeySz_int = 0;
        ret = wc_MlDsaKey_GetPubLen(&key_pair_ctx, &pubKeySz_int);
        if (ret != 0) {
            throw std::runtime_error("Failed to get public key length: " + std::string(wc_GetErrorString(ret)));
        }
        ret = wc_MlDsaKey_GetPrivLen(&key_pair_ctx, &privKeySz_int);
         if (ret != 0) {
            throw std::runtime_error("Failed to get private key length: " + std::string(wc_GetErrorString(ret)));
        }

        auto pubKeySz = static_cast<uint32_t>(pubKeySz_int);
        auto privKeySz = static_cast<uint32_t>(privKeySz_int);

        data.public_key_bytes.resize(pubKeySz);
        uint32_t actualPubKeySz = pubKeySz;
        ret = wc_MlDsaKey_ExportPubRaw(&key_pair_ctx, data.public_key_bytes.data(), &actualPubKeySz);
        if (ret != 0) {
            throw std::runtime_error("Failed to export public key: " + std::string(wc_GetErrorString(ret)));
        }
        data.public_key_bytes.resize(actualPubKeySz);

        data.private_key_bytes.resize(privKeySz);
        uint32_t actualPrivKeySz = privKeySz; // For the pointer to size
        ret = wc_MlDsaKey_ExportPrivRaw(&key_pair_ctx, data.private_key_bytes.data(), &actualPrivKeySz);
        if (ret != 0) {
            throw std::runtime_error("Failed to export private key: " + std::string(wc_GetErrorString(ret)));
        }
        data.private_key_bytes.resize(actualPrivKeySz);
    }

    [[nodiscard]]
    std::pair<std::string, std::vector<byte>> sign_message(const std::string& message) {
        if (!key_pair_ctx_initialized || data.key_level == 0) {
            throw std::runtime_error("Key pair not generated/initialized. Call create_keypair() first.");
        }
         if (!rng_initialized) {
            throw std::runtime_error("RNG not initialized for signing.");
        }

        data.message = message;
        int sigSz_int = 0;
        int ret = wc_MlDsaKey_GetSigLen(&key_pair_ctx, &sigSz_int);
        if (ret != 0) {
            throw std::runtime_error("Failed to get signature length: " + std::string(wc_GetErrorString(ret)));
        }

        const auto sigSz = static_cast<uint32_t>(sigSz_int);
        data.signature.resize(sigSz);
        uint32_t actualSigSz = sigSz;

        ret = wc_MlDsaKey_Sign(
            &key_pair_ctx,
            data.signature.data(),
            &actualSigSz,
            reinterpret_cast<const byte*>(data.message.data()),
            static_cast<uint32_t>(data.message.length()),
            &rng_ctx
        );

        if (ret != 0) {
            throw std::runtime_error("Failed to sign message with wolfCrypt ML-DSA: " + std::string(wc_GetErrorString(ret)));
        }
        data.signature.resize(actualSigSz);

        std::cout << "Message signed successfully with wolfCrypt ML-DSA." << std::endl;
        return {data.message, data.signature};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    ML_DSA_DATA build() && { return data; }


  private:
    ML_DSA_Builder() = default;
    ML_DSA_DATA data {};
    WC_RNG rng_ctx {};
    MlDsaKey key_pair_ctx {};
    bool rng_initialized {};
    bool key_pair_ctx_initialized {};
    int level {};
    bool key_pair_initialized {};
    bool key_pair_generated {};
    template <FSMStates> friend class ML_DSA_BuilderWrapper;
  };

  using protocolInitialState = Typestate::InitialStates<FSMStates::START>;

  using protocolTransitions = Typestate::Transitions<
      Typestate::Transition<FSMStates::START, FSMStates::RANDOM,
          &ML_DSA_Builder::initialize_rng>,
      Typestate::Transition<FSMStates::RANDOM, FSMStates::KEYGEN,
          &ML_DSA_Builder::create_keypair>,
      Typestate::Transition<FSMStates::KEYGEN, FSMStates::SIGN,
          &ML_DSA_Builder::sign_message>>;

  using protocolFinalTransitions =
      Typestate::FinalTransitions<Typestate::FinalTransition<
          FSMStates::SIGN, &ML_DSA_Builder::build>>;

  using protocolValidQueries = Typestate::ValidQueries<Typestate::ValidQuery<
      FSMStates::KEYGEN, &ML_DSA_Builder::query_function>>;

  TYPESTATE_START_WRAPPER(ML_DSA_BuilderWrapper,
                          ML_DSA_Builder,
                          FSMStates, protocolInitialState,
                          protocolTransitions, protocolFinalTransitions,
                          protocolValidQueries);

    TYPESTATE_DECLARE_TRANSITION(initialize_rng);
    TYPESTATE_DECLARE_TRANSITION(create_keypair);
    TYPESTATE_DECLARE_TRANSITION(sign_message);
    TYPESTATE_DECLARE_FINAL_TRANSITION(build);
    TYPESTATE_DECLARE_QUERY_METHOD(query_function);

  TYPESTATE_END_WRAPPER;

  inline ML_DSA_BuilderWrapper<FSMStates::START>
  GetConnectionBuilder() { return {}; }

  class wolfcrypt_ml_dsa {
  public:
    [[nodiscard]]
    ML_DSA_DATA signing_protocol(const std::string& message) const {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair(WC_ML_DSA_44)
          .sign_message(message);
      return std::move(builder).build();
    }

    [[nodiscard]]
    bool is_protocol_successful(const ML_DSA_DATA& sign_data) const {
      if (verify_wolfcrypt_signature(sign_data)) {
        std::cout << "\n\nwolfCrypt " << dsa_primitive << " signature verified. Protocol ran successfully.\n";
        return true;
      }

      std::cout << "\n\nwolfCrypt " << dsa_primitive << " signature could not be verified. Protocol not successful.\n";
      return false;
    }

    void print_protocol_data(const ML_DSA_DATA& signature_data) const {
      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE wolfCrypt " << dsa_primitive << " PROTOCOL -------->";
      std::cout << "\n\nAlgorithm Level: " << signature_data.key_level;
      std::cout << "\n\nMessage to sign:\n" << signature_data.message;
      hex("\nSigner public key:\n", std::as_bytes(std::span(signature_data.public_key_bytes)));
      hex("\nSignature:\n", std::as_bytes(std::span(signature_data.signature)));
      std::cout << "\n\n<--------- END DATA OF PARTICIPANTS IN THE wolfCrypt " << dsa_primitive << " PROTOCOL --------->\n";
    }

  private:
    static void hex(const std::string_view label, const std::span<const std::byte> data) {
      std::cout << label << " (" << data.size() << " bytes): ";
      std::cout << std::hex << std::setfill('0');
      for (const auto& byte : data) {
        std::cout << std::setw(2) << static_cast<unsigned int>(byte);
      }
      std::cout << std::dec << std::endl;
    }

    [[nodiscard]]
    bool verify_wolfcrypt_signature(const ML_DSA_DATA& sign_data) const {
        if (sign_data.public_key_bytes.empty() || sign_data.message.empty() || sign_data.signature.empty() || sign_data.key_level == 0) {
            std::cerr << "Not enough data in provided sign_data to verify." << std::endl;
            return false;
        }

        MlDsaKey pub_key_for_verify;
        XMEMSET(&pub_key_for_verify, 0, sizeof(MlDsaKey));
        bool temp_key_initialized = false;

        int ret = wc_MlDsaKey_Init(&pub_key_for_verify, nullptr, INVALID_DEVID);
        if (ret != 0) {
            std::cerr << "Verify: Failed to init temp MlDsaKey: " << wc_GetErrorString(ret) << std::endl;
            return false;
        }
        temp_key_initialized = true;

        ret = wc_MlDsaKey_SetParams(&pub_key_for_verify, sign_data.key_level);
        if (ret != 0) {
            std::cerr << "Verify: Failed to set MlDsaKey params/level: " << wc_GetErrorString(ret) << std::endl;
            wc_MlDsaKey_Free(&pub_key_for_verify);
            return false;
        }

        ret = wc_MlDsaKey_ImportPubRaw(
            &pub_key_for_verify,
            sign_data.public_key_bytes.data(),
            static_cast<uint32_t>(sign_data.public_key_bytes.size())
        );
        if (ret != 0) {
            std::cerr << "Verify: Failed to import public key: " << wc_GetErrorString(ret) << std::endl;
          wc_MlDsaKey_Free(&pub_key_for_verify);
            return false;
        }

        int verification_result = -1;
        ret = wc_MlDsaKey_Verify(
            &pub_key_for_verify,
            sign_data.signature.data(),
            static_cast<uint32_t>(sign_data.signature.size()),
            reinterpret_cast<const byte*>(sign_data.message.data()),
            static_cast<uint32_t>(sign_data.message.length()),
            &verification_result
        );

        wc_MlDsaKey_Free(&pub_key_for_verify);

        if (ret == 0 && verification_result == 0) {
            return true;
        }

        return false;
    }

    std::string dsa_primitive = "ML-DSA-44";
  };
}

#endif //WOLFCRYPT_ML_DSA_H
