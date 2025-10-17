#ifndef BOTAN_ML_DSA_H
#define BOTAN_ML_DSA_H

#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "../Typestate.h"

#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/ml_dsa.h>
#include <botan/dilithium.h>
#include <botan/system_rng.h>

namespace BOTAN_ML_DSA {
  constexpr size_t message_length = 128;
  inline Botan::System_RNG rng {};

  struct ML_DSA_DATA {
    std::unique_ptr<Botan::Public_Key> public_key {};
    std::unique_ptr<Botan::ML_DSA_PrivateKey> secret_key {};
    std::string message {};
    std::vector<uint8_t> signature {};
  };

  // DSA states
  enum class FSMStates { START, RANDOM, KEYGEN, SIGN };
  template <FSMStates> class ML_DSA_BuilderWrapper;

  // Digital signature builder
  class ML_DSA_Builder {
  public:
    void initialize_rng() {
      rng.random_array<16>();
    }

    void create_keypair() {
        data.secret_key = std::make_unique<Botan::ML_DSA_PrivateKey>(rng, Botan::DilithiumMode::ML_DSA_4x4);
        data.public_key = data.secret_key->public_key();
    }

    [[nodiscard]]
    std::pair<std::string, std::vector<uint8_t>> sign_message(const std::string& message) {
      const std::string ml_dsa_scheme = "Randomized";
      Botan::PK_Signer signer(*data.secret_key, rng, ml_dsa_scheme);
      signer.update(reinterpret_cast<const uint8_t*>(message.data()), message.length());
      data.signature = signer.signature(rng);
      data.message = message;

      return {data.message, data.signature};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    ML_DSA_DATA build() && { return std::move(data); }

  private:
    ML_DSA_Builder() = default;
    ML_DSA_DATA data = {};
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

  class botan_ml_dsa {
  public:
    [[nodiscard]]
    ML_DSA_DATA signing_protocol(const std::string& message) const {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair()
          .sign_message(message);
      return std::move(builder).build();
    }

    [[nodiscard]]
    bool is_protocol_successful(const ML_DSA_DATA& sign_data) const {
        if (!sign_data.public_key) {
            std::cerr << "\n\nError: Public key is not initialized in ML_DSA_DATA.\n";
            return false;
        }
        if (sign_data.message.empty()) {
            std::cerr << "\n\nError: Message is empty in ML_DSA_DATA.\n";
            return false;
        }
        if (sign_data.signature.empty()) {
            std::cerr << "\n\nError: Signature is empty in ML_DSA_DATA.\n";
            return false;
        }

        try {
            const std::string ml_dsa_verification_scheme = "Pure";
            Botan::PK_Verifier verifier(*sign_data.public_key, ml_dsa_verification_scheme);
            verifier.update(sign_data.message);

            if (verifier.check_signature(sign_data.signature)) {
                std::cout << "\n\nBotan ML-DSA signature VERIFIED. Protocol ran successfully.\n";
                return true;
            }

            std::cout << "\n\nBotan ML-DSA signature verification FAILED. Protocol not successful.\n";
            return false;

        } catch (const Botan::Exception& e) {
            std::cerr << "\n\nBotan error during verification: " << e.what() << std::endl;
            return false;
        } catch (const std::exception& e) {
            std::cerr << "\n\nGeneric error during verification: " << e.what() << std::endl;
            return false;
        }
    }

    void print_protocol_data(const ML_DSA_DATA& signature_data) const {
      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << dsa_scheme << " PROTOCOL -------->";
      hex("\nMessage to sign:\n", std::as_bytes(std::span(signature_data.message)));

      // Print signer public key
      if (const Botan::Public_Key* public_key_ptr = signature_data.public_key.get()) {
        auto&& returned_alice_pk_bits = public_key_ptr->public_key_bits();
        Botan::secure_vector<uint8_t> pk_bytes(std::begin(returned_alice_pk_bits), std::end(returned_alice_pk_bits));
        hex("\nSigner public key:\n", std::as_bytes(std::span(pk_bytes)));
      } else {
        std::cout << "\nSigner public key: (null)\n";
      }

      // Print signer private key
      if (const Botan::ML_DSA_PrivateKey* secret_key_ptr = signature_data.secret_key.get()) {
        auto&& returned_alice_pk_bits = secret_key_ptr->private_key_bits();
        Botan::secure_vector<uint8_t> sk_bytes(std::begin(returned_alice_pk_bits), std::end(returned_alice_pk_bits));
        hex("\nSigner private key:\n", std::as_bytes(std::span(sk_bytes)));
      } else {
        std::cout << "\nSigner private key: (null)\n";
      }

      hex("\nSignature:\n", std::as_bytes(std::span(signature_data.signature)));
      std::cout << "\n<--------- END DATA OF PARTICIPANTS IN THE " << dsa_scheme << " PROTOCOL --------->";
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

    std::string dsa_scheme = "botan ml-dsa 44";
  };
}

#endif //BOTAN_ML_DSA_H
