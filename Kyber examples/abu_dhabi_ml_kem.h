#ifndef ABU_DHABI_ML_KEM_H
#define ABU_DHABI_ML_KEM_H

#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <memory>

#include "../Typestate.h"

#include <ml_kem/ml_kem_512.hpp>

#include <randomshake/randomshake.hpp>

namespace ABU_DHABI_ML_KEM {
  inline std::array<uint8_t, ml_kem_512::SEED_D_BYTE_LEN> d{};
  inline std::array<uint8_t, ml_kem_512::SEED_Z_BYTE_LEN> z{};
  inline std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m{};

  struct ML_KEM_DATA {
    std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> public_key{};
    std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> secret_key{};
    std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> ciphertext{};
    std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> shared_secret{};
  };

  // FSM states
  enum class FSMStates { START, RANDOM, KEYGEN, ENCAPSULATE };
  template <FSMStates> class ML_KEM_BuilderWrapper;

  // Key encapsulation mechanism builder
  class ML_KEM_Builder {
  public:

    void initialize_rng() {
      rng->generate(d);
      rng->generate(z);
      rng->generate(m);
    }

    void create_keypair() {
      ml_kem_512::keygen(d, z, data.public_key, data.secret_key);
    }

    std::pair<std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN>, std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN>>
    encapsulate_secret(const std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN>& recipient_public_key) {
      assert(ml_kem_512::encapsulate(m, recipient_public_key, data.ciphertext, data.shared_secret));
      return {data.ciphertext, data.shared_secret};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    [[nodiscard]]
    ML_KEM_DATA build() && { return std::move(data); }

  private:
    ML_KEM_Builder() = default;
    ML_KEM_DATA data = {};
    std::unique_ptr<randomshake::randomshake_t<192>> rng = std::make_unique<randomshake::randomshake_t<192>>();
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

  class abu_dhabi_ml_kem {
  public:
    [[nodiscard]]
    std::pair<std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN>, std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN>> recipient() const {
      randomshake::randomshake_t<192> rng{};
      rng.generate(d);
      rng.generate(z);
      std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> public_key{};
      std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> secret_key{};

      ml_kem_512::keygen(d, z, public_key, secret_key);

      return {public_key, secret_key};
    }

    [[nodiscard]]
    static ML_KEM_DATA sender_protocol(const std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN>& recipient_public_key) {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair()
          .encapsulate_secret(recipient_public_key);
      return std::move(builder).build();
    }

    [[nodiscard]]
    static bool is_protocol_successful(const ML_KEM_DATA& sender_data, const std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN>& recipient_private_key) {
      const auto ciphertext = sender_data.ciphertext;
      const auto sender_secret = sender_data.shared_secret;
      std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> recipient_secret{};

      try {
        ml_kem_512::decapsulate(recipient_private_key, ciphertext, recipient_secret);

        if (recipient_secret == sender_secret) {
          std::cout << "\n\n ml-kem API ML-KEM-512" << " shared secret is equal. Protocol ran successfully.\n";
          return true;
        }

        std::cout << "\n\n ml-kem API ML-KEM-512" << " shared secret is not equal. Protocol not successful.\n";
        return false;

      } catch (const std::exception& e) {
        std::cout << "\nProtocol failed during decapsulation step or comparison: " << e.what() << std::endl;
        return false;
      } catch (...) {
        std::cout << "\nProtocol failed due to an unexpected error." << std::endl;
        return false;
      }
    }

    void print_protocol_data(const ML_KEM_DATA& sender_data,
      const std::pair<std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN>, std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN>>& recipient) const {
      const auto alice_public_key = sender_data.public_key;
      const auto alice_shared_secret = sender_data.shared_secret;
      const auto ciphertext = sender_data.ciphertext;
      const auto bob_public_key = recipient.first;
      std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN>  bob_shared_secret{};
      ml_kem_512::decapsulate(recipient.second, ciphertext, bob_shared_secret);

      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << kem_scheme << " PROTOCOL -------->";
      hex("\nBob public key:\n", std::as_bytes(std::span(bob_public_key)));
      hex("\nBob shared secret:\n", std::as_bytes(std::span(bob_shared_secret)));

      hex("\nAlice public key:\n", std::as_bytes(std::span(alice_public_key)));
      hex("\nAlice shared secret:\n", std::as_bytes(std::span(alice_shared_secret)));
      std::cout << "\n<--------- END DATA OF PARTICIPANTS IN THE " << kem_scheme << " PROTOCOL --------->";
    }

  private:
    std::string kem_scheme = "ml-kem API";

    static void hex(const std::string_view label, const std::span<const std::byte> data) {
      std::cout << label << " (" << data.size() << " bytes): ";
      std::cout << std::hex << std::setfill('0');
      for (const auto& byte : data) {
        std::cout << std::setw(2) << static_cast<unsigned int>(byte);
      }
      std::cout << std::dec << std::endl;
    }
  };
}

#endif //ABU_DHABI_ML_KEM_H
