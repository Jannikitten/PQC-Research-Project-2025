#ifndef ML_KEM_NATIVE_H
#define ML_KEM_NATIVE_H

#include <iostream>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <iterator>
#include <span>
#include <iomanip>
#include <string>

#include "../Typestate.h"

extern "C" {
#include "../mlkem/mlkem_native.h"
#include "../test/notrandombytes/notrandombytes.h" // for entropy. Not safe, used for testing only.
}

constexpr size_t PUBLIC_KEY_BYTES = CRYPTO_PUBLICKEYBYTES;
constexpr size_t SECRET_KEY_BYTES = CRYPTO_SECRETKEYBYTES;
constexpr size_t CIPHERTEXT_BYTES = CRYPTO_CIPHERTEXTBYTES;
constexpr size_t SHARED_SECRET_BYTES = CRYPTO_BYTES;

namespace ML_KEM_NATIVE {
using PublicKey = std::array<uint8_t, PUBLIC_KEY_BYTES>;
using SecretKey = std::array<uint8_t, SECRET_KEY_BYTES>;
using Ciphertext = std::array<uint8_t, CIPHERTEXT_BYTES>;
using SharedSecret = std::array<uint8_t, SHARED_SECRET_BYTES>;

  struct ML_KEM_DATA {
    PublicKey public_key {};
    SecretKey secret_key {};
    Ciphertext ciphertext {};
    SharedSecret shared_secret {};
  };

  // FSM states
  enum class FSMStates { START, KEYGEN, ENCAPSULATE };
  template <FSMStates> class ML_KEM_BuilderWrapper;

  // Key encapsulation mechanism builder
  class ML_KEM_Builder {
  public:

    std::pair<PublicKey, SecretKey> create_keypair() {
      randombytes_reset();
      crypto_kem_keypair(data.public_key.data(), data.secret_key.data());
      return {data.public_key, data.secret_key};
    }

    std::pair<Ciphertext, SharedSecret> encapsulate_secret(const PublicKey& recipient_public_key) {
      crypto_kem_enc(data.ciphertext.data(), data.shared_secret.data(), recipient_public_key.data());
      return {data.ciphertext, data.shared_secret};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    [[nodiscard]]
    ML_KEM_DATA build() && { return data; }

  private:
    ML_KEM_Builder() = default;
    ML_KEM_DATA data = {};
    template <FSMStates> friend class ML_KEM_BuilderWrapper;
  };

  using protocolInitialState = Typestate::InitialStates<FSMStates::START>;

  using protocolTransitions = Typestate::Transitions<
      Typestate::Transition<FSMStates::START, FSMStates::KEYGEN,
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

    TYPESTATE_DECLARE_TRANSITION(create_keypair);
    TYPESTATE_DECLARE_TRANSITION(encapsulate_secret);
    TYPESTATE_DECLARE_FINAL_TRANSITION(build);
    TYPESTATE_DECLARE_QUERY_METHOD(query_function);

  TYPESTATE_END_WRAPPER;

  inline ML_KEM_BuilderWrapper<FSMStates::START>
  GetConnectionBuilder() { return {}; }

  class ml_kem_native_example {
  public:

    [[nodiscard]]
    static std::pair<PublicKey, SecretKey> recipient() {
      auto public_key = PublicKey {};
      auto secret_key = SecretKey {};

      crypto_kem_keypair(public_key.data(), secret_key.data());

      return {public_key, secret_key};
    }

    [[nodiscard]]
    static ML_KEM_DATA sender_protocol(const PublicKey& recipient_public_key) {
      auto builder = GetConnectionBuilder()
          .create_keypair()
          .encapsulate_secret(recipient_public_key);
      return std::move(builder).build();
    }

    [[nodiscard]]
    static bool is_protocol_successful(const ML_KEM_DATA& sender_data, const std::pair<PublicKey, SecretKey>& recipient) {
      const Ciphertext ciphertext = sender_data.ciphertext;
      const SharedSecret sender_secret = sender_data.shared_secret;
      SharedSecret recipient_secret;
      crypto_kem_dec(recipient_secret.data(), ciphertext.data(), recipient.second.data());

      if (recipient_secret == sender_secret) {
        std::cout << "\n\n mlkem-native ML-KEM-512" << " shared secret is equal. Protocol ran successfully.\n";
        return true;
      }

      std::cout << "\n\n mlkem-native ML-KEM-512" << " shared secret is not equal. Protocol not successful.\n";
      return false;
    }

    void print_protocol_data(
      const ML_KEM_DATA& sender_data,
      const std::pair<PublicKey, SecretKey>& recipient) const {
      const auto alice_public_key = sender_data.public_key;
      const auto alice_shared_secret = sender_data.shared_secret;
      const auto ciphertext = sender_data.ciphertext;
      const auto bob_public_key = recipient.first;
      SharedSecret bob_shared_secret;
      crypto_kem_dec(bob_shared_secret.data(), ciphertext.data(), recipient.second.data());

      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << kem_primitive << " PROTOCOL -------->";
      hex("\nBob public key:\n", std::as_bytes(std::span(bob_public_key)));
      hex("\nBob shared secret:\n", std::as_bytes(std::span(bob_shared_secret)));

      hex("\nAlice public key:\n", std::as_bytes(std::span(alice_public_key)));
      hex("\nAlice shared secret:\n", std::as_bytes(std::span(alice_shared_secret)));
      std::cout << "\n<--------- END DATA OF PARTICIPANTS IN THE " << kem_primitive << " PROTOCOL --------->";
    }

  private:
    std::string kem_primitive = "mlkem-native ML-KEM-512";

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

#endif //ML_KEM_NATIVE_H
