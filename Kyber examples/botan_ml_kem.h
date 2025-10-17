#ifndef BOTAN_ML_KEM_H
#define BOTAN_ML_KEM_H

#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "../Typestate.h"

#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>

namespace BOTAN_ML_KEM {

  using Ciphertext = std::vector<uint8_t>;
  using SharedSecret = Botan::secure_vector<uint8_t>;
  constexpr inline auto kyber_mode = Botan::ML_KEM_Mode::ML_KEM_512;
  constexpr inline size_t shared_key_len = 32;
  constexpr inline std::string_view kdf = "HKDF(SHA-512)";
  inline std::array<uint8_t, 16> salt {};
  inline Botan::System_RNG rng {};

  struct ML_KEM_DATA {
    std::unique_ptr<Botan::Public_Key> public_key {};
    std::unique_ptr<Botan::ML_KEM_PrivateKey> secret_key {};
    SharedSecret shared_secret {};
    Ciphertext ciphertext {};
  };

  // FSM states
  enum class FSMStates { START, RANDOM, KEYGEN, ENCAPSULATE };
  template <FSMStates> class ML_KEM_BuilderWrapper;

  // Key encapsulation mechanism builder
  class ML_KEM_Builder {
  public:

    void initialize_rng() {
      salt = rng.random_array<16>();
    }

    void create_keypair() {
      data.secret_key = std::make_unique<Botan::ML_KEM_PrivateKey>(rng, Botan::ML_KEM_Mode::ML_KEM_512);
      data.public_key = data.secret_key->public_key();
    }

    std::pair<Ciphertext, SharedSecret> encapsulate_secret(const Botan::Public_Key& recipient_public_key) {
      Botan::PK_KEM_Encryptor enc(recipient_public_key, kdf);
      const auto kem_result = enc.encrypt(rng, shared_key_len, salt);
      data.ciphertext = kem_result.encapsulated_shared_key();
      data.shared_secret = kem_result.shared_key();

      return {data.ciphertext, data.shared_secret};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    [[nodiscard]]
    ML_KEM_DATA build() && { return std::move(data); }

  private:
    ML_KEM_Builder() = default;
    ML_KEM_DATA data = {};
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

  class botan_ml_kem {
  public:

    [[nodiscard]]
    std::pair<std::unique_ptr<Botan::Public_Key>, std::unique_ptr<Botan::ML_KEM_PrivateKey>> recipient() const {
      std::unique_ptr<Botan::ML_KEM_PrivateKey> secret_key = std::make_unique<Botan::ML_KEM_PrivateKey>(rng, Botan::ML_KEM_Mode::ML_KEM_512);
      auto public_key = secret_key->public_key();

      return {std::move(public_key), std::move(secret_key)};
    }

    [[nodiscard]]
    static ML_KEM_DATA sender_protocol(const Botan::Public_Key& recipient_public_key) {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair()
          .encapsulate_secret(recipient_public_key);
      return std::move(builder).build();
    }

    [[nodiscard]]
    static bool is_protocol_successful(const ML_KEM_DATA& sender_data, const Botan::ML_KEM_PrivateKey& recipient_private_key) {
      const Ciphertext ciphertext = sender_data.ciphertext;
      const SharedSecret sender_secret = sender_data.shared_secret;

      try {
        const SharedSecret recipient_secret =
            decapsulate_secret(recipient_private_key, ciphertext);

        if (recipient_secret.size() != sender_secret.size()) {
          std::cout << "\n\n botan3 ML-KEM-512" << " shared secret size mismatch. Protocol not successful.\n";
          return false;
        }

        if (recipient_secret == sender_secret) {
          std::cout << "\n\n botan3 ML-KEM-512" << " shared secret is equal. Protocol ran successfully.\n";
          return true;
        }

        std::cout << "\n\n botan3 ML-KEM-512" << " shared secret is not equal. Protocol not successful.\n";
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
      const std::pair<std::unique_ptr<Botan::Public_Key>, std::unique_ptr<Botan::ML_KEM_PrivateKey>>& recipient) const {

      const Botan::Public_Key* alice_public_key_ptr = sender_data.public_key.get();
      const Botan::secure_vector<uint8_t>& alice_shared_secret = sender_data.shared_secret;
      const Ciphertext ciphertext = sender_data.ciphertext;

      const Botan::Public_Key* bob_public_key_ptr = recipient.first.get();
      const Botan::ML_KEM_PrivateKey* bob_secret_key_ptr = recipient.second.get();

      SharedSecret bob_shared_secret;
      if (bob_secret_key_ptr) {
        bob_shared_secret = decapsulate_secret(*bob_secret_key_ptr, ciphertext);
      } else {
        std::cerr << "Error: Bob's secret key is null, cannot decapsulate." << std::endl;
      }

      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << kem_scheme << " PROTOCOL -------->";

      // Print Bob's public key
      if (bob_public_key_ptr) {
        auto&& returned_bob_pk_bits = bob_public_key_ptr->public_key_bits();
        Botan::secure_vector<uint8_t> bob_pk_bytes(std::begin(returned_bob_pk_bits), std::end(returned_bob_pk_bits));
        hex("\nBob public key:\n", std::as_bytes(std::span(bob_pk_bytes)));
      } else {
        std::cout << "\nBob public key: (null)\n";
      }

      hex("\nBob shared secret:\n", std::as_bytes(std::span(bob_shared_secret)));

      // Print Alice's public key
      if (alice_public_key_ptr) {
        auto&& returned_alice_pk_bits = alice_public_key_ptr->public_key_bits();
        Botan::secure_vector<uint8_t> alice_pk_bytes(std::begin(returned_alice_pk_bits), std::end(returned_alice_pk_bits));
        hex("\nAlice public key:\n", std::as_bytes(std::span(alice_pk_bytes)));
      } else {
        std::cout << "\nAlice public key: (null)\n";
      }

      hex("\nAlice shared secret:\n", std::as_bytes(std::span(alice_shared_secret)));
      std::cout << "\n<--------- END DATA OF PARTICIPANTS IN THE " << kem_scheme << " PROTOCOL --------->";
    }

  private:
    std::string kem_scheme = "botan3 ML-KEM-512";

    static void hex(const std::string_view label, const std::span<const std::byte> data) {
      std::cout << label << " (" << data.size() << " bytes): ";
      std::cout << std::hex << std::setfill('0');
      for (const auto& byte : data) {
        std::cout << std::setw(2) << static_cast<unsigned int>(byte);
      }
      std::cout << std::dec << std::endl;
    }

    [[nodiscard]]
    static SharedSecret decapsulate_secret(const Botan::ML_KEM_PrivateKey& secret_key, const Ciphertext& ciphertext) {
      Botan::PK_KEM_Decryptor dec(secret_key, rng, kdf);
      auto shared_secret = dec.decrypt(ciphertext, shared_key_len, salt);

      return shared_secret;
    }
  };
}

#endif //BOTAN_ML_KEM_H
