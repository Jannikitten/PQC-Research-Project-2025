#ifndef ABU_DHABI_ML_DSA_EXAMPLE_H
#define ABU_DHABI_ML_DSA_EXAMPLE_H

#include "ml_dsa/ml_dsa_44.hpp"
#include "randomshake/randomshake.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>

#include "../Typestate.h"

namespace ABU_DHABI_ML_DSA {
  inline std::array<uint8_t, ml_dsa_44::KeygenSeedByteLen> seed{};
  inline std::array<uint8_t, ml_dsa_44::SigningSeedByteLen> rnd{};
  inline std::array<uint8_t, 8> context {};
  constexpr uint8_t message_length = 32;
  using PublicKey = std::vector<uint8_t>;

  struct ML_DSA_DATA {
    std::array<uint8_t, ml_dsa_44::PubKeyByteLen> public_key {};
    std::array<uint8_t, ml_dsa_44::SecKeyByteLen> secret_key {};
    std::array<uint8_t, message_length> message {};
    std::array<uint8_t, ml_dsa_44::SigByteLen> signature {};
  };

  // DSA states
  enum class FSMStates { START, RANDOM, KEYGEN, SIGN };
  template <FSMStates> class ML_DSA_BuilderWrapper;

  // Digital signature builder
  class ML_DSA_Builder {
  public:
    void initialize_rng() {
      rng->generate(seed);
      rng->generate(context);
      rng->generate(rnd);
    }

    std::pair<std::array<uint8_t, ml_dsa_44::PubKeyByteLen>, std::array<uint8_t, ml_dsa_44::SecKeyByteLen>> create_keypair() {
      ml_dsa_44::keygen(seed, data.public_key, data.secret_key);
      return {data.public_key, data.secret_key};
    }

    [[nodiscard]]
    std::pair<std::array<uint8_t, message_length>,
    std::array<uint8_t, ml_dsa_44::SigByteLen>> sign_message(const std::array<uint8_t, message_length>& message) {
      assert(ml_dsa_44::sign(rnd, data.secret_key, message, context, data.signature));
      data.message = message;
      return {data.message, data.signature};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    ML_DSA_DATA build() && { return data; }

  private:
    ML_DSA_Builder() = default;
    ML_DSA_DATA data = {};
    std::unique_ptr<randomshake::randomshake_t<192>> rng = std::make_unique<randomshake::randomshake_t<192>>();
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

  class abu_dhabi_ml_dsa {
  public:
    [[nodiscard]]
    ML_DSA_DATA signing_protocol(const std::array<uint8_t, message_length>& message) const {
      auto builder = GetConnectionBuilder()
          .initialize_rng()
          .create_keypair()
          .sign_message(message);
      return std::move(builder).build();
    }

    [[nodiscard]]
    bool is_protocol_successful(const ML_DSA_DATA& sign_data) const {
      if (ml_dsa_44::verify(sign_data.public_key, sign_data.message, context, sign_data.signature)) {
        std::cout << "\n\nml-dsa API " << "44" << " signature verified. Protocol ran successfully.\n";
        return true;
      }

      std::cout << "\n\nml-dsa API " << "44" << " signature could not be verified. Protocol not successful.\n";
      return false;
    }

    void print_protocol_data(const ML_DSA_DATA& signature_data, const std::array<uint8_t, message_length>& message) const {
      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE " << dsa_scheme << " PROTOCOL -------->";
      hex("\nMessage to sign:\n", std::as_bytes(std::span(message)));
      hex("\nSigner private key:\n", std::as_bytes(std::span(signature_data.secret_key)));
      hex("\nSigner public key:\n", std::as_bytes(std::span(signature_data.public_key)));
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

    std::string dsa_scheme = "ml-dsa API";
  };
}

#endif //ABU_DHABI_ML_DSA_EXAMPLE_H
