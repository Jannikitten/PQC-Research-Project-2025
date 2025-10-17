#ifndef LIBOQS_ML_KEM_H
#define LIBOQS_ML_KEM_H

#include <iostream>
#include <string>
#include <utility>
#include <optional>

#include "../Typestate.h"
#include <oqs_cpp.hpp>

namespace LIBOQS_ML_KEM {
  struct ML_KEM_DATA {
    std::optional<oqs::KeyEncapsulation> kem; // defer construction to later
    oqs::bytes public_key;
    oqs::bytes ciphertext;
    oqs::bytes shared_secret;
  };

  // FSM states
  enum class FSMStates { START, KEYGEN, ENCAPSULATE };
  template <FSMStates> class ML_KEM_BuilderWrapper;

  // Key encapsulation mechanism builder
  class ML_KEM_Builder {
  public:
    std::pair<oqs::KeyEncapsulation, oqs::bytes> create_keypair(const std::string& kem_primitive) {
      data.kem.emplace(kem_primitive); // construct in place
      data.public_key = data.kem->generate_keypair();
      return {*data.kem, data.public_key};
    }

    std::pair<oqs::bytes, oqs::bytes> encapsulate_secret(const oqs::bytes& recipient_public_key) {
      auto [ciphertext, shared_secret] = data.kem->encap_secret(recipient_public_key);
      data.ciphertext = ciphertext;
      data.shared_secret = shared_secret;
      return {ciphertext, shared_secret};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
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

  class liboqs_ml_kem {
  public:

    [[nodiscard]]
    std::pair<oqs::KeyEncapsulation, oqs::bytes> recipient() const {
      oqs::KeyEncapsulation recipient{kem_primitive};
      oqs::bytes public_key = recipient.generate_keypair();

      return {recipient, public_key};
    }

    [[nodiscard]]
    ML_KEM_DATA sender_protocol(const oqs::bytes& public_key) const {
      auto builder = GetConnectionBuilder()
          .create_keypair(kem_primitive)
          .encapsulate_secret(public_key);
      return std::move(builder).build();
    }

    [[nodiscard]]
    bool is_protocol_successful(
      const ML_KEM_DATA& sender_data,
      const std::pair<oqs::KeyEncapsulation, oqs::bytes>& recipient) const {

      if (recipient.first.decap_secret(sender_data.ciphertext) == sender_data.shared_secret) {
        std::cout << "\n\nliboqs-cpp " << kem_primitive << " shared secret is equal. Protocol ran successfully.\n";
        return oqs::OQS_STATUS::OQS_SUCCESS;
      }

      std::cout << "\n\nliboqs-cpp " << kem_primitive << " shared secret is not equal. Protocol not successful.\n";
      return oqs::OQS_STATUS::OQS_ERROR;
    }

    void print_protocol_data(
      const ML_KEM_DATA& sender_data,
      const std::pair<oqs::KeyEncapsulation, oqs::bytes>& recipient) const {
      const auto alice_public_key = sender_data.public_key;
      const auto alice_shared_secret = sender_data.shared_secret;
      const auto ciphertext = sender_data.ciphertext;
      const auto bob_public_key = recipient.second;
      const auto bob_shared_secret = recipient.first.decap_secret(ciphertext);

      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE liboqs-cpp " << kem_primitive << " PROTOCOL -------->";
      std::cout << "\n\nKEM details:\n" << sender_data.kem.value().get_details();
      std::cout << "\n\nBob public key:\n" << oqs::hex_chop(bob_public_key);
      std::cout << "\n\nBob shared secret:\n" << oqs::hex_chop(bob_shared_secret);

      std::cout << "\n\nAlice public key:\n" << oqs::hex_chop(alice_public_key);
      std::cout << "\n\nAlice shared secret:\n" << oqs::hex_chop(alice_shared_secret);
      std::cout << "\n\n<--------- END DATA OF PARTICIPANTS IN THE liboqs-cpp " << kem_primitive << " PROTOCOL --------->";
    }

  private:
    std::string kem_primitive = "ML-KEM-512";
  };
}

#endif //LIBOQS_ML_KEM_H
