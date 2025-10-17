#ifndef LIBOQS_ML_DSA_H
#define LIBOQS_ML_DSA_H

#include <iostream>
#include <string>
#include <utility>
#include <optional>

#include "../Typestate.h"
#include <oqs_cpp.hpp>

namespace LIBOQS_ML_DSA {;
  struct ML_DSA_DATA {
    std::optional<oqs::Signature> signer; // defer construction to later
    oqs::bytes public_key;
    oqs::bytes message;
    oqs::bytes signature;
  };

  // DSA states
  enum class FSMStates { START, KEYGEN, SIGN };
  template <FSMStates> class ML_DSA_BuilderWrapper;

  // Digital signature builder
  class ML_DSA_Builder {
  public:
    std::pair<oqs::Signature, oqs::bytes> create_keypair(const std::string& dsa_primitive) {
      data.signer.emplace(dsa_primitive); // construct in place
      data.public_key = data.signer->generate_keypair();
      return {*data.signer, data.public_key};
    }

    [[nodiscard]]
    std::pair<oqs::bytes, oqs::bytes> sign_message(const oqs::bytes& message) {
      const oqs::bytes signature = data.signer->sign(message);
      data.message = message;
      data.signature = signature;
      return {data.message, data.signature};
    }

    [[nodiscard]]
    static size_t query_function() { return 0; }
    ML_DSA_DATA build() && { return data; }


  private:
    ML_DSA_Builder() = default;
    ML_DSA_DATA data = {};
    template <FSMStates> friend class ML_DSA_BuilderWrapper;
  };

  using protocolInitialState = Typestate::InitialStates<FSMStates::START>;

  using protocolTransitions = Typestate::Transitions<
      Typestate::Transition<FSMStates::START, FSMStates::KEYGEN,
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

    TYPESTATE_DECLARE_TRANSITION(create_keypair);
    TYPESTATE_DECLARE_TRANSITION(sign_message);
    TYPESTATE_DECLARE_FINAL_TRANSITION(build);
    TYPESTATE_DECLARE_QUERY_METHOD(query_function);

  TYPESTATE_END_WRAPPER;

  inline ML_DSA_BuilderWrapper<FSMStates::START>
  GetConnectionBuilder() { return {}; }

  class liboqs_ml_dsa {
  public:

    [[nodiscard]]
    oqs::Signature verifier() const {
      oqs::Signature verifier{dsa_primitive};
      return verifier;
    }

    [[nodiscard]]
    ML_DSA_DATA signing_protocol(const oqs::bytes& message) const {
      auto builder = GetConnectionBuilder()
          .create_keypair(dsa_primitive)
          .sign_message(message);
      return std::move(builder).build();
    }

    [[nodiscard]]
    bool is_protocol_successful(const ML_DSA_DATA& sign_data) const {
      if (verifier().verify(sign_data.message, sign_data.signature, sign_data.public_key)) {
        std::cout << "\n\nliboqs-cpp " << dsa_primitive << " signature verified. Protocol ran successfully.\n";
        return oqs::OQS_STATUS::OQS_SUCCESS;
      }

      std::cout << "\n\nliboqs-cpp " << dsa_primitive << " signature could not be verified. Protocol not successful.\n";
      return oqs::OQS_STATUS::OQS_ERROR;
    }

    void print_protocol_data(const ML_DSA_DATA& signature_data, const oqs::bytes& message) const {
      std::cout << "\n<-------- BEGIN DATA OF PARTICIPANTS IN THE liboqs-cpp " << dsa_primitive << " PROTOCOL -------->";
      std::cout << "\n\nSignature details:\n" << signature_data.signer.value().get_details();
      std::cout << "\n\nMessage to sign:\n" << oqs::hex_chop(message);
      std::cout << "\n\nSigner public key:\n" << oqs::hex_chop(signature_data.public_key);
      std::cout << "\n\nSignature:\n" << oqs::hex_chop(signature_data.signature);
      std::cout << "\n\n<--------- END DATA OF PARTICIPANTS IN THE liboqs-cpp " << dsa_primitive << " PROTOCOL --------->";
    }

  private:
    std::string dsa_primitive = "ML-DSA-44";
  };
}

#endif //LIBOQS_ML_DSA_H
