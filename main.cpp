#include "kyber examples/liboqs_ml_kem.h"
#include "kyber examples/ml-kem_native.h"
#include "kyber examples/wolfCrypt_ml_kem.h"
#include "kyber examples/botan_ml_kem.h"
#include "kyber examples/abu_dhabi_ml_kem.h"

#include "dilithium examples/liboqs_ml_dsa.h"
#include "dilithium examples/abu_dhabi_ml_dsa.h"
#include "dilithium examples/botan_ml_dsa.h"
#include "dilithium examples/wolfCrypt_ml_dsa.h"

#include "Halstead_metrics.h"

inline void compute_halstead(const std::filesystem::path& file_path_obj, std::ostream& out = std::cout) {
  const Halstead::HalsteadReport report = Halstead::getHalsteadMetricsForFile(file_path_obj.string());
  Halstead::printHalsteadReport(report, out);
}

void print_halstead(const std::string &header_filename, const std::string &subfolder_name = "kyber examples") {
  const std::filesystem::path current_execution_path = std::filesystem::current_path();
  const std::filesystem::path base_path = current_execution_path.parent_path();
  const std::filesystem::path input_path = base_path / subfolder_name / header_filename;

  std::cout << "\n\nAttempting to process file at filepath: " << input_path.string() << std::endl;

  if (!std::filesystem::exists(input_path)) {
    std::cerr << "Error: The file does not exist at the constructed path: " << input_path.string() << std::endl;
    return;
  }
  if (!std::filesystem::is_regular_file(input_path)) {
    std::cerr << "Error: The path exists but is not a regular file: " << input_path.string() << std::endl;
    return;
  }

  compute_halstead(input_path);
}

template <size_t N>
std::array<uint8_t, N> stringToUint8Array(const std::string& str) {
  std::array<uint8_t, N> byteArray{};
  size_t bytesToCopy = std::min(str.length(), N);

  for (size_t i = 0; i < bytesToCopy; ++i) {
    byteArray[i] = static_cast<uint8_t>(str[i]);
  }

  return byteArray;
}

int main() {
  // liboqs mlkem example
  LIBOQS_ML_KEM::liboqs_ml_kem liboqs_ml_kem;
  const auto recipient = liboqs_ml_kem.recipient();
  const auto sender = liboqs_ml_kem.sender_protocol(recipient.second);

  if (liboqs_ml_kem.is_protocol_successful(sender, recipient) == 0) {
    liboqs_ml_kem.print_protocol_data(sender, recipient);
  }

  // mlkem_native mlkem example
  ML_KEM_NATIVE::ml_kem_native_example ml_kem_native;
  const auto ml_kem_native_recipient = ML_KEM_NATIVE::ml_kem_native_example::recipient();
  const auto ml_kem_native_sender = ML_KEM_NATIVE::ml_kem_native_example::sender_protocol(ml_kem_native_recipient.first);

  if (ML_KEM_NATIVE::ml_kem_native_example::is_protocol_successful(ml_kem_native_sender, ml_kem_native_recipient)) {
    ml_kem_native.print_protocol_data(ml_kem_native_sender, ml_kem_native_recipient);
  }

  // wolfCrypt mlkem example
  WOLFCRYPT_ML_KEM::wolfCrypt_ml_kem wolf_crypt_ml_kem;
  const auto wolfCrypt_ml_kem_recipient = WOLFCRYPT_ML_KEM::wolfCrypt_ml_kem::recipient();
  const auto wolfCrypt_ml_kem_sender = WOLFCRYPT_ML_KEM::wolfCrypt_ml_kem::sender_protocol(*wolfCrypt_ml_kem_recipient);

  if (WOLFCRYPT_ML_KEM::wolfCrypt_ml_kem::is_protocol_successful(wolfCrypt_ml_kem_sender, *wolfCrypt_ml_kem_recipient)) {
    wolf_crypt_ml_kem.print_protocol_data(wolfCrypt_ml_kem_sender, *wolfCrypt_ml_kem_recipient);
  }

  // botan3 mlkem example
  BOTAN_ML_KEM::botan_ml_kem botan3_ml_kem;
  const auto botan3_mlkem_recipient = botan3_ml_kem.recipient();
  const auto botan3_mlkem_sender = BOTAN_ML_KEM::botan_ml_kem::sender_protocol(*botan3_mlkem_recipient.first);

  if (BOTAN_ML_KEM::botan_ml_kem::is_protocol_successful(botan3_mlkem_sender, *botan3_mlkem_recipient.second)) {
    botan3_ml_kem.print_protocol_data(botan3_mlkem_sender, botan3_mlkem_recipient);
  }

  // ml-kem API mlkem example
  ABU_DHABI_ML_KEM::abu_dhabi_ml_kem abu_dhabi_ml_kem;
  const auto abu_dhabi_ml_kem_recipient = abu_dhabi_ml_kem.recipient();
  const auto abu_dhabi_ml_kem_sender = ABU_DHABI_ML_KEM::abu_dhabi_ml_kem::sender_protocol(abu_dhabi_ml_kem_recipient.first);

  if (ABU_DHABI_ML_KEM::abu_dhabi_ml_kem::is_protocol_successful(abu_dhabi_ml_kem_sender, abu_dhabi_ml_kem_recipient.second)) {
    abu_dhabi_ml_kem.print_protocol_data(abu_dhabi_ml_kem_sender, abu_dhabi_ml_kem_recipient);
  }

  // liboqs ml dsa example
  LIBOQS_ML_DSA::liboqs_ml_dsa liboqs_ml_dsa;
  const auto liboqs_message = "Message to sign"_bytes;
  const auto liboqs_signer = liboqs_ml_dsa.signing_protocol(liboqs_message);

  if (liboqs_ml_dsa.is_protocol_successful(liboqs_signer) == 0) {
    liboqs_ml_dsa.print_protocol_data(liboqs_signer, liboqs_message);
  }

  // ml-dsa API ml dsa example
  ABU_DHABI_ML_DSA::abu_dhabi_ml_dsa abu_dhabi_ml_dsa;
  const std::string abu_dhabi_message = "Message to sign";
  std::array<uint8_t, ABU_DHABI_ML_DSA::message_length> abu_dhabi_message_converted =
          stringToUint8Array<ABU_DHABI_ML_DSA::message_length>(abu_dhabi_message);
  const auto abu_dhabi_signer = abu_dhabi_ml_dsa.signing_protocol(abu_dhabi_message_converted);

  if (abu_dhabi_ml_dsa.is_protocol_successful(abu_dhabi_signer)) {
    abu_dhabi_ml_dsa.print_protocol_data(abu_dhabi_signer, abu_dhabi_message_converted);
  }

  // botan3 ml dsa example
  BOTAN_ML_DSA::botan_ml_dsa botan_ml_dsa;
  const std::string botan_message = "Message to sign";
  const auto botan_signer = botan_ml_dsa.signing_protocol(botan_message);

  if (botan_ml_dsa.is_protocol_successful(botan_signer)) {
    botan_ml_dsa.print_protocol_data(botan_signer);
  }

  // wolfCrypt ml dsa example
  WOLFCRYPT_ML_DSA::wolfcrypt_ml_dsa wolfcrypt_ml_dsa;
  const std::string wolfcrypt_message = "Message to sign";
  const auto wolfCrypt_signer = wolfcrypt_ml_dsa.signing_protocol(wolfcrypt_message);

  if (wolfcrypt_ml_dsa.is_protocol_successful(wolfCrypt_signer)) {
    wolfcrypt_ml_dsa.print_protocol_data(wolfCrypt_signer);
  }

  // Halstead volume
  //print_halstead("wolfcrypt_ml_dsa.h", "dilithium examples");

  return 0;
}