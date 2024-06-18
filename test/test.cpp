#include "openfhe.h"

using namespace lbcrypto;

void PopulateAndEncryptDCRTPoly();

int main(int argc, char* argv[]) {
    PopulateAndEncryptDCRTPoly();
    return 0;
}

void PopulateAndEncryptDCRTPoly() {
    std::cout << "--------------------------------- Populate and Encrypt DCRTPoly ---------------------------------" << std::endl;

    // Set CKKS parameters
    uint32_t batchSize = 8;
    uint32_t depth = 1;
    uint32_t scaleModSize = 48;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);

    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> contextGenTime = end - start;
    std::cout << "Context generation time: " << contextGenTime.count() << " seconds" << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    start = std::chrono::high_resolution_clock::now();
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> keyGenTime = end - start;
    std::cout << "Key generation time: " << keyGenTime.count() << " seconds" << std::endl;


    // Create and populate the DCRTPoly object
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly poly(params, Format::EVALUATION, true);
    poly.SetValuesToZero();

    // for (size_t i = 0; i < poly.GetAllElements().size(); ++i) {
    //     NativePoly element = poly.GetElementAtIndex(i);
    //     for (size_t j = 0; j < element.GetLength(); ++j) {
    //         element[j] = NativeInteger(4); // Example: setting values to 1, 2, 3, ...
    //     }
    //     poly.SetElementAtIndex(i, std::move(element));
    // }

    // std::cout << "DCRTPoly before populating :" << std::endl;
    // std::cout << poly << std::endl;

    std::vector<double> input{ 40000 };
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(input);
    poly = ptxt->GetElement<DCRTPoly>();

    // uint32_t numModuli = cc->GetElementParams()->GetParams().size();
    // auto elParams = cc->GetElementParams()->GetParams();

    // for (size_t i = 0; i < numModuli; i++) {
    //       NativePoly temp(poly.GetElementAtIndex(0));
    //       temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
    //       ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    // }

    // std::cout << "DCRTPoly after populating :" << std::endl;
    // std::cout << poly << std::endl;

    std::cout << "Input vector: " << ptxt << std::endl;

    // Encrypt the DCRTPoly object
    start = std::chrono::high_resolution_clock::now();
    auto ciphertext = cc->Encrypt(keys.publicKey, ptxt);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "Encryption time: " << encryptionTime.count() << " seconds" << std::endl;


    // Decrypt and display the result
    Plaintext result;

    start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(ciphertext, keys.secretKey, &result);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    result->SetLength(batchSize);
    std::cout << "Decrypted result: " << result << std::endl;
}
