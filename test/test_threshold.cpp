#include "openfhe.h"
#include <chrono>

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
    parameters.SetThresholdNumOfParties(4); // Set the threshold number of parties to 4

    // Timing context generation
    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> contextGenTime = end - start;
    std::cout << "Context generation time: " << contextGenTime.count() << " seconds" << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    // Initialize Public Key Containers for four parties
    KeyPair<DCRTPoly> kp1, kp2, kp3, kp4;

    // Timing key generation
    start = std::chrono::high_resolution_clock::now();
    kp1 = cc->KeyGen();
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);
    kp3 = cc->MultipartyKeyGen(kp2.publicKey);
    kp4 = cc->MultipartyKeyGen(kp3.publicKey);
    
    // Generate evalmult keys for each party
    auto evalMultKey1 = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey1);
    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey1);
    auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMultKey1);

    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey1, evalMultKey2, kp2.publicKey->GetKeyTag());
    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());
    auto evalMultFinal = cc->MultiAddEvalKeys(evalMultABC, evalMultKey4, kp4.publicKey->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});

    // Generate evalsum keys for each party
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());
    auto evalSumKeysD = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeys, kp4.publicKey->GetKeyTag());
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysD, evalSumKeysC, kp4.publicKey->GetKeyTag());
    evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysJoin, evalSumKeysB, kp4.publicKey->GetKeyTag());
    evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysJoin, evalSumKeys, kp4.publicKey->GetKeyTag());

    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> keyGenTime = end - start;
    std::cout << "Key generation time: " << keyGenTime.count() << " seconds" << std::endl;

    cc->InsertEvalSumKey(evalSumKeysJoin);

    // Create and populate the DCRTPoly object
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly poly(params, Format::EVALUATION, true);
    poly.SetValuesToZero();
    int aggVal = 125;
    std::cout << "Aggregation value: " << aggVal << std::endl;

    for (size_t i = 0; i < poly.GetAllElements().size(); ++i) {
        NativePoly element = poly.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal); 
        }
        poly.SetElementAtIndex(i, std::move(element));
    }

    // Convert DCRTPoly to Plaintext
    poly.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues;
    for (size_t i = 0; i < poly.GetLength(); ++i) {
       complexValues.emplace_back(static_cast<double>(poly.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues.resize(batchSize);

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(complexValues);

    // Timing encryption
    start = std::chrono::high_resolution_clock::now();
    auto ciphertext = cc->Encrypt(kp4.publicKey, ptxt);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // Timing decryption
    start = std::chrono::high_resolution_clock::now();
    Plaintext result;
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext}, kp1.secretKey);
    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertext}, kp2.secretKey);
    auto ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertext}, kp3.secretKey);
    auto ciphertextPartial4 = cc->MultipartyDecryptMain({ciphertext}, kp4.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);
    partialCiphertextVec.push_back(ciphertextPartial4[0]);

    cc->MultipartyDecryptFusion(partialCiphertextVec, &result);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    result->SetLength(batchSize);
    std::cout << "Decrypted result: " << result << std::endl;
}
