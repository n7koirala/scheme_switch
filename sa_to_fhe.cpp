#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"


using namespace lbcrypto;

const std::string DATAFOLDER = "/home/nkoirala/scheme_switch/build/ciphertexts";

void RunCKKSWoFault();

void RunCKKSWithFault();

int main(int argc, char* argv[]) {
    char userChoice;

    std::cout << "Do you want to run the simulation with a fault? (Y/N): ";
    std::cin >> userChoice;

    userChoice = toupper(userChoice);

    if (userChoice == 'Y') {
        std::cout << "\n================= Running for 5 parties with Party 1 faulting =====================" << std::endl;
        std::cout << "\n";
        std::cout << "\n";
        RunCKKSWithFault();
    } else if (userChoice == 'N') {
        std::cout << "\n================= Running for 5 parties w/o any fault =====================" << std::endl;
        std::cout << "\n";
        std::cout << "\n";
        RunCKKSWoFault();
    } else {
        std::cout << "Invalid input. Please enter 'Y' for yes or 'N' for no." << std::endl;
    }

    return 0;

}


void RunCKKSWoFault() {

    std::cout << "\n================= Threshold FHE parameter and key generation =====================" << std::endl;
    std::cout << "\n";

    usint batchSize = 16;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    parameters.SetThresholdNumOfParties(3);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    std::cout << "Crypto context and parameters initialized for threshold FHE.. using 128-bit security level." << std::endl;

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "\tPlaintext modulus: = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "\tCyclotomic order: " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "\tLog2 of ciphertext modulus: " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers for two parties A and B
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n";
    std::cout << "Key generation for multiple parties started." << std::endl;

    // Round 1 (party A)

    kp1      = cc->KeyGen();
    kp2      = cc->MultipartyKeyGen(kp1.publicKey);
    auto kp3 = cc->MultipartyKeyGen(kp2.publicKey);
    auto kp4 = cc->MultipartyKeyGen(kp3.publicKey);
    auto kp5 = cc->MultipartyKeyGen(kp4.publicKey);

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    std::cout << "\tParty 1 key pair generated." << std::endl;

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    std::cout << "\tParty 2 joint key with Party 1 generated." << std::endl;

    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey);
    std::cout << "\tParty 3 joint key with previous parties generated." << std::endl;

    auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMultKey);
    std::cout << "\tParty 4 joint key with previous parties generated." << std::endl;

    auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMultKey);
    std::cout << "\tParty 5 joint key with previous parties generated." << std::endl;

    std::cout << "\tGenerating multiparty evaluation keys for homomorphic evaluations." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());

    auto evalMultABCD = cc->MultiAddEvalKeys(evalMultABC, evalMultKey4, kp4.publicKey->GetKeyTag());

    auto evalMultABCDE = cc->MultiAddEvalKeys(evalMultABCD, evalMultKey5, kp5.publicKey->GetKeyTag());

    auto evalMultEABCDE = cc->MultiMultEvalKey(kp5.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDABCDE = cc->MultiMultEvalKey(kp4.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultCABCDE = cc->MultiMultEvalKey(kp3.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultBABCDE = cc->MultiMultEvalKey(kp2.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultAABCDE = cc->MultiMultEvalKey(kp1.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDEABCDE = cc->MultiAddEvalMultKeys(evalMultEABCDE, evalMultDABCDE, evalMultEABCDE->GetKeyTag());

    auto evalMultCDEABCDE = cc->MultiAddEvalMultKeys(evalMultCABCDE, evalMultDEABCDE, evalMultCABCDE->GetKeyTag());

    auto evalMultBCDEABCDE = cc->MultiAddEvalMultKeys(evalMultBABCDE, evalMultCDEABCDE, evalMultBABCDE->GetKeyTag());

    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABCDE, evalMultBCDEABCDE, kp5.publicKey->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});

    //---------------------------------------------------
    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());

    auto evalSumKeysD = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeys, kp4.publicKey->GetKeyTag());

    auto evalSumKeysE = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeys, kp5.publicKey->GetKeyTag());

    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysABC = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp3.publicKey->GetKeyTag());

    auto evalSumKeysABCD = cc->MultiAddEvalSumKeys(evalSumKeysABC, evalSumKeysD, kp4.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysE, evalSumKeysABCD, kp5.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "All required keys for 5 parties have been generated." << std::endl;


    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
     // Create and populate the DCRTPoly object
    
    auto params = cc->GetCryptoParameters()->GetElementParams();

    std::cout << "\n";
    std::cout << "\n================= Data Encoding to Secure Aggregation (SA) =====================" << std::endl;
    std::cout << "\n";

    // for party 0
    std::cout << "Generating test data for each party." << std::endl;
    int aggVal = 6;
    int aggVal1 = 2;
    int aggVal2 = 5;
    int aggVal3 = 3;
    int aggVal4 = 7;


    std::cout << "\tParty 1's value: " << aggVal << std::endl;
    std::cout << "\tParty 2's value: " << aggVal1 << std::endl;
    std::cout << "\tParty 3's value: " << aggVal2 << std::endl;
    std::cout << "\tParty 4's value: " << aggVal3 << std::endl;
    std::cout << "\tParty 5's value: " << aggVal4 << std::endl;

    
    std::cout << "\n";
    std::cout << "Encoding the parties data into SA ciphertexts. " << std::endl;

    DCRTPoly poly(params, Format::EVALUATION, true);

    // for party 0
    poly.SetValuesToZero();
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

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(complexValues);

    // for party 1

    
    DCRTPoly poly1(params, Format::EVALUATION, true);
    poly1.SetValuesToZero();


    for (size_t i = 0; i < poly1.GetAllElements().size(); ++i) {
        NativePoly element = poly1.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal1); 
        }
        poly1.SetElementAtIndex(i, std::move(element));
    }

    // Convert DCRTPoly to Plaintext
    poly1.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues1;
    for (size_t i = 0; i < poly1.GetLength(); ++i) {
       complexValues1.emplace_back(static_cast<double>(poly1.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues1.resize(batchSize);

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(complexValues1);

    // for party 2

    DCRTPoly poly2(params, Format::EVALUATION, true);
    poly2.SetValuesToZero();

    

    for (size_t i = 0; i < poly2.GetAllElements().size(); ++i) {
        NativePoly element = poly2.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal2); 
        }
        poly2.SetElementAtIndex(i, std::move(element));
    }

    poly2.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues2;
    for (size_t i = 0; i < poly2.GetLength(); ++i) {
       complexValues2.emplace_back(static_cast<double>(poly2.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues2.resize(batchSize);

    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(complexValues2);


    // for party 3

    DCRTPoly poly3(params, Format::EVALUATION, true);
    poly3.SetValuesToZero();

    
    for (size_t i = 0; i < poly3.GetAllElements().size(); ++i) {
        NativePoly element = poly3.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal3); 
        }
        poly3.SetElementAtIndex(i, std::move(element));
    }

    poly3.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues3;
    for (size_t i = 0; i < poly3.GetLength(); ++i) {
       complexValues3.emplace_back(static_cast<double>(poly3.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues3.resize(batchSize);

    Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(complexValues3);

    // for party 4

    DCRTPoly poly4(params, Format::EVALUATION, true);
    poly4.SetValuesToZero();

    
    for (size_t i = 0; i < poly4.GetAllElements().size(); ++i) {
        NativePoly element = poly4.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal4); 
        }
        poly4.SetElementAtIndex(i, std::move(element));
    }

    poly4.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues4;
    for (size_t i = 0; i < poly4.GetLength(); ++i) {
       complexValues4.emplace_back(static_cast<double>(poly4.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues4.resize(batchSize);

    Plaintext plaintext4 = cc->MakeCKKSPackedPlaintext(complexValues4);

    std::cout << "Encoding into SA ciphertext completed. " << std::endl;


    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= SA to FHE conversion =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Performing SA to FHE conversion.." << std::endl;
    std::cout << "\tSA ciphertexts are being converted to FHE ciphertexts." << std::endl;

    Ciphertext<DCRTPoly> ciphertext;
    ciphertext = cc->Encrypt(kp5.publicKey, plaintext);

    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext.txt", ciphertext, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 0" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext1;
    ciphertext1 = cc->Encrypt(kp5.publicKey, plaintext1);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext2;
    ciphertext2 = cc->Encrypt(kp5.publicKey, plaintext2);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext2.txt", ciphertext2, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 2" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext3;
    ciphertext3 = cc->Encrypt(kp5.publicKey, plaintext3);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext3.txt", ciphertext3, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 3" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext4;
    ciphertext4 = cc->Encrypt(kp5.publicKey, plaintext4);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext4.txt", ciphertext4, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 4" << std::endl;
    }

    std::cout << "SA to FHE conversion completed." << std::endl;
    std::cout << "\n";

    std::cout << "Aggregating the FHE converted ciphertexts.." << std::endl;
    cc->EvalAddInPlace(ciphertext, ciphertext1);
    cc->EvalAddInPlace(ciphertext, ciphertext2);
    cc->EvalAddInPlace(ciphertext, ciphertext3);
    cc->EvalAddInPlace(ciphertext, ciphertext4);
    std::cout << "Aggregation completed." << std::endl;
    std::cout << "\n";
    

    ////////////////////////////////////////////////////////////
    // Homomorphic Operations
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= Computing on the FHE ciphertexts =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Computing on the aggregated FHE ciphertext homomorphically.." << std::endl;

    Ciphertext<DCRTPoly> reluApprox;

    double lowerBound = 0;
    double upperBound = 40;
    double threshold; // set this to about 2 points below the actual value
    std::cout << "\tPlease enter the threshold value to check for: ";
    std::cin >> threshold; // Take user input and store it in aggVal

    // Check if the input was successful
    if (!std::cin) {
        std::cout << "Invalid input. Please enter a numeric value." << std::endl;
        return ; // Exit the program with an error code
    }
     
    std::cout << "\tThreshold value for aggregation: " << threshold << std::endl;
    uint32_t polyDegree = 27; // Degree of the polynomial for approximation
    std::cout << "\tPerforming Chebyshev approximation for the max. function \n \tbetween threshold and aggregation value.. " << std::endl;
    reluApprox = cc->EvalChebyshevFunction([&threshold](double x) -> double { return std::max(threshold, x); }, ciphertext, lowerBound, upperBound, polyDegree);
 
    std::cout << "Homomorphic evaluation completed." << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= Multiparty Decryption =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Started the multiparty decryption process.." << std::endl;

    Plaintext plaintextMultipartyNew;

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

    // Distributed decryption
    // partial decryption by party A
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({reluApprox}, kp1.secretKey);

    // partial decryption by party B
    auto ciphertextPartial2 = cc->MultipartyDecryptMain({reluApprox}, kp2.secretKey);

    // partial decryption by party C
    auto ciphertextPartial3 = cc->MultipartyDecryptMain({reluApprox}, kp3.secretKey);

    // partial decryption by party D
    auto ciphertextPartial4 = cc->MultipartyDecryptMain({reluApprox}, kp4.secretKey);

    // partial decryption by party E
    auto ciphertextPartial5 = cc->MultipartyDecryptMain({reluApprox}, kp5.secretKey);

    std::cout << "\tPartial decryption ciphertexts generated for 5 parties.." << std::endl;

    std::cout << "\tCombining the partial decryptions.." << std::endl;
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);
    partialCiphertextVec.push_back(ciphertextPartial4[0]);
    partialCiphertextVec.push_back(ciphertextPartial5[0]);

    // Two partial decryptions are combined
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
     std::cout << "Decryption process completed." << std::endl;

    std::cout << "\n";
    std::cout << "\n================= Result Interpretation =====================" << std::endl;
    std::cout << "\n";

    std::cout << "\n";
    std::cout << "\nOriginal Plaintexts: \n" << std::endl;
    std::cout << plaintext << std::endl;
    std::cout << plaintext1 << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;
    std::cout << plaintext4 << std::endl;

    plaintextMultipartyNew->SetLength(1);

    std::cout << "\nResulting homomorphically evaluated (decrypted) plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    std::vector<double> vec_result = plaintextMultipartyNew->GetRealPackedValue();

    std::cout << "\tThreshold value: " << threshold << std::endl;
    std::cout << "\tValidating if aggregation crossed the threshold: " << std::endl;

    if(int(vec_result[0]) > int(threshold)){
        std::cout << "\tTrue!" <<std::endl;  
    }
    else{
        std::cout << "\tFalse!" <<std::endl;  
    }
    
    
    std::cout << "\n";
    std::cout << "\n================= END =====================" << std::endl;
    std::cout << "\n";

}


void RunCKKSWithFault() {
 
    std::cout << "\n================= Threshold FHE parameter and key generation =====================" << std::endl;
    std::cout << "\n";

    usint batchSize = 16;
    const usint N = 5;
    const usint THRESH = static_cast<usint>(std::floor(N / 2)) + 1;
    std::cout << "Threshold level : " << THRESH << std::endl;

    lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_128_classic;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(40);
    parameters.SetBatchSize(batchSize);
    parameters.SetThresholdNumOfParties(3);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    std::cout << "Crypto context and parameters initialized for threshold FHE." << std::endl;

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "\tPlaintext modulus: = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "\tCyclotomic order: " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "\tLog2 of ciphertext modulus: " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    std::cout << "\tSecurity level: " << securityLevel << std::endl;

    // Initialize Public Key Containers for two parties A and B
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n";
    std::cout << "Key generation for multiple parties started." << std::endl;

    // Round 1 (party A)
    kp1      = cc->KeyGen();
    auto kp1smap  = cc->ShareKeys(kp1.secretKey, N, THRESH, 1, "shamir");
    kp2      = cc->MultipartyKeyGen(kp1.publicKey);
    auto kp3 = cc->MultipartyKeyGen(kp2.publicKey);
    auto kp4 = cc->MultipartyKeyGen(kp3.publicKey);
    auto kp5 = cc->MultipartyKeyGen(kp4.publicKey);

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    std::cout << "\tParty 1 key pair generated." << std::endl;

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    std::cout << "\tParty 2 joint key with Party 1 generated." << std::endl;

    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey);
    std::cout << "\tParty 3 joint key with previous parties generated." << std::endl;

    auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMultKey);
    std::cout << "\tParty 4 joint key with previous parties generated." << std::endl;

    auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMultKey);
    std::cout << "\tParty 5 joint key with previous parties generated." << std::endl;

    std::cout << "\tGenerating multiparty evaluation keys for homomorphic evaluations." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());

    auto evalMultABCD = cc->MultiAddEvalKeys(evalMultABC, evalMultKey4, kp4.publicKey->GetKeyTag());

    auto evalMultABCDE = cc->MultiAddEvalKeys(evalMultABCD, evalMultKey5, kp5.publicKey->GetKeyTag());

    auto evalMultEABCDE = cc->MultiMultEvalKey(kp5.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDABCDE = cc->MultiMultEvalKey(kp4.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultCABCDE = cc->MultiMultEvalKey(kp3.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultBABCDE = cc->MultiMultEvalKey(kp2.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultAABCDE = cc->MultiMultEvalKey(kp1.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDEABCDE = cc->MultiAddEvalMultKeys(evalMultEABCDE, evalMultDABCDE, evalMultEABCDE->GetKeyTag());

    auto evalMultCDEABCDE = cc->MultiAddEvalMultKeys(evalMultCABCDE, evalMultDEABCDE, evalMultCABCDE->GetKeyTag());

    auto evalMultBCDEABCDE = cc->MultiAddEvalMultKeys(evalMultBABCDE, evalMultCDEABCDE, evalMultBABCDE->GetKeyTag());

    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABCDE, evalMultBCDEABCDE, kp5.publicKey->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});

    //---------------------------------------------------
    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());

    auto evalSumKeysD = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeys, kp4.publicKey->GetKeyTag());

    auto evalSumKeysE = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeys, kp5.publicKey->GetKeyTag());

    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysABC = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp3.publicKey->GetKeyTag());

    auto evalSumKeysABCD = cc->MultiAddEvalSumKeys(evalSumKeysABC, evalSumKeysD, kp4.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysE, evalSumKeysABCD, kp5.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "All required keys for 5 parties have been generated." << std::endl;


    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
     // Create and populate the DCRTPoly object
    
    auto params = cc->GetCryptoParameters()->GetElementParams();

    std::cout << "\n";
    std::cout << "\n================= Data Encoding to Secure Aggregation (SA) =====================" << std::endl;
    std::cout << "\n";

    // for party 0
    std::cout << "Generating test data for each party." << std::endl;
    int aggVal = 6;
    int aggVal1 = 2;
    int aggVal2 = 5;
    int aggVal3 = 3;
    int aggVal4 = 7;


    std::cout << "\tParty 1's value: " << aggVal << std::endl;
    std::cout << "\tParty 2's value: " << aggVal1 << std::endl;
    std::cout << "\tParty 3's value: " << aggVal2 << std::endl;
    std::cout << "\tParty 4's value: " << aggVal3 << std::endl;
    std::cout << "\tParty 5's value: " << aggVal4 << std::endl;

    
    std::cout << "\n";
    std::cout << "Encoding the parties data into SA ciphertexts. " << std::endl;

    DCRTPoly poly(params, Format::EVALUATION, true);

    // for party 0
    poly.SetValuesToZero();
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

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(complexValues);

    // for party 1

    
    DCRTPoly poly1(params, Format::EVALUATION, true);
    poly1.SetValuesToZero();


    for (size_t i = 0; i < poly1.GetAllElements().size(); ++i) {
        NativePoly element = poly1.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal1); 
        }
        poly1.SetElementAtIndex(i, std::move(element));
    }

    // Convert DCRTPoly to Plaintext
    poly1.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues1;
    for (size_t i = 0; i < poly1.GetLength(); ++i) {
       complexValues1.emplace_back(static_cast<double>(poly1.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues1.resize(batchSize);

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(complexValues1);

    // for party 2

    DCRTPoly poly2(params, Format::EVALUATION, true);
    poly2.SetValuesToZero();

    

    for (size_t i = 0; i < poly2.GetAllElements().size(); ++i) {
        NativePoly element = poly2.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal2); 
        }
        poly2.SetElementAtIndex(i, std::move(element));
    }

    poly2.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues2;
    for (size_t i = 0; i < poly2.GetLength(); ++i) {
       complexValues2.emplace_back(static_cast<double>(poly2.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues2.resize(batchSize);

    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(complexValues2);


    // for party 3

    DCRTPoly poly3(params, Format::EVALUATION, true);
    poly3.SetValuesToZero();

    
    for (size_t i = 0; i < poly3.GetAllElements().size(); ++i) {
        NativePoly element = poly3.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal3); 
        }
        poly3.SetElementAtIndex(i, std::move(element));
    }

    poly3.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues3;
    for (size_t i = 0; i < poly3.GetLength(); ++i) {
       complexValues3.emplace_back(static_cast<double>(poly3.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues3.resize(batchSize);

    Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(complexValues3);

    // for party 4

    DCRTPoly poly4(params, Format::EVALUATION, true);
    poly4.SetValuesToZero();

    
    for (size_t i = 0; i < poly4.GetAllElements().size(); ++i) {
        NativePoly element = poly4.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(aggVal4); 
        }
        poly4.SetElementAtIndex(i, std::move(element));
    }

    poly4.SetFormat(Format::COEFFICIENT);
    std::vector<std::complex<double>> complexValues4;
    for (size_t i = 0; i < poly4.GetLength(); ++i) {
       complexValues4.emplace_back(static_cast<double>(poly4.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    }
    complexValues4.resize(batchSize);

    Plaintext plaintext4 = cc->MakeCKKSPackedPlaintext(complexValues4);

    std::cout << "Encoding into SA ciphertext completed. " << std::endl;


    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= SA to FHE conversion =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Performing SA to FHE conversion.." << std::endl;
    std::cout << "\tSA ciphertexts are being converted to FHE ciphertexts." << std::endl;

    
    Ciphertext<DCRTPoly> ciphertext;
    ciphertext = cc->Encrypt(kp5.publicKey, plaintext);

    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext.txt", ciphertext, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 0" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext1;
    ciphertext1 = cc->Encrypt(kp5.publicKey, plaintext1);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext2;
    ciphertext2 = cc->Encrypt(kp5.publicKey, plaintext2);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext2.txt", ciphertext2, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 2" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext3;
    ciphertext3 = cc->Encrypt(kp5.publicKey, plaintext3);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext3.txt", ciphertext3, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 3" << std::endl;
    }

    Ciphertext<DCRTPoly> ciphertext4;
    ciphertext4 = cc->Encrypt(kp5.publicKey, plaintext4);
    if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertext4.txt", ciphertext4, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 4" << std::endl;
    }

    std::cout << "SA to FHE conversion completed." << std::endl;
    std::cout << "\n";
    std::cout << "Party 1 FAULTS.." << std::endl;
    std::cout << "\n";

    std::cout << "Aggregating the FHE converted ciphertexts w/o Party 1.." << std::endl;

    cc->EvalAddInPlace(ciphertext1, ciphertext2);
    cc->EvalAddInPlace(ciphertext1, ciphertext3);
    cc->EvalAddInPlace(ciphertext1, ciphertext4);
    std::cout << "Aggregation completed." << std::endl;
    std::cout << "\n";
    

    ////////////////////////////////////////////////////////////
    // Homomorphic Operations
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= Computing on the FHE ciphertexts =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Computing on the aggregated FHE ciphertext homomorphically.." << std::endl;

    Ciphertext<DCRTPoly> reluApprox;

    double lowerBound = 0;
    double upperBound = 21;
    double threshold; // set this to about 2 points below the actual value
    std::cout << "\tPlease enter the threshold value to check for: ";
    std::cin >> threshold; // Take user input and store it in aggVal

    // Check if the input was successful
    if (!std::cin) {
        std::cout << "Invalid input. Please enter a numeric value." << std::endl;
        return ; // Exit the program with an error code
    }
     
    std::cout << "\tThreshold value for aggregation: " << threshold << std::endl;
    uint32_t polyDegree = 27; // Degree of the polynomial for approximation
    std::cout << "\tPerforming Chebyshev approximation for the max. function \n \tbetween threshold and aggregation value.. " << std::endl;
    reluApprox = cc->EvalChebyshevFunction([&threshold](double x) -> double { return std::max(threshold, x); }, ciphertext1, lowerBound, upperBound, polyDegree);
 
    std::cout << "Homomorphic evaluation completed." << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ////////////////////////////////////////////////////////////

    std::cout << "\n";
    std::cout << "\n================= Multiparty Decryption =====================" << std::endl;
    std::cout << "\n";

    std::cout << "Started the multiparty decryption process.." << std::endl;

    Plaintext plaintextMultipartyNew;

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

    std::cout << "\tRecovering Party 1's secret key share from the shares \n \tassuming party 1 faulted (dropped out)." << std::endl;
    // Aborts - recovering kp1.secret key from the shares assuming party A dropped out
    PrivateKey<DCRTPoly> kp1_recovered_sk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    cc->RecoverSharedKey(kp1_recovered_sk, kp1smap, N, THRESH, "shamir");


    // Distributed decryption
    // partial decryption by party A
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({reluApprox}, kp1_recovered_sk);

    // partial decryption by party B
    auto ciphertextPartial2 = cc->MultipartyDecryptMain({reluApprox}, kp2.secretKey);

    // partial decryption by party C
    auto ciphertextPartial3 = cc->MultipartyDecryptMain({reluApprox}, kp3.secretKey);

    // partial decryption by party D
    auto ciphertextPartial4 = cc->MultipartyDecryptMain({reluApprox}, kp4.secretKey);

    // partial decryption by party E
    auto ciphertextPartial5 = cc->MultipartyDecryptMain({reluApprox}, kp5.secretKey);

    std::cout << "\tPartial decryption ciphertexts generated for 5 parties.." << std::endl;

    std::cout << "\tCombining the partial decryptions.." << std::endl;
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);
    partialCiphertextVec.push_back(ciphertextPartial4[0]);
    partialCiphertextVec.push_back(ciphertextPartial5[0]);

    // Two partial decryptions are combined
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
     std::cout << "Decryption process completed." << std::endl;

    std::cout << "\n";
    std::cout << "\n================= Result Interpretation =====================" << std::endl;
    std::cout << "\n";

    std::cout << "\n";
    std::cout << "\nOriginal Plaintexts: \n" << std::endl;
    std::cout << plaintext << std::endl;
    std::cout << plaintext1 << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;
    std::cout << plaintext4 << std::endl;

    plaintextMultipartyNew->SetLength(1);

    std::cout << "\nResulting homomorphically evaluated (decrypted) plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    std::vector<double> vec_result = plaintextMultipartyNew->GetRealPackedValue();

    std::cout << "\tThreshold value: " << threshold << std::endl;
    std::cout << "\tValidating if aggregation crossed the threshold: " << std::endl;

    if(int(vec_result[0]) > int(threshold)){
        std::cout << "\tTrue!" <<std::endl;  
    }
    else{
        std::cout << "\tFalse!" <<std::endl;  
    }
    
    
    std::cout << "\n";
    std::cout << "\n================= END =====================" << std::endl;
    std::cout << "\n";

}
