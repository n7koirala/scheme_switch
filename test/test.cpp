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
    uint32_t batchSize = 16;
    uint32_t depth = 6;
    uint32_t scaleModSize = 45;  // plaintext modulus for some reasons

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

    // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

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
    //std::cout << "poly.GetModulus().ConvertToInt() before ptxt: " << poly.GetModulus().ConvertToInt() << std::endl;
    int aggVal = 140;

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
    //std::cout << "poly.GetModulus().ConvertToInt() after ptxt: " << poly.GetModulus().ConvertToInt() << std::endl;

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(complexValues);
    //std::cout << "ptxt->GetEncodingParams()->GetPlaintextModulus(): " << ptxt->GetEncodingParams()->GetPlaintextModulus() << std::endl;


    // Encrypt the Plaintext object
    start = std::chrono::high_resolution_clock::now();
    auto ciphertext = cc->Encrypt(keys.publicKey, ptxt);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // Chebyshev approximation for ReLU function
    // when threshold is 120, anything > 40 results in positive. So 80 difference
    double lowerBound = 0;
    double upperBound = 150;
    double threshold = 138;  // set this to about 2 points below the actual value
    uint32_t polyDegree = 27; // Degree of the polynomial for approximation
    auto reluApprox = cc->EvalChebyshevFunction([&threshold](double x) -> double { return std::max(threshold, x); }, ciphertext, lowerBound, upperBound, polyDegree);
 
    // Decrypt and display the result
    Plaintext result;
    start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(reluApprox, keys.secretKey, &result);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    result->SetLength(batchSize);
    std::cout << "Decrypted result: " << result << std::endl;

    std::vector<double> vec_result = result->GetRealPackedValue();

    std::cout << "Threshold value: " << threshold << std::endl;
    std::cout << "Validating if aggregation (first slot value) crossed the threshold: " << std::endl;

    if(int(vec_result[0]) > int(threshold)){
        std::cout << "True!" <<std::endl;  
    }
    else{
        std::cout << "False!" <<std::endl;  
    }
    
    std::cout << "\n" <<std::endl;

}

/*
// Utility code (might be helpful in future):

    // uint32_t numModuli = cc->GetElementParams()->GetParams().size();
    // auto elParams = cc->GetElementParams()->GetParams();

    // for (size_t i = 0; i < numModuli; i++) {
    //       NativePoly temp(poly.GetElementAtIndex(0));
    //       temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
    //       ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    // }

    // std::cout << "DCRTPoly after populating :" << std::endl;
    // std::cout << poly << std::endl;


// poly -> plaintext -> ciphertext

    //ptxt->GetElement<DCRTPoly>() = poly;

    // std::cout << "Input vector: " << ptxt << std::endl;

    // Set the format to COEFFICIENT
    poly.SetFormat(Format::COEFFICIENT);

    // Convert DCRTPoly to a single polynomial
    Poly interpolatedPoly = poly.CRTInterpolate();

    // Manually convert the values to a vector of complex numbers
    std::vector<std::complex<double>> complexValues;
    for (size_t i = 0; i < interpolatedPoly.GetLength(); ++i) {
        complexValues.emplace_back(static_cast<double>(interpolatedPoly[i].ConvertToDouble()), 0.0);
    }

    //size_t slots = std::max(batchSize, static_cast<uint32_t>(complexValues.size()));
    complexValues.resize(batchSize);  // Truncate or pad with zeros if necessary


    Plaintext result = (std::make_shared<CKKSPackedEncoding>(params, cc->GetEncodingParams(), complexValues, 1, 0, 1.0, batchSize));

    //std::cout << "Converted Plaintext: " << result << std::endl;

    std::vector<double> vec_result = result->GetRealPackedValue();

    std::cout << "contents of the Converted Plaintext: " << std::endl;
    int j = 0;
    for (auto i: vec_result){
        std::cout << i << ' ';
        j++;
        if(j>10){
            break;
        }
    }
    std::cout << "\n" << std::endl;
*/
    

   
