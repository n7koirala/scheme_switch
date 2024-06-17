
#include "openfhe.h"
 #include "dgsampler.h"
 #include "constants.h"


using namespace lbcrypto;

void EvalSchemeSwitch();


int main(int argc, char* argv[]) {
    EvalSchemeSwitch();
    //EvalFunctionExample();
    return 0;
}

/**
 * Generate an ILDCRTParams with a given number of parms, with cyphertext moduli
 * of at least a given size
 * @param m - order
 * @param numOfTower - # of polynomials
 * @param pbits - number of bits in the prime, to start with
 * @return
 */
template <typename I>
static std::shared_ptr<ILDCRTParams<I>> GenerateDCRTParams(usint m, usint numOfTower, usint pbits) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("in GenerateDCRTParams");
    OPENFHE_DEBUGEXP(m);
    OPENFHE_DEBUGEXP(numOfTower);
    OPENFHE_DEBUGEXP(pbits);
    if (numOfTower == 0) {
        OPENFHE_THROW(math_error, "Can't make parms with numOfTower == 0");
    }

    std::vector<NativeInteger> moduli(numOfTower);
    std::vector<NativeInteger> rootsOfUnity(numOfTower);

    NativeInteger q = FirstPrime<NativeInteger>(pbits, m);
    I modulus(1);

    usint j = 0;
    OPENFHE_DEBUGEXP(q);

    for (;;) {
        moduli[j]       = q;
        rootsOfUnity[j] = RootOfUnity(m, q);
        modulus         = modulus * I(q.ConvertToInt());
        OPENFHE_DEBUG("j " << j << " modulus " << q << " rou " << rootsOfUnity[j]);
        if (++j == numOfTower)
            break;

        q = NextPrime(q, m);
    }

    auto params = std::make_shared<ILDCRTParams<I>>(m, moduli, rootsOfUnity);

    return params;
}


void EvalSchemeSwitch() {
    std::cout << "--------------------------------- EvalSchemeSwitch ---------------------------------"
              << std::endl;

    DCRTPoly aggregationKey;
    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(2048,1,53);

    aggregationKey = DCRTPoly(parms,COEFFICIENT);
    aggregationKey.SetValuesToZero();

    // DiscreteLaplacianGenerator dl;

    // dl.addRandomNoise(aggregationKey,10,UNIFORM);

    //Populate integer values into DCRTPoly
    for (size_t i = 0; i < aggregationKey.GetAllElements().size(); ++i) {
        NativePoly element = aggregationKey.GetElementAtIndex(i);
        for (size_t j = 0; j < element.GetLength(); ++j) {
            element[j] = NativeInteger(4); // Example: setting values to 1, 2, 3, ...
        }
        aggregationKey.SetElementAtIndex(i, std::move(element));
    }

     std::cout << aggregationKey << std::endl;

    const unsigned int ringDim = 1 << 10;
    CCParams<CryptoContextCKKSRNS> CKKSparameters;

CKKSparameters.SetMultiplicativeDepth(2);
   CKKSparameters.SetScalingModSize(30);
   CKKSparameters.SetRingDim(ringDim);
   CKKSparameters.SetSecurityLevel(HEStd_NotSet);

   CryptoContext<DCRTPoly> cc = GenCryptoContext(CKKSparameters);
   cc->Enable(PKE);
   cc->Enable(KEYSWITCH);
   cc->Enable(LEVELEDSHE);
    
     // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    
   KeyPair<DCRTPoly> kp = cc->KeyGen();

    std::vector<double> x(ringDim/2,1);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
    ptxt->SetFormat(Format::COEFFICIENT);

    uint32_t numModuli = cc->GetElementParams()->GetParams().size();
    auto elParams = cc->GetElementParams()->GetParams();

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(aggregationKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> ciph = cc->Encrypt(kp.publicKey, ptxt);

//    std::cout <<"getelement: " <<ciph.GetAllElements() << std::endl;

    std::cout << "Encryption successful!" << std::endl;


    Plaintext pt1;
    cc->Decrypt(kp.secretKey, ciph, &pt1);
        pt1->SetFormat(Format::COEFFICIENT);


    std::vector<double> vec_result = pt1->GetRealPackedValue();

    std::cout << "contents of the final_sum ciphertext: " << std::endl;
    for (auto i: vec_result){
        std::cout << i << ' ';
    }


    /*
         DCRTPoly ret = aggregationKey*publicKey;

    std::vector<double> x(plaintextParams.GetRingDimension()/2,1);
    Plaintext ptxt = CKKSContext->MakeCKKSPackedPlaintext(x);

    uint32_t numModuli = CKKSContext->GetElementParams()->GetParams().size();
    auto elParams = CKKSContext->GetElementParams()->GetParams();

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(aggregationKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> aggreg_key_ciph = CKKSContext->Encrypt(kp.publicKey, ptxt);

     Plaintext pt1;
     CKKSContext->Decrypt(kp.secretKey, aggreg_key_ciph, &pt1);


    // converting public key to plaintext
    std::vector<double> x1(plaintextParams.GetRingDimension()/2,1);
    Plaintext ptxt_public_key = CKKSContext->MakeCKKSPackedPlaintext(x1);

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(publicKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt_public_key->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> ret_ciph = CKKSContext->EvalMult(aggreg_key_ciph, ptxt_public_key);


    DCRTPoly temp_sum;
    temp_sum = DCRTPoly(ciphertextParams.GetParams(),EVALUATION);
    temp_sum.SetValuesToZero();

    //Add all the ciphertexts (mod q)
    if(!num_additions){
        num_additions = ciphertexts.size();
    }

    for(unsigned int i = 0; i < num_additions; i++){
        temp_sum += ciphertexts.at(i % ciphertexts.size());
    }

    std::vector<double> x2(plaintextParams.GetRingDimension()/2,0);
    Plaintext ptxt_temp_sum = CKKSContext->MakeCKKSPackedPlaintext(x2);

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(publicKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt_temp_sum->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> final_sum = CKKSContext->EvalAdd(ret_ciph, ptxt_temp_sum);

    // std::cout << "precision bits after decryption: " << pt1->GetLogPrecision() << std::endl;

    // std::vector<double> vec_result = pt1->GetRealPackedValue();

    // std::cout << "contents of the final_sum ciphertext: " << std::endl;
    // for (auto i: vec_result){
    //     std::cout << i << ' ';
    // }

    auto end = std::chrono::steady_clock::now();
    //Now scale and reduce
    //return ret.scale_down(plain_parms, *q_to_t);
    SwitchBasis(ret, plaintextParams);

    std::cout << "ret contents" << ret << std::endl;
    
    return ret;
    */

    
}
