
#include "openfhe.h"

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
    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(1024,1,19);

    aggregationKey = DCRTPoly(parms,EVALUATION);
    aggregationKey.SetValuesToZero();


// set up the crypto context for threshold FHE
const unsigned int ringDim = 1 << 9;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    //parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
   parameters.SetSecurityLevel(HEStd_NotSet);
   parameters.SetThresholdNumOfParties(5);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
                 "into s_b*(s_a + s_b)..."
              << std::endl;
    auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party A) started." << std::endl;

    std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..." << std::endl;
    auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});

    std::cout << "Round 3 of key generation completed." << std::endl;



///////

    std::vector<double> x(ringDim/2,1);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);

    uint32_t numModuli = cc->GetElementParams()->GetParams().size();
    auto elParams = cc->GetElementParams()->GetParams();

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(aggregationKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> ciph = cc->Encrypt(kp2.publicKey, ptxt);

    std::cout << "Encryption successful using threshold CKKS" << std::endl;
}
