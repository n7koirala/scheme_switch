
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


    const unsigned int ringDim = 1 << 9;
    CCParams<CryptoContextCKKSRNS> CKKSparameters;

    CKKSparameters.SetMultiplicativeDepth(1);
   CKKSparameters.SetScalingModSize(50);
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

    uint32_t numModuli = cc->GetElementParams()->GetParams().size();
    auto elParams = cc->GetElementParams()->GetParams();

    for (size_t i = 0; i < numModuli; i++) {
          NativePoly temp(aggregationKey.GetElementAtIndex(0));
          temp.SwitchModulus(elParams[i]->GetModulus(), elParams[i]->GetRootOfUnity(),0,0);
          ptxt->GetElement<DCRTPoly>().SetElementAtIndex(i, std::move(temp));
    }

    Ciphertext<DCRTPoly> ciph = cc->Encrypt(kp.publicKey, ptxt);

    std::cout << "Encryption successful!" << std::endl;
}
