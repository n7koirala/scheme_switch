#ifndef OPENFHE_DGSAMPLER_H
#define OPENFHE_DGSAMPLER_H

#include <iostream>
#include <random>
#include <cmath>
#include <core/lattice/lat-hal.h>
#include "constants.h"

using namespace lbcrypto;

class DiscreteLaplacianGenerator {
public:

// Sample uniformly from range [0, m)
    int sample_uniform(int m, std::mt19937 &rng) {
        std::uniform_int_distribution<int> dist(0, m - 1);
        return dist(rng);
    }

    int u(const double scale){
        std::random_device rd;
        std::mt19937 rng(rd());
        return sample_uniform(scale, rng);
    }



    void addRandomNoise(DCRTPoly &input, const double scale, const Distribution dist){

        //DCRTPoly res(input.GetParams(), input.GetFormat());
        //auto test = input.GetParams();
        auto c{input.GetParams()->GetCyclotomicOrder()};
        const auto& m{input.GetParams()->GetModulus()};
        auto parm{std::make_shared<ILParamsImpl<BigInteger>>(c, m, 1)};
        DCRTPolyImpl<BigVector>::PolyLargeType element(parm);
        element.SetValues(GenerateVector(c/2,scale, m,dist), input.GetFormat());
        DCRTPolyImpl<BigVector> test(element, input.GetParams());
        input = DCRTPoly(test);

    }

    void addRandomNoise(std::vector<double> &input, const double scale, const Distribution dist){
        for (size_t i = 0; i < input.size(); i++){
            if (dist == UNIFORM){
                input.at(i) += u(scale);
            }
        }
    }

    //discretegaussiangenerator-impl.h
    BigVector GenerateVector(const usint size, const double scale,
                           const typename BigVector::Integer& modulus, const Distribution dist) {
        auto result = GenerateIntVector(size, scale, dist);
        BigVector ans(size, modulus);
        for (usint i = 0; i < size; i++) {
            int32_t v = (result.get())[i];
            if (v < 0)
                ans[i] = modulus - typename BigVector::Integer(-v);
            else
                ans[i] = typename BigVector::Integer(v);
        }
        return ans;
    }

    std::shared_ptr<int64_t> GenerateIntVector(usint size, const double scale, const Distribution dist) {
        std::shared_ptr<int64_t> ans(new int64_t[size], std::default_delete<int64_t[]>());
        for (usint i = 0; i < size; ++i) {
            int64_t val=0;
            if (dist == UNIFORM){
                val = u(scale);
            }
            (ans.get())[i] = val;
        }
        return ans;
    }


};

#endif  //OPENFHE_DGSAMPLER_H
