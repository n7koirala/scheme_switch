# Scheme Switching with Fault Tolerance README

## Introduction

This repo contains the implementation of a scheme-switching idea where a Secure Aggregation's (SA) aggregator key is converted to a fully homomorphic encryption (FHE) ciphertext in OpenFHE. The primary goal of this project is to allow scheme switching of SA ciphertexts to FHE to allow for homomorphic evaluations on SA ciphertexts.


## Requirements

- **C++ Compiler**: Ensure you have a modern C++ compiler that supports C++17 or later.
- **CMake**: Build system generator (version 3.10 or later).
- **OpenFHE Library**: For homomorphic encryption operations.
- **Standard Libraries**: Standard libraries for image processing and mathematical computations.

## Installation

### Step-by-Step Guide

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/n7koirala/scheme_switch.git
    cd scheme_switch
    ```

2. **Install Dependencies**:
    Ensure you have all necessary dependencies installed:
    - OpenFHE
    - CMake
    - Standard C++ libraries

3. **Build the Project**:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

## Usage

To run the application, run the executable under the build folder:
```bash
./build/sa_to_fhe
```

### Parameters

Currently, the parameters have been configured to run for 5 parties where one of the parties can fault (drop out).
The application can be configured using various parameters defined in the source code. Key parameters include:

- **Multiplicative Depth**: Set the depth of multiplicative operations.
- **Scaling Mod Size**: Configure the size for scaling modulus.
- **Batch Size**: Determine the batch size for encoding parameters.

### Example Configuration

```cpp
CCParams<CryptoContextCKKSRNS> parameters;
parameters.SetMultiplicativeDepth(6);
parameters.SetScalingModSize(40);
parameters.SetBatchSize(32768);
```

## Contributing

We welcome contributions from the community to enhance the functionality and performance of the scheme_switch project. Here’s how you can contribute:

1. **Fork the Repository**: Click on the fork button at the top right of the repository page.
2. **Create a Branch**: Create a new branch for your feature or bugfix.
    ```bash
    git checkout -b feature-name
    ```
3. **Make Changes**: Implement your changes in the new branch.
4. **Submit a Pull Request**: Push your changes to your forked repository and submit a pull request to the main repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

This README provides a comprehensive guide to understanding, installing, and contributing to the scheme_switch project. For more detailed information, please refer to the source code and comments within the repository.

