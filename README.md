# MuseAir C++ Implementation: A Fast Non-Cryptographic Hashing Algorithm

[![License](https://img.shields.io/badge/license-GNU-blue.svg)](LICENSE)  
[![Build Status](https://img.shields.io/github/actions/workflow/status/Twilight-Dream-Of-Magic/museair-cpp/CI.yml?branch=main)](https://github.com/Twilight-Dream-Of-Magic/museair-cpp/actions)  
[![Contributors](https://img.shields.io/github/contributors/Twilight-Dream-Of-Magic/museair-cpp)](https://github.com/Twilight-Dream-Of-Magic/museair-cpp/graphs/contributors)

### Introduction

Welcome to the C++ world of MuseAir! This repository showcases a C++ adaptation of the MuseAir hashing algorithm, a brainchild originally conceived by [eternal-io](https://github.com/eternal-io/museair). The algorithm was initially developed in Rust, but to broaden its reach, we've translated it into C++—a more widely used language, especially in performance-critical applications.

MuseAir isn't just any hashing algorithm; it’s optimized for high-speed, non-cryptographic hashing. It's particularly good at what it does—resisting vulnerabilities like blinding multiplication, and we’ve taken care to maintain these strengths in the C++ version.

### Key Features
- **High-Performance Hashing:** MuseAir holds its own against other speedy hashes like WyHash, and our C++ version retains that rapidity.
- **Versatile Output:** Whether you need 64-bit or 128-bit hash outputs, MuseAir has you covered, with minimal performance overhead.
- **Platform-Specific Tweaks:** We’ve made sure to include optimizations for different platforms, leveraging SIMD instructions where possible. The C++17 template parameters also let you fine-tune the hashing process to your liking.

### What’s in This Repository?

This repository doesn’t just bring you the code—it brings the possibility of using MuseAir in your C++ projects. We’ve ensured that this implementation is as seamless as possible, aiming for a header-only design with a few critical paths handled by platform-specific assembly. 

**Minimum Requirements:**
- **C++ Standard:** You’ll need at least C++17.
- **Build System:** We use CMake (version 3.10 or later) to streamline the build process.

### How to Build and Use MuseAir

1. **Clone the Repository:**  
   Start by cloning the project to your local machine.

2. **Navigate to the Project Directory:**  
   Open up a terminal, head to the project’s location, and get ready to build.

3. **Create a Build Directory:**  
   ```bash
   mkdir build
   cd build
   ```

4. **Run CMake:**  
   Configure the project with CMake. For Debug mode:
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   ```
   Or for Release mode:
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Release ..
   ```

5. **Build the Project:**  
   Compile everything with:
   ```bash
   cmake --build .
   ```

6. **Run the Executable:**  
   Once built, run `test_muse_air` to see the hashing in action.

### Example Usage of MuseAir

Curious about how MuseAir works? Here’s a quick example. We’ve made it easy to compute hash values with the `MuseAir` class, whether you need 64-bit or 128-bit outputs.

```cpp
#include <iostream>
#include <cstdint>
#include "MuseAir.hpp"

void print_hash_64(const uint64_t& hash) {
    std::cout << "64-bit hash: " << std::hex << hash << std::endl;
}

void print_hash_128(const uint8_t* hash) {
    std::cout << "128-bit hash: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}

int main() {
    // Example data to hash
    const uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const size_t length = sizeof(data);
    uint64_t seed = 0x12345678ABCDEF;

    // Buffers to store the results
    uint64_t result_64;
    uint8_t result_128[16];

    // Instantiate the MuseAir class with BlindFast = false
    MuseAir<false> hasher_slow;

    // Hashing 64-bit with BlindFast = false
    hasher_slow.hash<false>(data, length, seed, &result_64);
    std::cout << "With BlindFast = false: ";
    print_hash_64(result_64);

    // Hashing 128-bit with BlindFast = false
    hasher_slow.hash_128<false>(data, length, seed, result_128);
    std::cout << "With BlindFast = false: ";
    print_hash_128(result_128);

    // Instantiate the MuseAir class with BlindFast = true
    MuseAir<true> hasher_fast;

    // Hashing 64-bit with BlindFast = true
    hasher_fast.hash<false>(data, length, seed, &result_64);
    std::cout << "With BlindFast = true: ";
    print_hash_64(result_64);

    // Hashing 128-bit with BlindFast = true
    hasher_fast.hash_128<false>(data, length, seed, result_128);
    std::cout << "With BlindFast = true: ";
    print_hash_128(result_128);

    return 0;
}
```

### Explaining the Code

- **`MuseAir` Class:** Templated with `BlindFast`, this class determines the balance between speed and accuracy during hashing. The `hash` method adapts based on this configuration, providing either a fast or a more precise hash.
  
- **Input Data:** We’re working with a simple byte array and a 64-bit seed, showing how even minor tweaks like seed changes can affect the output.

- **Output:** Depending on whether `BlindFast` is `true` or `false`, you’ll see different hash values, showcasing the flexibility and performance of the algorithm.

## Explanation of BlindFast

The BlindFast parameter is a template boolean argument in the MuseAir class that determines the balance between speed and accuracy during hash computation. When BlindFast is set to true, the algorithm is optimized for speed, potentially sacrificing some accuracy. This mode is ideal for scenarios where performance is critical, and the exact precision of the hash value is less important. Conversely, when BlindFast is set to false, the algorithm prioritizes accuracy, making it more suitable for cases where the exactness of the hash value is paramount, even if it results in a slower computation.

### Benchmarks

Benchmarking MuseAir in C++ reveals that it keeps up with the original Rust implementation, clocking in at up to 33.2 GiB/s for the BFast variant on modern CPUs. For the full details, check out the original [MuseAir repository](https://github.com/eternal-io/museair).

### Contributing

Feel like contributing? Great! Fork this repository, make your improvements, and submit a pull request. Just remember to add tests for any new features.

### License

This project is under the MIT License. For more details, see the [LICENSE](LICENSE) file.

### Acknowledgments

Special thanks to [eternal-io](https://github.com/eternal-io) for creating the MuseAir algorithm. This C++ version is a third-party implementation by a friend of the original author (that's me), aimed at making MuseAir accessible to the C++ community. We welcome contributions, issue reports, and forks for your own projects.
### Performance Comparison: MuseAir vs. WyHash vs. RapidHash

In this section, we pit the MuseAir hashing algorithm against two well-known competitors—WyHash and RapidHash. We ran a series of speed tests using the SMHasher3 benchmarking tool to evaluate the performance of these algorithms across various scenarios, focusing on small and bulk key speeds.

![Small Key Speed Test](images/Small%20Key%20Speed%20Test%20-%20Cycles%20per%20Hash%20vs%20Key%20Size%20%5B1%2C%2031%5D-byte%20keys.png)

#### Small Key Speed Test (1 to 31-byte keys)

| Algorithm            | Average Cycles/Hash |
|----------------------|---------------------|
| **MuseAir**          | 29.92               |
| **WyHash (non-strict)**  | 21.94               |
| **WyHash (strict)**      | 25.13               |
| **RapidHash**        | 21.63               |
| **RapidHash (protected)** | 25.12               |

- **Winner**: **WyHash (non-strict)** and **RapidHash** lead in this test, showing the lowest average cycles per hash for small keys, with MuseAir trailing behind.

![Bulk Speed Test](images/Bulk%20Speed%20Test%20-%20GiBsec%20vs%20Alignment%20for%20wyhash%2C%20rapidhash%2C%20MuseAir%2C%20and%20MuseAir-BFast.png)

#### Bulk Key Speed Test (262144-byte keys)

| Algorithm            | Average Bytes/Cycle | Speed (GiB/sec) @ 3.5 GHz |
|----------------------|---------------------|---------------------------|
| **MuseAir**          | 10.89               | 35.49                      |
| **WyHash (non-strict)**  | 10.78               | 35.15                      |
| **WyHash (strict)**      | 7.41                | 24.14                      |
| **RapidHash**        | 10.85               | 35.36                      |
| **RapidHash (protected)** | 7.41                | 24.14                      |

- **Winner**: **MuseAir** edges out the competition slightly in bulk key speed, achieving the highest bytes per cycle and GiB/sec. RapidHash is a close second, while WyHash (strict) lags significantly behind.

### Analysis

From these results, we can conclude that while MuseAir might not excel in small key hashing compared to WyHash and RapidHash, it performs exceptionally well in bulk key scenarios, which is crucial for applications that process large amounts of data. 

WyHash in its non-strict form is a solid performer across the board, particularly in scenarios with smaller keys. Meanwhile, RapidHash shows consistent performance, making it a versatile choice depending on the use case.

MuseAir's strength lies in its balance of performance for larger datasets, making it an excellent choice for systems that prioritize throughput over minimal cycle counts on small inputs.

These results offer a clear view of the strengths and weaknesses of each algorithm, allowing developers to make informed decisions based on their specific needs.

----

# Chinese:

### MuseAir C++ 实现：一种快速的非密码学哈希算法

[![License](https://img.shields.io/badge/license-GNU-blue.svg)](LICENSE)  
[![Build Status](https://img.shields.io/github/actions/workflow/status/Twilight-Dream-Of-Magic/museair-cpp/CI.yml?branch=main)](https://github.com/Twilight-Dream-Of-Magic/museair-cpp/actions)  
[![Contributors](https://img.shields.io/github/contributors/Twilight-Dream-Of-Magic/museair-cpp)](https://github.com/Twilight-Dream-Of-Magic/museair-cpp/graphs/contributors)

### 简介

欢迎来到MuseAir的C++世界！这个仓库展示了MuseAir哈希算法的C++版本，该算法最初由[eternal-io](https://github.com/eternal-io/museair)在Rust中开发。为了扩大其应用范围，我们将其转换为C++语言，这是一种在性能关键的应用中更广泛使用的语言。

MuseAir不仅仅是一个普通的哈希算法；它专为高速、非密码学哈希而优化。它在处理盲乘法等漏洞时表现优异，我们在C++版本中也保留了这些优势。

### 主要特性
- **高性能哈希**：MuseAir与其他快速哈希算法（如WyHash）不相上下，我们的C++版本保留了这种速度优势。
- **多功能输出**：无论你需要64位还是128位哈希输出，MuseAir都能胜任，并且性能损失极小。
- **平台特定优化**：我们确保在不同平台上进行优化，尽可能利用SIMD指令。C++17的模板参数还允许你根据需要微调哈希过程。

### 仓库内容

这个仓库不仅仅为你提供代码，还为你提供了在C++项目中使用MuseAir的可能性。我们确保该实现尽可能无缝，目标是头文件唯一的设计，少量关键路径使用平台特定的汇编代码。

**最低要求：**
- **C++标准**：至少需要C++17。
- **构建系统**：我们使用CMake（版本3.10或更高）来简化构建过程。

### 如何构建和使用MuseAir

1. **克隆仓库**：  
   首先将项目克隆到你的本地机器上。

2. **导航到项目目录**：  
   打开终端，导航到项目所在的位置，准备构建。

3. **创建构建目录**：  
   ```bash
   mkdir build
   cd build
   ```

4. **运行CMake**：  
   使用CMake配置项目。对于Debug模式：
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   ```
   或者Release模式：
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Release ..
   ```

5. **构建项目**：  
   运行以下命令进行编译：
   ```bash
   cmake --build .
   ```

6. **运行可执行文件**：  
   构建完成后，运行 `test_muse_air` 查看哈希算法的表现。

### MuseAir示例代码

想了解MuseAir是如何工作的吗？这里有一个简单的示例。我们使得通过`MuseAir`类计算哈希值变得非常简单，无论你需要64位还是128位的输出。

```cpp
void print_hash_64(const uint64_t& hash) {
    std::cout << "64位哈希值: " << std::hex << hash << std::endl;
}

void print_hash_128(const uint8_t* hash) {
    std::cout << "128位哈希值: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}

int main() {
    // 要进行哈希的示例数据
    const uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const size_t length = sizeof(data);
    uint64_t seed = 0x12345678ABCDEF;

    // 用于存储结果的缓冲区
    uint64_t result_64;
    uint8_t result_128[16];

    // 实例化MuseAir类，BlindFast = false
    MuseAir<false> hasher_slow;

    // 使用BlindFast = false进行64位哈希
    hasher_slow.hash<false>(data, length, seed, &result_64);
    std::cout << "使用BlindFast = false: ";
    print_hash_64(result_64);

    // 使用BlindFast = false进行128位哈希
    hasher_slow.hash_128<false>(data, length, seed, result_128);
    std::cout << "使用BlindFast = false: ";
    print_hash_128(result_128);

    // 实例化MuseAir类，BlindFast = true
    MuseAir<true> hasher_fast;

    // 使用BlindFast = true进行64位哈希
    hasher_fast.hash<false>(data, length, seed, &result_64);
    std::cout << "使用BlindFast = true: ";
    print_hash_64(result_64);

    // 使用BlindFast = true进行128位哈希
    hasher_fast.hash_128<false>(data, length, seed, result_128);
    std::cout << "使用BlindFast = true: ";
    print_hash_128(result_128);

    return 0;
}
```

### 代码解释

- **`MuseAir` 类**：使用模板参数 `BlindFast`，该类决定哈希过程中速度与准确性之间的平衡。`hash` 方法根据这个配置进行调整，提供快速或更精确的哈希值。
  
- **输入数据**：我们使用了一个简单的字节数组和一个64位种子，展示了即使是微小的种子变化也会影响输出结果。

- **输出**：根据 `BlindFast` 设置为 `true` 或 `false`，你会看到不同的哈希值，展示了算法的灵活性和性能。

### 解释 BlindFast 参数

BlindFast 参数是 MuseAir 类中的一个模板布尔参数，用于决定哈希计算时速度和准确性之间的平衡。当 BlindFast 设置为 true 时，算法优化为速度优先，可能会牺牲一些准确性。此模式适用于对性能要求较高且对哈希值的精确性要求较低的场景。相反，当 BlindFast 设置为 false 时，算法优先考虑准确性，这使其更适合对哈希值的精确性要求较高的情况，即使这会导致计算速度变慢。

### 基准测试

MuseAir在C++中的基准测试表明，它的性能与原始的Rust实现相当，在现代CPU上BFast变体达到了33.2 GiB/s的速度。有关算法性能的详细信息，请参阅原始的 [MuseAir 仓库](https://github.com/eternal-io/museair)。

### 贡献

想贡献代码？太好了！请fork此仓库，做出改进，并提交pull request。请确保为任何新功能编写测试。

### 许可证

本项目遵循MIT许可证。有关详细信息，请参阅 [LICENSE](LICENSE) 文件。

### 致谢

特别感谢 [eternal-io](https://github.com/eternal-io) 创建了MuseAir算法。这个C++版本是由原作者的朋友（也就是我）实现的第三方版本，旨在让MuseAir为C++社区所用。我们欢迎贡献、问题报告以及fork用于自己的项目。

### 性能对比：MuseAir vs. WyHash vs. RapidHash

在本章节中，我们将MuseAir哈希算法与两个知名的竞争对手——WyHash和RapidHash进行对比。我们使用SMHasher3基准测试工具对这些算法在各种场景下的性能进行了测试，重点关注小规模和大规模密钥的速度表现。

#### 小规模密钥速度测试（1到31字节密钥）

| 算法                    | 平均每次哈希所需周期数 |
|------------------------|---------------------|
| **MuseAir**            | 29.92               |
| **WyHash (非严格版)**     | 21.94               |
| **WyHash (严格版)**       | 25.13               |
| **RapidHash**          | 21.63               |
| **RapidHash (保护版)**   | 25.12               |

- **赢家**：**WyHash (非严格版)** 和 **RapidHash** 在此测试中表现最佳，展示了对小规模密钥最低的平均每次哈希所需周期数，而MuseAir略显逊色。

#### 大规模密钥速度测试（262144字节密钥）

| 算法                    | 每周期处理字节数 | 在3.5 GHz下的速度 (GiB/秒) |
|------------------------|-----------------|---------------------------|
| **MuseAir**            | 10.89           | 35.49                      |
| **WyHash (非严格版)**     | 10.78           | 35.15                      |
| **WyHash (严格版)**       | 7.41            | 24.14                      |
| **RapidHash**          | 10.85           | 35.36                      |
| **RapidHash (保护版)**   | 7.41            | 24.14                      |

- **赢家**：在大规模密钥速度测试中，**MuseAir** 稍微领先，达到了最高的每周期处理字节数和GiB/秒。RapidHash紧随其后，而WyHash（严格版）则明显落后。

### 分析

从这些结果中，我们可以得出结论，尽管MuseAir在小规模密钥哈希方面不如WyHash和RapidHash表现出色，但它在大规模密钥场景中表现尤为优异，这对于处理大量数据的应用至关重要。

WyHash的非严格版本在各个方面表现稳定，特别是在处理较小密钥的场景中。与此同时，RapidHash展现了出色的一致性，使其成为根据不同用例选择的多功能选项。

MuseAir的优势在于其在处理较大数据集时的性能平衡，使其成为优先考虑吞吐量而非对小输入进行最小周期计数的系统的绝佳选择。

这些结果清晰地展现了每种算法的优点和缺点，帮助开发者根据自身的具体需求做出明智的决策。