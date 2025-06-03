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
- **Platform-Specific Tweaks:** We’ve made sure to include optimizations for different platforms, leveraging SIMD instructions where possible. The C++20 template parameters also let you fine-tune the hashing process to your liking.

### What’s in This Repository?

This repository doesn’t just bring you the code—it brings the possibility of using MuseAir in your C++ projects. We’ve ensured that this implementation is as seamless as possible, aiming for a header-only design with a few critical paths handled by platform-specific assembly. 

**Minimum Requirements:**
- **C++ Standard:** You’ll need at least C++20.
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

#### Windows MSYS compilation SMHasher3 effect

```
Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~
# cd '/e/[About Programming]/[CodeProjects]/C++/smhasher3/'

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3
# cmake -S ./ -B ./build
-- The C compiler identification is GNU 11.3.0
-- The CXX compiler identification is GNU 11.3.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc.exe - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++.exe - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- CMAKE_SYSTEM_PROCESSOR: x86_64
-- GCC detected
-- Probing fixed-width integer variants
--   signed and unsigned 8,16,32,64-bit integers found
--   signed and unsigned 128-bit integers found
--   appropriate type for seed_t found
-- Setting target as little-endian
-- Probing compiler builtin function variants
--   likely() / unlikely() found
--   expectp() found
--   unpredictable() found
--   unreachable() found
--   assume() found
--   prefetch() found
--   forcing function inlining found
--   preventing function inlining found
--   C++ restrict keyword replacement found
--   type aliasing attribute found
--   32-bit integer rotation not found, using fallback
--   64-bit integer rotation not found, using fallback
--   Integer byteswapping found
--   32-bit integer popcount found
--   64-bit integer popcount found
--   32-bit integer count leading zero bits found
--   64-bit integer count leading zero bits found
--   Generic vector types found
--   Integer shuffling found
-- x86 universal intrinsic header available
-- Probing instruction-set availability
--   x86_64 SSE 2 intrinsics available
--   x86_64 16- and 32-bit loadu intrinsics available
--   x86_64 64-bit loadu intrinsics available
--   x86_64 SSSE3 intrinsics available
--   x86_64 SSE 4.1 intrinsics available
--   x86_64 CRC-32C intrinsics available
--   x86_64 CLMUL intrinsics available
--   x86_64 AES intrinsics available
--   x86_64 SHA-1 intrinsics available
--   x86_64 SHA-2 intrinsics available
--   x86_64 AVX intrinsics available
--   x86_64 AVX2 intrinsics available
--   x86_64 __asm__() available
-- Looking for pthread.h
-- Looking for pthread.h - found
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD - Success
-- Found Threads: TRUE
-- Probing high-resolution timing functions
--   monotonic clock found
--   hardware performance counter found
-- Found Git: /usr/bin/git.exe (found version "2.41.0")
-- Configuring done
-- Generating done
-- Build files have been written to: /e/[About Programming]/[CodeProjects]/C++/smhasher3/build

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3
# cd build/

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3/build
# make
[  1%] Generating Hashrefs.cpp
Scanning dependencies of target SMHasher3Hashlib
[  2%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/Hashrefs.cpp.o
[  3%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Hashlib.cpp.o
[  4%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Hashinfo.cpp.o
[  4%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/AEStables.cpp.o
[  5%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/AEStest.cpp.o
[  6%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Mathmult.cpp.o
[  7%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/donothing.cpp.o
[  8%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/badhash.cpp.o
[  9%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesrng.cpp.o
[ 10%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/farmhash.cpp.o
[ 10%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/mum_mir.cpp.o
[ 11%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/halftimehash.cpp.o
[ 12%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blake3.cpp.o
[ 13%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/xxhash.cpp.o
[ 14%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blake2.cpp.o
[ 15%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/umash.cpp.o
[ 15%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/cityhash.cpp.o
[ 16%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rmd.cpp.o
[ 17%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/t1ha.cpp.o
[ 18%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/abseil.cpp.o
[ 19%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/metrohash.cpp.o
[ 20%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rust-ahash.cpp.o
[ 21%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/highwayhash.cpp.o
[ 21%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/clhash.cpp.o
[ 22%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/discohash.cpp.o
[ 23%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/chaskey.cpp.o
[ 24%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/siphash.cpp.o
[ 25%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/nmhash.cpp.o
[ 26%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/ascon.cpp.o
[ 26%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/prvhash.cpp.o
[ 27%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/vmac.cpp.o
[ 28%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/meowhash.cpp.o
[ 29%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/spookyhash.cpp.o
[ 30%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha2.cpp.o
[ 31%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rainstorm.cpp.o
[ 32%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha1.cpp.o
[ 32%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/farsh.cpp.o
[ 33%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/hasshe2.cpp.o
[ 34%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/perlhashes.cpp.o
[ 35%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/beamsplitter.cpp.o
[ 36%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/khashv.cpp.o
[ 37%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/polymur.cpp.o
[ 37%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/jodyhash.cpp.o
[ 38%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/poly_mersenne.cpp.o
[ 39%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/falkhash.cpp.o
[ 40%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fnv.cpp.o
[ 41%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rainbow.cpp.o
[ 42%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/wyhash.cpp.o
[ 43%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aquahash.cpp.o
[ 43%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesnihash-peterrk.cpp.o
[ 44%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/md5.cpp.o
[ 45%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash3.cpp.o
[ 46%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/museair.cpp.o
[ 47%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/mx3.cpp.o
[ 48%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/crc.cpp.o
[ 50%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rapidhash.cpp.o
[ 50%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/pearson.cpp.o
[ 51%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/multiply_shift.cpp.o
[ 52%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/komihash.cpp.o
[ 53%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesnihash-majek.cpp.o
[ 54%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/tabulation.cpp.o
[ 55%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/khash.cpp.o
[ 55%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash2.cpp.o
[ 56%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fletcher.cpp.o
[ 57%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/floppsyhash.cpp.o
[ 58%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/seahash.cpp.o
[ 59%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/crap.cpp.o
[ 60%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blockpearson.cpp.o
[ 61%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha3.cpp.o
[ 61%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/lookup3.cpp.o
[ 62%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash1.cpp.o
[ 63%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rust-fxhash.cpp.o
[ 64%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/falcon_oaat.cpp.o
[ 65%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fasthash.cpp.o
[ 66%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/pengyhash.cpp.o
[ 66%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/superfasthash.cpp.o
[ 67%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/o1hash.cpp.o
[ 68%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmur_oaat.cpp.o
[ 69%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/x17.cpp.o
[ 70%] Linking CXX static library libSMHasher3Hashlib.a
[ 70%] Built target SMHasher3Hashlib
[ 71%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Platform.cpp.o
[ 72%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Analyze.cpp.o
[ 72%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Blob.cpp.o
[ 73%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Blobsort.cpp.o
[ 74%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Reporting.cpp.o
[ 75%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Random.cpp.o
[ 76%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Stats.cpp.o
[ 77%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/VCode.cpp.o
[ 77%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Wordlist.cpp.o
[ 78%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/TestGlobals.cpp.o
[ 79%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SanityTest.cpp.o
[ 80%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/AvalancheTest.cpp.o
[ 81%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BitflipTest.cpp.o
[ 82%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BitIndependenceTest.cpp.o
[ 83%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/HashMapTest.cpp.o
[ 83%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SparseKeysetTest.cpp.o
[ 84%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/ZeroesKeysetTest.cpp.o
[ 85%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/CyclicKeysetTest.cpp.o
[ 86%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/TwoBytesKeysetTest.cpp.o
[ 87%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/TextKeysetTest.cpp.o
[ 88%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/PermutationKeysetTest.cpp.o
[ 88%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedTest.cpp.o
[ 89%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedZeroesTest.cpp.o
[ 90%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedSparseTest.cpp.o
[ 91%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBitflipTest.cpp.o
[ 92%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBlockLenTest.cpp.o
[ 93%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBlockOffsetTest.cpp.o
[ 94%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedAvalancheTest.cpp.o
[ 94%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBitIndependenceTest.cpp.o
[ 95%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BadSeedsTest.cpp.o
[ 96%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/PerlinNoiseTest.cpp.o
[ 97%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SpeedTest.cpp.o
[ 98%] Linking CXX static library libSMHasher3Tests.a
[ 98%] Built target SMHasher3Tests
[ 98%] Built target SMHasher3Version
[ 98%] Building CXX object CMakeFiles/SMHasher3.dir/main.cpp.o
[100%] Linking CXX executable SMHasher3.exe
[100%] Built target SMHasher3

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3/build
#
```

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

SMHasher3 Tester Toolkit Results on a 12th Gen Intel(R) Core(TM) i7-12700K CPU

#### Small Key Speed Test (1 to 31-byte keys)

![Small Key Speed Test](images/Small%20Key%20Speed%20Test%20-%20Cycles%20per%20Hash%20vs%20Key%20Size%20%5B1%2C%2031%5D-byte%20keys.png)

#### Bulk Key Speed Test (262144-byte keys)

![Bulk Speed Test](images/Bulk%20Speed%20Test%20-%20GiBsec%20vs%20Alignment%20for%20wyhash%2C%20rapidhash%2C%20MuseAir%2C%20and%20MuseAir-BFast.png)

#### C++ SMHasher3

**Test wyhash (non‐strict version)**
```bash
./SMHasher3 --test=Speed wyhash
```

**Test wyhash.strict (strict version)**
```bash
./SMHasher3 --test=Speed wyhash.strict
```

**Test rapidhash (standard version)**
```bash
./SMHasher3 --test=Speed rapidhash
```

**Test rapidhash.protected (protected version)**
```bash
./SMHasher3 --test=Speed rapidhash.protected
```

**Test MuseAir (standard version)**
```bash
./SMHasher3 --test=Speed MuseAir
```

**Test MuseAir-BFast (blind‐cover fast version)**
```bash
./SMHasher3 --test=Speed MuseAir-BFast
```

**Include extra security tests for the parallel‐accelerated MuseAir-BFast (using 16 CPU cores)**
```bash
./SMHasher3 --extra --ncpu=16 MuseAir-BFast
```


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
- **平台特定优化**：我们确保在不同平台上进行优化，尽可能利用SIMD指令。C++20的模板参数还允许你根据需要微调哈希过程。

### 仓库内容

这个仓库不仅仅为你提供代码，还为你提供了在C++项目中使用MuseAir的可能性。我们确保该实现尽可能无缝，目标是头文件唯一的设计，少量关键路径使用平台特定的汇编代码。

**最低要求：**
- **C++标准**：至少需要C++20。
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


#### Windows MSYS 编译SMHasher3效果

```
Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~
# cd '/e/[About Programming]/[CodeProjects]/C++/smhasher3/'

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3
# cmake -S ./ -B ./build
-- The C compiler identification is GNU 11.3.0
-- The CXX compiler identification is GNU 11.3.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc.exe - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++.exe - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- CMAKE_SYSTEM_PROCESSOR: x86_64
-- GCC detected
-- Probing fixed-width integer variants
--   signed and unsigned 8,16,32,64-bit integers found
--   signed and unsigned 128-bit integers found
--   appropriate type for seed_t found
-- Setting target as little-endian
-- Probing compiler builtin function variants
--   likely() / unlikely() found
--   expectp() found
--   unpredictable() found
--   unreachable() found
--   assume() found
--   prefetch() found
--   forcing function inlining found
--   preventing function inlining found
--   C++ restrict keyword replacement found
--   type aliasing attribute found
--   32-bit integer rotation not found, using fallback
--   64-bit integer rotation not found, using fallback
--   Integer byteswapping found
--   32-bit integer popcount found
--   64-bit integer popcount found
--   32-bit integer count leading zero bits found
--   64-bit integer count leading zero bits found
--   Generic vector types found
--   Integer shuffling found
-- x86 universal intrinsic header available
-- Probing instruction-set availability
--   x86_64 SSE 2 intrinsics available
--   x86_64 16- and 32-bit loadu intrinsics available
--   x86_64 64-bit loadu intrinsics available
--   x86_64 SSSE3 intrinsics available
--   x86_64 SSE 4.1 intrinsics available
--   x86_64 CRC-32C intrinsics available
--   x86_64 CLMUL intrinsics available
--   x86_64 AES intrinsics available
--   x86_64 SHA-1 intrinsics available
--   x86_64 SHA-2 intrinsics available
--   x86_64 AVX intrinsics available
--   x86_64 AVX2 intrinsics available
--   x86_64 __asm__() available
-- Looking for pthread.h
-- Looking for pthread.h - found
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD - Success
-- Found Threads: TRUE
-- Probing high-resolution timing functions
--   monotonic clock found
--   hardware performance counter found
-- Found Git: /usr/bin/git.exe (found version "2.41.0")
-- Configuring done
-- Generating done
-- Build files have been written to: /e/[About Programming]/[CodeProjects]/C++/smhasher3/build

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3
# cd build/

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3/build
# make
[  1%] Generating Hashrefs.cpp
Scanning dependencies of target SMHasher3Hashlib
[  2%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/Hashrefs.cpp.o
[  3%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Hashlib.cpp.o
[  4%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Hashinfo.cpp.o
[  4%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/AEStables.cpp.o
[  5%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/AEStest.cpp.o
[  6%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/lib/Mathmult.cpp.o
[  7%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/donothing.cpp.o
[  8%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/badhash.cpp.o
[  9%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesrng.cpp.o
[ 10%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/farmhash.cpp.o
[ 10%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/mum_mir.cpp.o
[ 11%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/halftimehash.cpp.o
[ 12%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blake3.cpp.o
[ 13%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/xxhash.cpp.o
[ 14%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blake2.cpp.o
[ 15%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/umash.cpp.o
[ 15%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/cityhash.cpp.o
[ 16%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rmd.cpp.o
[ 17%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/t1ha.cpp.o
[ 18%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/abseil.cpp.o
[ 19%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/metrohash.cpp.o
[ 20%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rust-ahash.cpp.o
[ 21%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/highwayhash.cpp.o
[ 21%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/clhash.cpp.o
[ 22%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/discohash.cpp.o
[ 23%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/chaskey.cpp.o
[ 24%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/siphash.cpp.o
[ 25%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/nmhash.cpp.o
[ 26%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/ascon.cpp.o
[ 26%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/prvhash.cpp.o
[ 27%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/vmac.cpp.o
[ 28%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/meowhash.cpp.o
[ 29%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/spookyhash.cpp.o
[ 30%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha2.cpp.o
[ 31%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rainstorm.cpp.o
[ 32%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha1.cpp.o
[ 32%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/farsh.cpp.o
[ 33%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/hasshe2.cpp.o
[ 34%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/perlhashes.cpp.o
[ 35%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/beamsplitter.cpp.o
[ 36%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/khashv.cpp.o
[ 37%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/polymur.cpp.o
[ 37%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/jodyhash.cpp.o
[ 38%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/poly_mersenne.cpp.o
[ 39%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/falkhash.cpp.o
[ 40%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fnv.cpp.o
[ 41%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rainbow.cpp.o
[ 42%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/wyhash.cpp.o
[ 43%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aquahash.cpp.o
[ 43%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesnihash-peterrk.cpp.o
[ 44%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/md5.cpp.o
[ 45%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash3.cpp.o
[ 46%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/museair.cpp.o
[ 47%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/mx3.cpp.o
[ 48%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/crc.cpp.o
[ 50%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rapidhash.cpp.o
[ 50%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/pearson.cpp.o
[ 51%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/multiply_shift.cpp.o
[ 52%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/komihash.cpp.o
[ 53%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/aesnihash-majek.cpp.o
[ 54%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/tabulation.cpp.o
[ 55%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/khash.cpp.o
[ 55%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash2.cpp.o
[ 56%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fletcher.cpp.o
[ 57%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/floppsyhash.cpp.o
[ 58%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/seahash.cpp.o
[ 59%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/crap.cpp.o
[ 60%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/blockpearson.cpp.o
[ 61%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/sha3.cpp.o
[ 61%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/lookup3.cpp.o
[ 62%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmurhash1.cpp.o
[ 63%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/rust-fxhash.cpp.o
[ 64%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/falcon_oaat.cpp.o
[ 65%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/fasthash.cpp.o
[ 66%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/pengyhash.cpp.o
[ 66%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/superfasthash.cpp.o
[ 67%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/o1hash.cpp.o
[ 68%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/murmur_oaat.cpp.o
[ 69%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/x17.cpp.o
[ 70%] Linking CXX static library libSMHasher3Hashlib.a
[ 70%] Built target SMHasher3Hashlib
[ 71%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Platform.cpp.o
[ 72%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Analyze.cpp.o
[ 72%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Blob.cpp.o
[ 73%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Blobsort.cpp.o
[ 74%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Reporting.cpp.o
[ 75%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Random.cpp.o
[ 76%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Stats.cpp.o
[ 77%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/VCode.cpp.o
[ 77%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/Wordlist.cpp.o
[ 78%] Building CXX object CMakeFiles/SMHasher3Tests.dir/util/TestGlobals.cpp.o
[ 79%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SanityTest.cpp.o
[ 80%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/AvalancheTest.cpp.o
[ 81%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BitflipTest.cpp.o
[ 82%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BitIndependenceTest.cpp.o
[ 83%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/HashMapTest.cpp.o
[ 83%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SparseKeysetTest.cpp.o
[ 84%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/ZeroesKeysetTest.cpp.o
[ 85%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/CyclicKeysetTest.cpp.o
[ 86%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/TwoBytesKeysetTest.cpp.o
[ 87%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/TextKeysetTest.cpp.o
[ 88%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/PermutationKeysetTest.cpp.o
[ 88%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedTest.cpp.o
[ 89%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedZeroesTest.cpp.o
[ 90%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedSparseTest.cpp.o
[ 91%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBitflipTest.cpp.o
[ 92%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBlockLenTest.cpp.o
[ 93%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBlockOffsetTest.cpp.o
[ 94%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedAvalancheTest.cpp.o
[ 94%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SeedBitIndependenceTest.cpp.o
[ 95%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/BadSeedsTest.cpp.o
[ 96%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/PerlinNoiseTest.cpp.o
[ 97%] Building CXX object CMakeFiles/SMHasher3Tests.dir/tests/SpeedTest.cpp.o
[ 98%] Linking CXX static library libSMHasher3Tests.a
[ 98%] Built target SMHasher3Tests
[ 98%] Built target SMHasher3Version
[ 98%] Building CXX object CMakeFiles/SMHasher3.dir/main.cpp.o
[100%] Linking CXX executable SMHasher3.exe
[100%] Built target SMHasher3

Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS /e/[About Programming]/[CodeProjects]/C++/smhasher3/build
#
```

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

SMHasher3 Tester Toolkit Results on a 12th Gen Intel(R) Core(TM) i7-12700K CPU

#### C++ SMHasher3

**测试 wyhash “非严格”版本**
./SMHasher3 --test=Speed wyhash

**测试 wyhash.strict 严格版本**
./SMHasher3 --test=Speed wyhash.strict

**测试 rapidhash “普通”版本**
./SMHasher3 --test=Speed rapidhash

**测试 rapidhash.protected 受保护版本**
./SMHasher3 --test=Speed rapidhash.protected

**测试 MuseAir “标准”版本**
./SMHasher3 --test=Speed MuseAir

**测试 MuseAir “致盲覆盖快速版本”版本**
./SMHasher3 --test=Speed MuseAir-BFast

**包含额外安全测试 MuseAir-BFast 并行加速版本（使用 16 核 CPU）**
./SMHasher3 --extra --ncpu=16 MuseAir-BFast

#### 小规模密钥速度测试（1到31字节密钥）

![Small Key Speed Test](images/Small%20Key%20Speed%20Test%20-%20Cycles%20per%20Hash%20vs%20Key%20Size%20%5B1%2C%2031%5D-byte%20keys.png)

#### 大规模密钥速度测试（262144字节密钥）

![Bulk Speed Test](images/Bulk%20Speed%20Test%20-%20GiBsec%20vs%20Alignment%20for%20wyhash%2C%20rapidhash%2C%20MuseAir%2C%20and%20MuseAir-BFast.png)
