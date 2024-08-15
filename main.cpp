#include <cstring> // for memset
#include <iostream>
#include <iomanip> // For std::hex

#include "MuseAir.hpp"

inline void print_hash_values()
{
	// 测试数据
	const uint8_t data1[] = "Hello, World!";
	const uint8_t data2[] = "The quick brown fox jumps over the lazy dog.";
	const uint8_t data3[] = "This is a very long string to test the performance of the hash function over a larger input.";

	uint64_t seed = 0x123456789ABCDEF0;

	// 创建MuseAir对象
	MuseAir<false> museAirStandard;	  // 不使用BlindFast优化
	MuseAir<true>  museAirOptimized;  // 使用BlindFast优化

	// 计算64位哈希
	uint64_t hash1;
	uint64_t hash2;
	uint64_t hash3;

	museAirStandard.hash<false>( data1, strlen( reinterpret_cast<const char*>( data1 ) ), seed, &hash1 );
	museAirStandard.hash<false>( data2, strlen( reinterpret_cast<const char*>( data2 ) ), seed, &hash2 );
	museAirStandard.hash<false>( data3, strlen( reinterpret_cast<const char*>( data3 ) ), seed, &hash3 );

	uint64_t hashOptimized1;
	uint64_t hashOptimized2;
	uint64_t hashOptimized3;

	museAirOptimized.hash<false>( data1, strlen( reinterpret_cast<const char*>( data1 ) ), seed, &hashOptimized1 );
	museAirOptimized.hash<false>( data2, strlen( reinterpret_cast<const char*>( data2 ) ), seed, &hashOptimized2 );
	museAirOptimized.hash<false>( data3, strlen( reinterpret_cast<const char*>( data3 ) ), seed, &hashOptimized3 );

	// 打印结果
	std::cout << "Hash for data1 (Standard): " << std::hex << hash1 << std::endl;
	std::cout << "Hash for data2 (Standard): " << std::hex << hash2 << std::endl;
	std::cout << "Hash for data3 (Standard): " << std::hex << hash3 << std::endl;

	std::cout << "Hash for data1 (Optimized): " << std::hex << hashOptimized1 << std::endl;
	std::cout << "Hash for data2 (Optimized): " << std::hex << hashOptimized2 << std::endl;
	std::cout << "Hash for data3 (Optimized): " << std::hex << hashOptimized3 << std::endl;

	// 计算128位哈希
	uint8_t hash128_1[ 16 ];
	uint8_t hash128_2[ 16 ];
	uint8_t hash128_3[ 16 ];

	museAirStandard.hash_128<false>( data1, strlen( reinterpret_cast<const char*>( data1 ) ), seed, hash128_1 );
	museAirStandard.hash_128<false>( data2, strlen( reinterpret_cast<const char*>( data2 ) ), seed, hash128_2 );
	museAirStandard.hash_128<false>( data3, strlen( reinterpret_cast<const char*>( data3 ) ), seed, hash128_3 );

	uint8_t hash128Optimized1[ 16 ];
	uint8_t hash128Optimized2[ 16 ];
	uint8_t hash128Optimized3[ 16 ];

	museAirOptimized.hash_128<false>( data1, strlen( reinterpret_cast<const char*>( data1 ) ), seed, hash128Optimized1 );
	museAirOptimized.hash_128<false>( data2, strlen( reinterpret_cast<const char*>( data2 ) ), seed, hash128Optimized2 );
	museAirOptimized.hash_128<false>( data3, strlen( reinterpret_cast<const char*>( data3 ) ), seed, hash128Optimized3 );

	// 打印结果
	std::cout << "Hash128 for data1 (Standard): " << std::hex << *reinterpret_cast<uint64_t*>( hash128_1 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128_1 + 8 ) << std::endl;

	std::cout << "Hash128 for data2 (Standard): " << std::hex << *reinterpret_cast<uint64_t*>( hash128_2 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128_2 + 8 ) << std::endl;

	std::cout << "Hash128 for data3 (Standard): " << std::hex << *reinterpret_cast<uint64_t*>( hash128_3 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128_3 + 8 ) << std::endl;

	std::cout << "Hash128 for data1 (Optimized): " << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized1 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized1 + 8 ) << std::endl;

	std::cout << "Hash128 for data2 (Optimized): " << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized2 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized2 + 8 ) << std::endl;

	std::cout << "Hash128 for data3 (Optimized): " << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized3 ) << std::hex << *reinterpret_cast<uint64_t*>( hash128Optimized3 + 8 ) << std::endl;
}


int main()
{
	print_hash_values();
	if ( hash_selftest() )
	{
		std::cout << "Congratulations on the successful implementation of the MuseAir algorithm! (64-Bits) All test vectors have passed." << std::endl;
	}
	if ( hash_128_selftest() )
	{
		std::cout << "Congratulations on the successful implementation of the MuseAir algorithm! (128-Bits) All test vectors have passed." << std::endl;
	}
	if ( hash_blindfast_selftest() )
	{
		std::cout << "Congratulations on the successful implementation of the MuseAir algorithm! (64-Bits BlindFast) All test vectors have passed." << std::endl;
	}
	if ( hash_128_blindfast_selftest() )
	{
		std::cout << "Congratulations on the successful implementation of the MuseAir algorithm! (128-Bits BlindFast) All test vectors have passed." << std::endl;
	}
}
