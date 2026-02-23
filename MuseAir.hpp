/*
 * MuseAir Hash Algorithm Implementation
 * 
 * Copyright (C) 2024-present MuseAir contributors
 * 
 * This file is part of the MuseAir project and is distributed under the terms of the GNU General Public License v3.0.
 * 
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * 
 * We are contributors to this algorithm. The original author is K--Aethiax.
 * GitHub: https://github.com/eternal-io/museair
 * 
 * This C++ third-party version is published by Twilight-Dream-Of-Magic.
 */

#pragma once
#if !defined( NON_CRYPTOGRAPHIC_HASH_MUSE_AIR_HPP )
#define NON_CRYPTOGRAPHIC_HASH_MUSE_AIR_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <algorithm>
#include <bit>		// for std::endian std::rotl std::rotr
#include <cstring>	// for std::memcpy

// MSVC provides _umul128 on x64 in <intrin.h>. Do not include x86 SIMD headers unconditionally.
// MSVC 在 x64 下通过 <intrin.h> 提供 _umul128；不要无条件引入 x86 SIMD 相关头文件。
#if defined( _MSC_VER ) && ( defined( _M_X64 ) || defined( __x86_64__ ) )
#include <intrin.h>
#endif

#if defined( _MSC_VER )
#define FORCE_INLINE __forceinline
#define NEVER_INLINE __declspec( noinline )
#elif defined( __GNUC__ ) || defined( __clang__ )
#define FORCE_INLINE __attribute__( ( always_inline ) ) inline
#define NEVER_INLINE __attribute__( ( noinline ) )
#else
#define FORCE_INLINE inline
#define NEVER_INLINE
#endif

//#if defined(__GNUC__) || defined(__clang__)
//#define LIKELY(x)   __builtin_expect(!!(x), 1)
//#define UNLIKELY(x) __builtin_expect(!!(x), 0)
//#elif defined(_MSC_VER)
//#define LIKELY(x)   (x)
//#define UNLIKELY(x) (x)
//#else
//#define LIKELY(x)   (x)
//#define UNLIKELY(x) (x)
//#endif

// 定义一个常量数组MUSEAIR_CONSTANT，包含7个uint64_t元素，作为哈希算法的默认密钥。
// MUSEAIR_CONSTANT is a constant array containing 7 uint64_t elements, serving as the default secret key for the hash algorithm.
// `AiryAi(0)` mantissa calculated by Y-Cruncher.
constexpr std::array<uint64_t, 7> MUSEAIR_CONSTANT = 
{
	0x5ae31e589c56e17a,
	0x96d7bb04e64f6da9,
	0x7ab1006b26f9eb64,
	0x21233394220b8457,
	0x047cb9557c9f3b43,
	0xd24f2590c0bcee28,
	
	// 定义一个常量INITIALIZE_RING_PREV，用于初始化环形累加器的前一个值，作为哈希过程中的初始参数。
	//INITIALIZE_RING_PREV is a constant used to initialize the previous value of the ring accumulator, serving as an initial parameter in the hashing process.
	0x33ea8f71bb6016d8,
};

// 定义一个内联函数segment_size，用于计算给定数字乘以8后的值，常用于字节数转换。
// Define an inline function seg that calculates the given number multiplied by 8, commonly used for byte conversions.
constexpr size_t segment_size( size_t n )
{
	return n * 8;
}

// 定义一个结构模板Values2，包含两个类型为Type的成员变量first和second，用于存储两组相关值。
// Define a struct template Values2 with two member variables of type Type, first and second, used to store two related values.
template <typename Type>
struct Values2
{
	Type first;
	Type second;
};

// 定义一个结构模板Values3，包含三个类型为Type的成员变量first、second和third，用于存储三组相关值。
// Define a struct template Values3 with three member variables of type Type, first, second, and third, used to store three related values.
template <typename Type>
struct Values3
{
	Type first;
	Type second;
	Type third;
};

// 辅助函数，用于交换字节顺序（用于小端/大端转换）
// Helper function to swap byte order (for little-endian/big-endian conversion)
FORCE_INLINE uint64_t swap_uint64( uint64_t value )
{
	// 按位操作，将64位的值转换成相反的字节顺序
	// Bitwise operations to convert the 64-bit value to the opposite byte order
	return ( ( value >> 56 ) & 0x00000000000000FF ) | ( ( value >> 40 ) & 0x000000000000FF00 ) | ( ( value >> 24 ) & 0x0000000000FF0000 ) | ( ( value >> 8 ) & 0x00000000FF000000 ) | ( ( value << 8 ) & 0x000000FF00000000 ) | ( ( value << 24 ) & 0x0000FF0000000000 ) | ( ( value << 40 ) & 0x00FF000000000000 ) | ( ( value << 56 ) & 0xFF00000000000000 );
}

// 辅助函数，用于交换32位整数的字节顺序（用于小端/大端转换）
// Helper function to swap the byte order of a 32-bit integer (for little-endian/big-endian conversion)
FORCE_INLINE uint32_t swap_uint32( uint32_t value )
{
	return ( ( value >> 24 ) & 0x000000FF ) | ( ( value >> 8 ) & 0x0000FF00 ) | ( ( value << 8 ) & 0x00FF0000 ) | ( ( value << 24 ) & 0xFF000000 );
}

// 读取64位无符号整数的模板函数，支持字节顺序的自动调整
// Template function to read a 64-bit unsigned integer, supporting automatic byte order adjustment
template <bool ByteSwap>
FORCE_INLINE uint64_t read_u64( const uint8_t* p )
{
	uint64_t value;
	std::memcpy( &value, p, sizeof( value ) );
	if constexpr ( ByteSwap )
	{
		return swap_uint64( value );
	}
	else
	{
		return value;
	}
}

// 读取32位无符号整数的模板函数，支持字节顺序的自动调整
// Template function to read a 32-bit unsigned integer, supporting automatic byte order adjustment
template <bool ByteSwap>
FORCE_INLINE uint64_t read_u32( const uint8_t* p )
{
	uint32_t value;
	std::memcpy( &value, p, sizeof( value ) );
	if constexpr ( ByteSwap )
	{
		return swap_uint32( value );
	}
	else
	{
		return value;
	}
}

// 写入64位无符号整数的模板函数，支持字节顺序的自动调整
// Template function to write a 64-bit unsigned integer, supporting automatic byte order adjustment
template <bool ByteSwap>
FORCE_INLINE void write_u64( uint8_t* p, uint64_t& value )
{
	uint64_t v = value;
	if constexpr ( ByteSwap )
	{
		v = swap_uint64( v );
	}
	std::memcpy( p, &v, sizeof( v ) );
}

// 写入32位无符号整数的模板函数，支持字节顺序的自动调整
// Template function to write a 32-bit unsigned integer, supporting automatic byte order adjustment
template <bool ByteSwap>
FORCE_INLINE void write_u32( uint8_t* p, uint32_t& value )
{
	uint32_t v = value;
	if constexpr ( ByteSwap )
	{
		v = swap_uint32( v );
	}
	std::memcpy( p, &v, sizeof( v ) );
}

/**
 * @brief Reads and processes a short sequence of bytes, converting it into two 64-bit values.
 * 
 * This function reads a byte array and interprets the data based on the provided length.
 * If the length is 4 or more, it combines two 32-bit values into two 64-bit values.
 * For shorter lengths, it packs bytes into a 64-bit value, handling both little-endian and big-endian formats.
 * 
 * @tparam ByteSwap A boolean indicating whether to swap byte order (true for swapping, false for no swap).
 * @param bytes The input byte array to read from.
 * @param length The length of the byte array.
 * @param values A reference to a Values2<uint64_t> structure where the output values are stored.
 */
template <bool ByteSwap>
FORCE_INLINE void read_short( const uint8_t* bytes, const size_t length, Values2<uint64_t>& values )
{
	auto& [ i, j ] = values;

	// 当长度>=4时，读取两个32位的值，并将它们合并成两个64位的值
	// When length >= 4, read two 32-bit values and combine them into two 64-bit values
	if ( length >= 4 )
	{
		int offset = ( length & 24 ) >> ( length >> 3 );  // 对length的值进行位操作来计算偏移量 (length >= 8 ? 4 : 0)
		i = ( read_u32<ByteSwap>( bytes ) << 32 ) | read_u32<ByteSwap>( bytes + length - 4 );
		j = ( read_u32<ByteSwap>( bytes + offset ) << 32 ) | read_u32<ByteSwap>( bytes + length - 4 - offset );
	}
	// 对于小于4字节的长度，按字节顺序处理并打包为64位整数
	// For lengths less than 4 bytes, handle and pack the bytes into a 64-bit integer
	else if ( length > 0 )
	{
		// MSB <-> LSB
		// [0] [0] [0] for len == 1 (0b01)
		// [0] [1] [1] for len == 2 (0b10)
		// [0] [1] [2] for len == 3 (0b11)
		i = ( ( uint64_t )bytes[ 0 ] << 48 ) | ( ( uint64_t )bytes[ length >> 1 ] << 24 ) | ( uint64_t )bytes[ length - 1 ];
		j = 0;
	}
	// 如果长度为0，将i和j初始化为0
	// If the length is 0, initialize i and j to 0
	else
	{
		i = 0;
		j = 0;
	}
}

/**
 * @brief Multiplies two 64-bit integers and stores the result as a 128-bit value.
 * 
 * This function performs a 64-bit multiplication and stores the result in two 64-bit parts,
 * effectively providing a 128-bit result. It leverages platform-specific intrinsics if available,
 * otherwise, it falls back to manual multiplication.
 * 
 * @param x The first 64-bit integer operand.
 * @param y The second 64-bit integer operand.
 * @param result A reference to a Values2<uint64_t> structure where the 128-bit result is stored.
 */
FORCE_INLINE void multiple64_128bit( uint64_t x, uint64_t y, Values2<uint64_t>& result )
{
	auto& [ left, right ] = result;

#if defined( __SIZEOF_INT128__ )
	// 使用128位整数类型进行乘法运算（GCC/Clang支持）
	// Use 128-bit integer type for multiplication (supported by GCC/Clang)
	__uint128_t product = static_cast<__uint128_t>( x ) * static_cast<__uint128_t>( y );
	left = static_cast<uint64_t>( product );
	right = static_cast<uint64_t>( product >> 64 );
#elif defined( _M_X64 ) || defined( __x86_64__ )
	// 使用MSVC的 _umul128 函数进行64位乘法，并得到128位结果
	// Use MSVC's _umul128 function for 64-bit multiplication, yielding a 128-bit result
	left = _umul128( x, y, &right );
#elif defined( __aarch64__ )
	// 在ARM架构上使用__umulh进行64位乘法
	// Use __umulh for 64-bit multiplication on ARM architecture
	left = x * y;
	right = __umulh( x, y );
#elif defined( __POWERPC64__ )
	// 在PowerPC64平台上使用内建的__builtin_mulll_overflow进行乘法
	// Use __builtin_mulll_overflow for multiplication on PowerPC64 platform
	unsigned __int128 product = static_cast<unsigned __int128>( x ) * static_cast<unsigned __int128>( y );
	left = static_cast<uint64_t>( product );
	right = static_cast<uint64_t>( product >> 64 );
#else
	// 如果没有128位整数支持，使用分割乘法方法手动计算128位结果
	// If 128-bit integer support is unavailable, manually compute the 128-bit result using split multiplication
	uint64_t x_high = x >> 32;
	uint64_t x_low = x & 0xFFFFFFFF;
	uint64_t y_high = y >> 32;
	uint64_t y_low = y & 0xFFFFFFFF;

	uint64_t high_high = x_high * y_high;
	uint64_t high_low = x_high * y_low;
	uint64_t low_high = x_low * y_high;
	uint64_t low_low = x_low * y_low;

	uint64_t cross = ( high_low & 0xFFFFFFFF ) + ( low_high & 0xFFFFFFFF ) + ( low_low >> 32 );
	right = high_high + ( high_low >> 32 ) + ( low_high >> 32 ) + ( cross >> 32 );
	left = ( cross << 32 ) | ( low_low & 0xFFFFFFFF );
#endif
}

template <bool BlindFast>
class MuseAir
{
public:
	// 计算64位的MuseAir散列值
	template <bool ByteSwap>
	inline void hash( const void* bytes, const size_t length, const uint64_t seed, void* result )
	{
		Values2<uint64_t> hash_values{ 0, 0 };
		calculate_hash<ByteSwap, false>( bytes, length, seed, hash_values );
		const uint64_t output_lower = hash_values.first;

		if constexpr(std::endian::native == std::endian::little)
		{
			uint64_t output_value = output_lower;
			write_u64<false>( (uint8_t*)result + 0, output_value );
		}
		else
		{
			uint64_t output_value = output_lower;
			write_u64<true>( (uint8_t*)result + 0, output_value );
		}
	}

	// 计算128位的MuseAir散列值
	template <bool ByteSwap>
	inline void hash_128( const void* bytes, const size_t length, const uint64_t seed, void* result )
	{
		Values2<uint64_t> hash_values{ 0, 0 };
		calculate_hash<ByteSwap, true>( bytes, length, seed, hash_values );
		const uint64_t output_lower = hash_values.first;
		const uint64_t output_higher = hash_values.second;

		if constexpr(std::endian::native == std::endian::little)
		{
			uint64_t output_value_0 = output_lower;
			uint64_t output_value_1 = output_higher;
			write_u64<false>( (uint8_t*)result + 0, output_value_0 );
			write_u64<false>( (uint8_t*)result + 8, output_value_1 );
		}
		else
		{
			uint64_t output_value_0 = output_lower;
			uint64_t output_value_1 = output_higher;
			write_u64<true>( (uint8_t*)result + 0, output_value_0 );
			write_u64<true>( (uint8_t*)result + 8, output_value_1 );
		}
	}

private:
	/**
	 * @brief Core hash function shared by 64-bit and 128-bit outputs.
	 *
	 * 该函数是64位与128位输出的共享核心实现，逻辑与官方参考实现保持一致。
	 *
	 * @tparam ByteSwap Whether to swap byte order when reading input.
	 * @tparam OutputIs128Bit Whether to compute 128-bit output.
	 * @param bytes Input message bytes.
	 * @param length Input message length in bytes.
	 * @param seed User-provided seed.
	 * @param output Output values (lower 64-bit always valid; higher 64-bit valid only for 128-bit mode).
	 */
	template <bool ByteSwap, bool OutputIs128Bit>
	static inline void calculate_hash( const void* bytes, const size_t length, const uint64_t seed, Values2<uint64_t>& output )
	{
		if ( length <= segment_size( 4 ) ) [[likely]]
		{
			calculate_hash_short<ByteSwap, OutputIs128Bit>( static_cast<const uint8_t*>( bytes ), length, seed, output );
		}
		else
		{
			calculate_hash_long<ByteSwap, OutputIs128Bit>( static_cast<const uint8_t*>( bytes ), length, seed, output );
		}
	}

	template <bool ByteSwap, bool OutputIs128Bit>
	static FORCE_INLINE void calculate_hash_short( const uint8_t* bytes, const size_t length, const uint64_t seed, Values2<uint64_t>& output )
	{
		uint64_t lower_part_0 = 0;
		uint64_t lower_part_1 = 0;
		uint64_t lower_part_2 = 0;
		uint64_t higher_part_0 = 0;
		uint64_t higher_part_1 = 0;
		uint64_t higher_part_2 = 0;

		Values2<uint64_t> multiplication_result{ 0, 0 };
		multiple64_128bit( seed ^ MUSEAIR_CONSTANT[ 0 ], length ^ MUSEAIR_CONSTANT[ 1 ], multiplication_result );
		lower_part_2 = multiplication_result.first;
		higher_part_2 = multiplication_result.second;

		Values2<uint64_t> first_pair_values{ 0, 0 };
		read_short<ByteSwap>( bytes, length <= 16 ? length : 16, first_pair_values );
		uint64_t first_value = first_pair_values.first ^ ( length ^ lower_part_2 );
		uint64_t second_value = first_pair_values.second ^ ( seed ^ higher_part_2 );

		if ( length > segment_size( 2 ) ) [[unlikely]]
		{
			Values2<uint64_t> second_pair_values{ 0, 0 };
			read_short<ByteSwap>( bytes + segment_size( 2 ), length - segment_size( 2 ), second_pair_values );

			Values2<uint64_t> multiplication_result_0{ 0, 0 };
			Values2<uint64_t> multiplication_result_1{ 0, 0 };
			multiple64_128bit( MUSEAIR_CONSTANT[ 2 ], MUSEAIR_CONSTANT[ 3 ] ^ second_pair_values.first, multiplication_result_0 );
			multiple64_128bit( MUSEAIR_CONSTANT[ 4 ], MUSEAIR_CONSTANT[ 5 ] ^ second_pair_values.second, multiplication_result_1 );

			lower_part_0 = multiplication_result_0.first;
			higher_part_0 = multiplication_result_0.second;
			lower_part_1 = multiplication_result_1.first;
			higher_part_1 = multiplication_result_1.second;

			first_value ^= lower_part_0 ^ higher_part_1;
			second_value ^= lower_part_1 ^ higher_part_0;
		}

		// -------- epilogue for short inputs / 短输入尾段混合 --------
		if constexpr ( OutputIs128Bit )
		{
			Values2<uint64_t> multiplication_result_0{ 0, 0 };
			Values2<uint64_t> multiplication_result_1{ 0, 0 };
			multiple64_128bit( first_value, second_value, multiplication_result_0 );
			multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 2 ], second_value ^ MUSEAIR_CONSTANT[ 3 ], multiplication_result_1 );

			first_value = multiplication_result_0.first ^ multiplication_result_1.second;
			second_value = multiplication_result_1.first ^ multiplication_result_0.second;

			multiple64_128bit( first_value, second_value, multiplication_result_0 );
			multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 4 ], second_value ^ MUSEAIR_CONSTANT[ 5 ], multiplication_result_1 );

			output.first = multiplication_result_0.first ^ multiplication_result_1.second;
			output.second = multiplication_result_1.first ^ multiplication_result_0.second;
		}
		else
		{
			if constexpr ( !BlindFast )
			{
				Values2<uint64_t> multiplication_result_0{ 0, 0 };
				Values2<uint64_t> multiplication_result_1{ 0, 0 };
				multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 2 ], second_value ^ MUSEAIR_CONSTANT[ 3 ], multiplication_result_0 );
				multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 4 ], second_value ^ MUSEAIR_CONSTANT[ 5 ], multiplication_result_1 );

				first_value = multiplication_result_0.first ^ multiplication_result_1.second;
				second_value = multiplication_result_1.first ^ multiplication_result_0.second;

				multiple64_128bit( first_value, second_value, multiplication_result );
				output.first = first_value ^ second_value ^ multiplication_result.first ^ multiplication_result.second;
			}
			else
			{
				// Fast variant: overwrite the working pair by multiply outputs.
				// 快速变体：直接用乘法结果覆盖工作对。
				Values2<uint64_t> multiplication_result_0{ 0, 0 };
				multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 2 ], second_value ^ MUSEAIR_CONSTANT[ 3 ], multiplication_result_0 );
				first_value = multiplication_result_0.first;
				second_value = multiplication_result_0.second;
				multiple64_128bit( first_value ^ MUSEAIR_CONSTANT[ 4 ], second_value ^ MUSEAIR_CONSTANT[ 5 ], multiplication_result_0 );
				output.first = multiplication_result_0.first ^ multiplication_result_0.second;
			}
			output.second = 0;
		}
	}

	template <bool ByteSwap, bool OutputIs128Bit>
	static NEVER_INLINE void calculate_hash_long( const uint8_t* bytes, const size_t length, const uint64_t seed, Values2<uint64_t>& output )
	{
		const uint8_t* byte_pointer = bytes;
		size_t remaining_length = length;

		uint64_t lower_part_0 = 0;
		uint64_t lower_part_1 = 0;
		uint64_t lower_part_2 = 0;
		uint64_t lower_part_3 = 0;
		uint64_t lower_part_4 = 0;
		uint64_t lower_part_5 = MUSEAIR_CONSTANT[ 6 ];
		uint64_t higher_part_0 = 0;
		uint64_t higher_part_1 = 0;
		uint64_t higher_part_2 = 0;
		uint64_t higher_part_3 = 0;
		uint64_t higher_part_4 = 0;
		uint64_t higher_part_5 = 0;

		std::array<uint64_t, 6> state_values =
		{
			MUSEAIR_CONSTANT[ 0 ] + seed,
			MUSEAIR_CONSTANT[ 1 ] - seed,
			MUSEAIR_CONSTANT[ 2 ] ^ seed,
			MUSEAIR_CONSTANT[ 3 ] + seed,
			MUSEAIR_CONSTANT[ 4 ] - seed,
			MUSEAIR_CONSTANT[ 5 ] ^ seed
		};

		// -------- ring accumulator loop / 环形累加器主循环（每次处理96字节） --------
		if ( remaining_length > segment_size( 12 ) ) [[unlikely]]
		{
			do
			{
				if constexpr ( !BlindFast )
				{
					state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) );
					state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) );
					Values2<uint64_t> multiplication_result_0{ 0, 0 };
					multiple64_128bit( state_values[ 0 ], state_values[ 1 ], multiplication_result_0 );
					lower_part_0 = multiplication_result_0.first;
					higher_part_0 = multiplication_result_0.second;
					state_values[ 0 ] += ( lower_part_5 ^ higher_part_0 );

					state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) );
					state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) );
					Values2<uint64_t> multiplication_result_1{ 0, 0 };
					multiple64_128bit( state_values[ 1 ], state_values[ 2 ], multiplication_result_1 );
					lower_part_1 = multiplication_result_1.first;
					higher_part_1 = multiplication_result_1.second;
					state_values[ 1 ] += ( lower_part_0 ^ higher_part_1 );

					state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 4 ) );
					state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 5 ) );
					Values2<uint64_t> multiplication_result_2{ 0, 0 };
					multiple64_128bit( state_values[ 2 ], state_values[ 3 ], multiplication_result_2 );
					lower_part_2 = multiplication_result_2.first;
					higher_part_2 = multiplication_result_2.second;
					state_values[ 2 ] += ( lower_part_1 ^ higher_part_2 );

					state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 6 ) );
					state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 7 ) );
					Values2<uint64_t> multiplication_result_3{ 0, 0 };
					multiple64_128bit( state_values[ 3 ], state_values[ 4 ], multiplication_result_3 );
					lower_part_3 = multiplication_result_3.first;
					higher_part_3 = multiplication_result_3.second;
					state_values[ 3 ] += ( lower_part_2 ^ higher_part_3 );

					state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 8 ) );
					state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 9 ) );
					Values2<uint64_t> multiplication_result_4{ 0, 0 };
					multiple64_128bit( state_values[ 4 ], state_values[ 5 ], multiplication_result_4 );
					lower_part_4 = multiplication_result_4.first;
					higher_part_4 = multiplication_result_4.second;
					state_values[ 4 ] += ( lower_part_3 ^ higher_part_4 );

					state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 10 ) );
					state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 11 ) );
					Values2<uint64_t> multiplication_result_5{ 0, 0 };
					multiple64_128bit( state_values[ 5 ], state_values[ 0 ], multiplication_result_5 );
					lower_part_5 = multiplication_result_5.first;
					higher_part_5 = multiplication_result_5.second;
					state_values[ 5 ] += ( lower_part_4 ^ higher_part_5 );
				}
				else
				{
					state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) );
					state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) );
					Values2<uint64_t> multiplication_result_0{ 0, 0 };
					multiple64_128bit( state_values[ 0 ], state_values[ 1 ], multiplication_result_0 );
					lower_part_0 = multiplication_result_0.first;
					higher_part_0 = multiplication_result_0.second;
					state_values[ 0 ] = ( lower_part_5 ^ higher_part_0 );

					state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) );
					state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) );
					Values2<uint64_t> multiplication_result_1{ 0, 0 };
					multiple64_128bit( state_values[ 1 ], state_values[ 2 ], multiplication_result_1 );
					lower_part_1 = multiplication_result_1.first;
					higher_part_1 = multiplication_result_1.second;
					state_values[ 1 ] = ( lower_part_0 ^ higher_part_1 );

					state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 4 ) );
					state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 5 ) );
					Values2<uint64_t> multiplication_result_2{ 0, 0 };
					multiple64_128bit( state_values[ 2 ], state_values[ 3 ], multiplication_result_2 );
					lower_part_2 = multiplication_result_2.first;
					higher_part_2 = multiplication_result_2.second;
					state_values[ 2 ] = ( lower_part_1 ^ higher_part_2 );

					state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 6 ) );
					state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 7 ) );
					Values2<uint64_t> multiplication_result_3{ 0, 0 };
					multiple64_128bit( state_values[ 3 ], state_values[ 4 ], multiplication_result_3 );
					lower_part_3 = multiplication_result_3.first;
					higher_part_3 = multiplication_result_3.second;
					state_values[ 3 ] = ( lower_part_2 ^ higher_part_3 );

					state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 8 ) );
					state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 9 ) );
					Values2<uint64_t> multiplication_result_4{ 0, 0 };
					multiple64_128bit( state_values[ 4 ], state_values[ 5 ], multiplication_result_4 );
					lower_part_4 = multiplication_result_4.first;
					higher_part_4 = multiplication_result_4.second;
					state_values[ 4 ] = ( lower_part_3 ^ higher_part_4 );

					state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 10 ) );
					state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 11 ) );
					Values2<uint64_t> multiplication_result_5{ 0, 0 };
					multiple64_128bit( state_values[ 5 ], state_values[ 0 ], multiplication_result_5 );
					lower_part_5 = multiplication_result_5.first;
					higher_part_5 = multiplication_result_5.second;
					state_values[ 5 ] = ( lower_part_4 ^ higher_part_5 );
				}

				byte_pointer += segment_size( 12 );
				remaining_length -= segment_size( 12 );

			} while ( remaining_length > segment_size( 12 ) );

			// Do not forget this final state update.
			// 不要忘记这次最终状态更新。
			state_values[ 0 ] ^= lower_part_5;
		}

		// Reset multiplication scratch values.
		// 重置乘法临时变量。
		lower_part_0 = 0;
		lower_part_1 = 0;
		lower_part_2 = 0;
		lower_part_3 = 0;
		lower_part_4 = 0;
		lower_part_5 = 0;
		higher_part_0 = 0;
		higher_part_1 = 0;
		higher_part_2 = 0;
		higher_part_3 = 0;
		higher_part_4 = 0;
		higher_part_5 = 0;

		// -------- partial body / 分段主体（最多读取前80字节） --------
		if ( remaining_length > segment_size( 4 ) ) [[likely]]
		{
			state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) );
			state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) );
			Values2<uint64_t> multiplication_result_0{ 0, 0 };
			multiple64_128bit( state_values[ 0 ], state_values[ 1 ], multiplication_result_0 );
			lower_part_0 = multiplication_result_0.first;
			higher_part_0 = multiplication_result_0.second;

			if ( remaining_length > segment_size( 6 ) ) [[likely]]
			{
				state_values[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) );
				state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) );
				Values2<uint64_t> multiplication_result_1{ 0, 0 };
				multiple64_128bit( state_values[ 1 ], state_values[ 2 ], multiplication_result_1 );
				lower_part_1 = multiplication_result_1.first;
				higher_part_1 = multiplication_result_1.second;

				if ( remaining_length > segment_size( 8 ) ) [[likely]]
				{
					state_values[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 4 ) );
					state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 5 ) );
					Values2<uint64_t> multiplication_result_2{ 0, 0 };
					multiple64_128bit( state_values[ 2 ], state_values[ 3 ], multiplication_result_2 );
					lower_part_2 = multiplication_result_2.first;
					higher_part_2 = multiplication_result_2.second;

					if ( remaining_length > segment_size( 10 ) ) [[likely]]
					{
						state_values[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 6 ) );
						state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size( 7 ) );
						Values2<uint64_t> multiplication_result_3{ 0, 0 };
						multiple64_128bit( state_values[ 3 ], state_values[ 4 ], multiplication_result_3 );
						lower_part_3 = multiplication_result_3.first;
						higher_part_3 = multiplication_result_3.second;
					}
				}
			}
		}

		// -------- mandatory tail processing / 必定执行的尾部处理 --------
		state_values[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + remaining_length - segment_size( 4 ) );
		state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + remaining_length - segment_size( 3 ) );
		Values2<uint64_t> multiplication_result_4{ 0, 0 };
		multiple64_128bit( state_values[ 4 ], state_values[ 5 ], multiplication_result_4 );
		lower_part_4 = multiplication_result_4.first;
		higher_part_4 = multiplication_result_4.second;

		state_values[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + remaining_length - segment_size( 2 ) );
		state_values[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + remaining_length - segment_size( 1 ) );
		Values2<uint64_t> multiplication_result_5{ 0, 0 };
		multiple64_128bit( state_values[ 5 ], state_values[ 0 ], multiplication_result_5 );
		lower_part_5 = multiplication_result_5.first;
		higher_part_5 = multiplication_result_5.second;

		uint64_t mix_value_0 = state_values[ 0 ] - state_values[ 1 ];
		uint64_t mix_value_1 = state_values[ 2 ] - state_values[ 3 ];
		uint64_t mix_value_2 = state_values[ 4 ] - state_values[ 5 ];

		const int rotation_amount = static_cast<int>( length & 63 );
		mix_value_0 = std::rotl( mix_value_0, rotation_amount );
		mix_value_1 = std::rotr( mix_value_1, rotation_amount );
		mix_value_2 ^= length;

		mix_value_0 += ( lower_part_3 ^ higher_part_3 ^ lower_part_4 ^ higher_part_4 );
		mix_value_1 += ( lower_part_5 ^ higher_part_5 ^ lower_part_0 ^ higher_part_0 );
		mix_value_2 += ( lower_part_1 ^ higher_part_1 ^ lower_part_2 ^ higher_part_2 );

		Values2<uint64_t> multiplication_result_0{ 0, 0 };
		Values2<uint64_t> multiplication_result_1{ 0, 0 };
		Values2<uint64_t> multiplication_result_2{ 0, 0 };
		multiple64_128bit( mix_value_0, mix_value_1, multiplication_result_0 );
		multiple64_128bit( mix_value_1, mix_value_2, multiplication_result_1 );
		multiple64_128bit( mix_value_2, mix_value_0, multiplication_result_2 );

		if constexpr ( OutputIs128Bit )
		{
			output.first = multiplication_result_0.first ^ multiplication_result_1.first ^ multiplication_result_2.second;
			output.second = multiplication_result_0.second ^ multiplication_result_1.second ^ multiplication_result_2.first;
		}
		else
		{
			output.first = ( multiplication_result_0.first ^ multiplication_result_2.second )
				+ ( multiplication_result_1.first ^ multiplication_result_0.second )
				+ ( multiplication_result_2.first ^ multiplication_result_1.second );
			output.second = 0;
		}
	}
};

#endif // NON_CRYPTOGRAPHIC_HASH_MUSE_AIR_HPP
