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

#include <immintrin.h>
#include <cstdint>
#include <array>
#include <vector>
#include <algorithm>
#include <bit>		// for std::endian std::rotl std::rotr

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
FORCE_INLINE void mumix(uint64_t input_p, uint64_t input_q, uint64_t* state_p, uint64_t* state_q )
{
	if constexpr( !BlindFast )
	{
		Values2<uint64_t> result{0, 0};
		*state_p ^= input_p;
		*state_q ^= input_q;
		multiple64_128bit( *state_p, *state_q, result );
		auto& [low, high] = result;
		*state_p ^= low;
		*state_q ^= high;
	}
	else
	{
		Values2<uint64_t> result{0, 0};
		multiple64_128bit( *state_p ^ input_p, *state_q ^ input_q,  result );
		*state_p = result.first;
		*state_q = result.second;
	}
}

template <bool BlindFast>
class MuseAir
{
public:
	// 计算64位的MuseAir散列值
	template <bool ByteSwap>
	inline void hash( const void* bytes, const size_t length, const uint64_t seed, void* result )
	{
		Values2<uint64_t> hash_values {0, 0};
		auto& [out_lo, out_hi] = hash_values;

		if ( length <= segment_size(4) ) [[likely]]
		{
			// 更可能会执行的分支
			// Short

			uint64_t low0 = 0, low1 = 0, low2 = 0;
			uint64_t high0 = 0, high1 = 0, high2 = 0;

			Values2<uint64_t> values_0{0, 0};
			multiple64_128bit(seed ^ MUSEAIR_CONSTANT[0], length ^ MUSEAIR_CONSTANT[1], values_0);
			low2  = values_0.first;
			high2 = values_0.second;

			Values2<uint64_t> half_hash_state{0, 0};
			read_short<ByteSwap>((uint8_t*)bytes, length <= 16 ? length : 16, half_hash_state);
			auto& [i, j] = half_hash_state;
			i ^= length ^ low2;
			j ^= seed ^ high2;

			if (length > segment_size(2)) [[unlikely]]
			{
				Values2<uint64_t> values_1{0, 0};
				read_short<ByteSwap>((uint8_t*)bytes + segment_size(2), length - segment_size(2), values_1);
				Values2<uint64_t> a {0, 0};
				Values2<uint64_t> b {0, 0};
				multiple64_128bit(MUSEAIR_CONSTANT[2], MUSEAIR_CONSTANT[3] ^ values_1.first, a);
				multiple64_128bit(MUSEAIR_CONSTANT[4], MUSEAIR_CONSTANT[5] ^ values_1.second, b);
				low0 = a.first, high0 = a.second;
				low1 = b.first, high1 = b.second;
				i ^= low0 ^ high1;
				j ^= low1 ^ high0;
			}

			/*-------- epilogue short 64-bit --------*/

			multiple64_128bit(i ^ MUSEAIR_CONSTANT[2], j ^ MUSEAIR_CONSTANT[3], values_0);
			low2 = values_0.first;
			high2 = values_0.second;
			if constexpr ( !BlindFast )
			{
				i ^= low2;
				j ^= high2;
			}
			else
			{
				i = low2;
				j = high2;
			}
			multiple64_128bit(i ^ MUSEAIR_CONSTANT[ 4 ], j ^ MUSEAIR_CONSTANT[ 5 ], values_0);
			low2 = values_0.first;
			high2 = values_0.second;
			if constexpr ( !BlindFast )
			{
				out_lo = i ^ j ^ low2 ^ high2;
			}
			else
			{
				out_lo = low2 ^ high2;
			}
		}
		else
		{
			// Loong

			uint64_t low0 = 0, low1 = 0, low2 = 0, low3 = 0, low4 = 0, low5 = MUSEAIR_CONSTANT[6];
			uint64_t high0 = 0, high1 = 0, high2 = 0, high3 = 0, high4 = 0, high5 = 0;

			const uint8_t* byte_pointer = (uint8_t*)bytes;
			size_t offset = length;

			std::array<uint64_t, 6> state_array =
			{ 
				MUSEAIR_CONSTANT[ 0 ] + seed,
				MUSEAIR_CONSTANT[ 1 ] - seed,
				MUSEAIR_CONSTANT[ 2 ] ^ seed,
				MUSEAIR_CONSTANT[ 3 ] + seed,
				MUSEAIR_CONSTANT[ 4 ] - seed,
				MUSEAIR_CONSTANT[ 5 ] ^ seed
			};

			if(offset >= segment_size(12)) [[unlikely]]
			{
				Values2<uint64_t> ring_accumulator_values {0, 0};
				do
				{
					//Ring accumulator
					if constexpr ( !BlindFast )
					{
						// If BlindFast mode is not enabled, apply full processing including modular additions
						// 如果未启用BlindFast模式，则应用包括模加操作在内的完整处理

						// First pair (state[0] and state[1])
						// 处理第一对（state[0] 和 state[1]）
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer );
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(1) );
						multiple64_128bit( state_array[ 0 ], state_array[ 1 ], ring_accumulator_values );
						low0 = ring_accumulator_values.first;
						high0 = ring_accumulator_values.second;
						state_array[ 0 ] += ( low5 ^ high0 );
						// Update state with ring accumulator and high0
						// 使用环形累加器和high0更新状态

						// Second pair (state[1] and state[2])
						// 处理第二对（state[1] 和 state[2]）
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(2) );
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(3) );
						multiple64_128bit( state_array[ 1 ], state_array[ 2 ], ring_accumulator_values );
						low1 = ring_accumulator_values.first;
						high1 = ring_accumulator_values.second;
						state_array[ 1 ] += ( low0 ^ high1 );
						// Update state with low0 and high1
						// 使用low0和high1更新状态

						// Third pair (state[2] and state[3])
						// 处理第三对（state[2] 和 state[3]）
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(4) );
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(5) );
						multiple64_128bit( state_array[ 2 ], state_array[ 3 ], ring_accumulator_values );
						low2 = ring_accumulator_values.first;
						high2 = ring_accumulator_values.second;
						state_array[ 2 ] += ( low1 ^ high2 );
						// Update state with low1 and high2
						// 使用low1和high2更新状态

						// Fourth pair (state[3] and state[4])
						// 处理第四对（state[3] 和 state[4]）
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(6) );
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(7) );
						multiple64_128bit( state_array[ 3 ], state_array[ 4 ], ring_accumulator_values );
						low3 = ring_accumulator_values.first;
						high3 = ring_accumulator_values.second;
						state_array[ 3 ] += ( low2 ^ high3 );
						// Update state with low2 and high3
						// 使用low2和high3更新状态

						// Fifth pair (state[4] and state[5])
						// 处理第五对（state[4] 和 state[5]）
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(8) );
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(9) );
						multiple64_128bit( state_array[ 4 ], state_array[ 5 ], ring_accumulator_values );
						low4 = ring_accumulator_values.first;
						high4 = ring_accumulator_values.second;
						state_array[ 4 ] += ( low3 ^ high4 );
						// Update state with low3 and high4
						// 使用low3和high4更新状态

						// Final pair (state[5] and state[0])
						// 处理最后一对（state[5] 和 state[0]）
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(10) );
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(11) );
						multiple64_128bit( state_array[ 5 ], state_array[ 0 ], ring_accumulator_values );
						low5 = ring_accumulator_values.first;
						high5 = ring_accumulator_values.second;
						state_array[ 5 ] += ( low4 ^ high5 );
						// Update state with low4 and high5
						// 使用low4和high5更新状态
					}
					else
					{
						// Apply the BlindFast mode optimizations by directly setting the state without modular additions
						// 应用BlindFast模式优化，直接设置状态而不进行模加操作

						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer );
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(1) );
						multiple64_128bit( state_array[ 0 ], state_array[ 1 ], ring_accumulator_values );
						low0 = ring_accumulator_values.first;
						high0 = ring_accumulator_values.second;
						state_array[ 0 ] = ( low5 ^ high0 );
						// Directly set state with ring accumulator and high0
						// 直接使用环形累加器和high0设置状态

						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(2) );
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(3) );
						multiple64_128bit( state_array[ 1 ], state_array[ 2 ], ring_accumulator_values );
						low1 = ring_accumulator_values.first;
						high1 = ring_accumulator_values.second;
						state_array[ 1 ] = ( low0 ^ high1 );
						// Directly set state with low0 and high1
						// 直接使用low0和high1设置状态

						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(4) );
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(5) );
						multiple64_128bit( state_array[ 2 ], state_array[ 3 ], ring_accumulator_values );
						low2 = ring_accumulator_values.first;
						high2 = ring_accumulator_values.second;
						state_array[ 2 ] = ( low1 ^ high2 );
						// Directly set state with low1 and high2
						// 直接使用low1和high2设置状态

						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(6) );
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(7) );
						multiple64_128bit( state_array[ 3 ], state_array[ 4 ], ring_accumulator_values );
						low3 = ring_accumulator_values.first;
						high3 = ring_accumulator_values.second;
						state_array[ 3 ] = ( low2 ^ high3 );
						// Directly set state with low2 and high3
						// 直接使用low2和high3设置状态

						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(8) );
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(9) );
						multiple64_128bit( state_array[ 4 ], state_array[ 5 ], ring_accumulator_values );
						low4 = ring_accumulator_values.first;
						high4 = ring_accumulator_values.second;
						state_array[ 4 ] = ( low3 ^ high4 );
						// Directly set state with low3 and high4
						// 直接使用low3和high4设置状态

						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(10) );
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(11) );
						multiple64_128bit( state_array[ 5 ], state_array[ 0 ], ring_accumulator_values );
						low5 = ring_accumulator_values.first;
						high5 = ring_accumulator_values.second;
						state_array[ 5 ] = ( low4 ^ high5 );
						// Directly set state with low4 and high5
						// 直接使用low4和high5设置状态
					}
					
					byte_pointer += segment_size(12);
					offset -= segment_size(12);

				} while ( offset >= segment_size(12) );

				state_array[0] ^= low5;
			}

			if ( offset >= segment_size( 6 ) ) [[unlikely]]
			{
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) ), &state_array[ 0 ], &state_array[ 1 ] );
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) ), &state_array[ 2 ], &state_array[ 3 ] );
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 4 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 5 ) ), &state_array[ 4 ], &state_array[ 5 ] );

				byte_pointer += segment_size( 6 );
				offset -= segment_size( 6 );
			}

			if ( offset >= segment_size( 2 ) ) [[likely]]
			{
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) ), &state_array[ 0 ], &state_array[ 3 ] );
				if ( offset >= segment_size( 4 ) ) [[likely]]
				{
					mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) ), &state_array[ 1 ], &state_array[ 4 ] );
				}
			}

			mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + offset - segment_size( 2 ) ), read_u64<ByteSwap>( byte_pointer + offset - segment_size( 1 ) ), &state_array[ 2 ], &state_array[ 5 ] );

			/*-------- epilogue loong 64-bit --------*/

			Values3<uint64_t> half_hash_state{0, 0, 0};
			auto& [i, j, k] = half_hash_state;

			i = state_array[0] - state_array[1];
			j = state_array[2] - state_array[3];
			k = state_array[4] - state_array[5];

			Values2<uint64_t> a {0, 0};
			Values2<uint64_t> b {0, 0};
			Values2<uint64_t> c {0, 0};

			i = std::rotl(i, length & 63);
			j = std::rotr(j, length & 63);
			k ^= length;

			multiple64_128bit(i, j, a);
			low0 = a.first, high0 = a.second;
			multiple64_128bit(j, k, b);
			low1 = b.first, high1 = b.second;
			multiple64_128bit(k, i, c);
			low2 = c.first, high2 = c.second;
			i = low0 ^ high2;
			j = low1 ^ high0;
			k = low2 ^ high1;

			// Unique code block
			multiple64_128bit(i, j, a);
			low0 = a.first, high0 = a.second;
			multiple64_128bit(j, k, b);
			low1 = b.first, high1 = b.second;
			multiple64_128bit(k, i, c);
			low2 = c.first, high2 = c.second;
			out_lo = (low0 ^ high2) + (low1 ^ high0) + (low2 ^ high1);
		}

		if constexpr(std::endian::native == std::endian::little)
		{
			write_u64<false>((uint8_t*)result + 0, out_lo);
		}
		else
		{
			write_u64<true>((uint8_t*)result + 0, out_lo);
		}
	}

	// 计算128位的MuseAir散列值
	template <bool ByteSwap>
	inline void hash_128( const void* bytes, const size_t length, const uint64_t seed, void* result )
	{
		Values2<uint64_t> hash_values {0, 0};
		auto& [out_lo, out_hi] = hash_values;

		if ( length <= segment_size(4) ) [[likely]]
		{
			// 更可能会执行的分支
			// Short

			uint64_t low0 = 0, low1 = 0, low2 = 0;
			uint64_t high0 = 0, high1 = 0, high2 = 0;

			Values2<uint64_t> values_0{0, 0};
			multiple64_128bit(seed ^ MUSEAIR_CONSTANT[0], length ^ MUSEAIR_CONSTANT[1], values_0);
			low2  = values_0.first;
			high2 = values_0.second;

			Values2<uint64_t> half_hash_state{0, 0};
			read_short<ByteSwap>((uint8_t*)bytes, length <= 16 ? length : 16, half_hash_state);
			auto& [i, j] = half_hash_state;
			i ^= length ^ low2;
			j ^= seed ^ high2;

			if (length > segment_size(2)) [[unlikely]]
			{
				Values2<uint64_t> values_1{0, 0};
				read_short<ByteSwap>((uint8_t*)bytes + segment_size(2), length - segment_size(2), values_1);
				Values2<uint64_t> a {0, 0};
				Values2<uint64_t> b {0, 0};
				multiple64_128bit(MUSEAIR_CONSTANT[2], MUSEAIR_CONSTANT[3] ^ values_1.first, a);
				multiple64_128bit(MUSEAIR_CONSTANT[4], MUSEAIR_CONSTANT[5] ^ values_1.second, b);
				low0 = a.first, high0 = a.second;
				low1 = b.first, high1 = b.second;
				i ^= low0 ^ high1;
				j ^= low1 ^ high0;
			}

			/*-------- epilogue short 128-bit --------*/

			multiple64_128bit(i, j, values_0);
			low0 = values_0.first;
			high0 = values_0.second;
			multiple64_128bit(i ^ MUSEAIR_CONSTANT[2], j ^ MUSEAIR_CONSTANT[3], values_0);
			low1 = values_0.first;
			high1 = values_0.second;
			i = low0 ^ high1;
			j = low1 ^ high0;

			multiple64_128bit(i, j, values_0);
			low0 = values_0.first;
			high0 = values_0.second;
			multiple64_128bit(i ^ MUSEAIR_CONSTANT[4], j ^ MUSEAIR_CONSTANT[5], values_0);
			low1 = values_0.first;
			high1 = values_0.second;
			out_lo = low0 ^ high1;
			out_hi = low1 ^ high0;
		}
		else
		{
			uint64_t low0 = 0, low1 = 0, low2 = 0, low3 = 0, low4 = 0, low5 = MUSEAIR_CONSTANT[6];
			uint64_t high0 = 0, high1 = 0, high2 = 0, high3 = 0, high4 = 0, high5 = 0;

			const uint8_t* byte_pointer = (uint8_t*)bytes;
			size_t offset = length;

			std::array<uint64_t, 6> state_array =
			{ 
				MUSEAIR_CONSTANT[ 0 ] + seed,
				MUSEAIR_CONSTANT[ 1 ] - seed,
				MUSEAIR_CONSTANT[ 2 ] ^ seed,
				MUSEAIR_CONSTANT[ 3 ] + seed,
				MUSEAIR_CONSTANT[ 4 ] - seed,
				MUSEAIR_CONSTANT[ 5 ] ^ seed
			};

			if(offset >= segment_size(12)) [[unlikely]]
			{
				Values2<uint64_t> ring_accumulator_values {0, 0};
				while ( offset >= segment_size(12) )
				{
					//Ring accumulator
					if constexpr ( !BlindFast )
					{
						// If BlindFast mode is not enabled, apply full processing including modular additions
						// 如果未启用BlindFast模式，则应用包括模加操作在内的完整处理

						// First pair (state[0] and state[1])
						// 处理第一对（state[0] 和 state[1]）
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer );
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(1) );
						multiple64_128bit( state_array[ 0 ], state_array[ 1 ], ring_accumulator_values );
						low0 = ring_accumulator_values.first;
						high0 = ring_accumulator_values.second;
						state_array[ 0 ] += ( low5 ^ high0 );
						// Update state with ring accumulator and high0
						// 使用环形累加器和high0更新状态

						// Second pair (state[1] and state[2])
						// 处理第二对（state[1] 和 state[2]）
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(2) );
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(3) );
						multiple64_128bit( state_array[ 1 ], state_array[ 2 ], ring_accumulator_values );
						low1 = ring_accumulator_values.first;
						high1 = ring_accumulator_values.second;
						state_array[ 1 ] += ( low0 ^ high1 );
						// Update state with low0 and high1
						// 使用low0和high1更新状态

						// Third pair (state[2] and state[3])
						// 处理第三对（state[2] 和 state[3]）
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(4) );
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(5) );
						multiple64_128bit( state_array[ 2 ], state_array[ 3 ], ring_accumulator_values );
						low2 = ring_accumulator_values.first;
						high2 = ring_accumulator_values.second;
						state_array[ 2 ] += ( low1 ^ high2 );
						// Update state with low1 and high2
						// 使用low1和high2更新状态

						// Fourth pair (state[3] and state[4])
						// 处理第四对（state[3] 和 state[4]）
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(6) );
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(7) );
						multiple64_128bit( state_array[ 3 ], state_array[ 4 ], ring_accumulator_values );
						low3 = ring_accumulator_values.first;
						high3 = ring_accumulator_values.second;
						state_array[ 3 ] += ( low2 ^ high3 );
						// Update state with low2 and high3
						// 使用low2和high3更新状态

						// Fifth pair (state[4] and state[5])
						// 处理第五对（state[4] 和 state[5]）
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(8) );
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(9) );
						multiple64_128bit( state_array[ 4 ], state_array[ 5 ], ring_accumulator_values );
						low4 = ring_accumulator_values.first;
						high4 = ring_accumulator_values.second;
						state_array[ 4 ] += ( low3 ^ high4 );
						// Update state with low3 and high4
						// 使用low3和high4更新状态

						// Final pair (state[5] and state[0])
						// 处理最后一对（state[5] 和 state[0]）
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(10) );
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(11) );
						multiple64_128bit( state_array[ 5 ], state_array[ 0 ], ring_accumulator_values );
						low5 = ring_accumulator_values.first;
						high5 = ring_accumulator_values.second;
						state_array[ 5 ] += ( low4 ^ high5 );
						// Update state with low4 and high5
						// 使用low4和high5更新状态
					}
					else
					{
						// Apply the BlindFast mode optimizations by directly setting the state without modular additions
						// 应用BlindFast模式优化，直接设置状态而不进行模加操作

						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer );
						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(1) );
						multiple64_128bit( state_array[ 0 ], state_array[ 1 ], ring_accumulator_values );
						low0 = ring_accumulator_values.first;
						high0 = ring_accumulator_values.second;
						state_array[ 0 ] = ( low5 ^ high0 );
						// Directly set state with ring accumulator and high0
						// 直接使用环形累加器和high0设置状态

						state_array[ 1 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(2) );
						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(3) );
						multiple64_128bit( state_array[ 1 ], state_array[ 2 ], ring_accumulator_values );
						low1 = ring_accumulator_values.first;
						high1 = ring_accumulator_values.second;
						state_array[ 1 ] = ( low0 ^ high1 );
						// Directly set state with low0 and high1
						// 直接使用low0和high1设置状态

						state_array[ 2 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(4) );
						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(5) );
						multiple64_128bit( state_array[ 2 ], state_array[ 3 ], ring_accumulator_values );
						low2 = ring_accumulator_values.first;
						high2 = ring_accumulator_values.second;
						state_array[ 2 ] = ( low1 ^ high2 );
						// Directly set state with low1 and high2
						// 直接使用low1和high2设置状态

						state_array[ 3 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(6) );
						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(7) );
						multiple64_128bit( state_array[ 3 ], state_array[ 4 ], ring_accumulator_values );
						low3 = ring_accumulator_values.first;
						high3 = ring_accumulator_values.second;
						state_array[ 3 ] = ( low2 ^ high3 );
						// Directly set state with low2 and high3
						// 直接使用low2和high3设置状态

						state_array[ 4 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(8) );
						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(9) );
						multiple64_128bit( state_array[ 4 ], state_array[ 5 ], ring_accumulator_values );
						low4 = ring_accumulator_values.first;
						high4 = ring_accumulator_values.second;
						state_array[ 4 ] = ( low3 ^ high4 );
						// Directly set state with low3 and high4
						// 直接使用low3和high4设置状态

						state_array[ 5 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(10) );
						state_array[ 0 ] ^= read_u64<ByteSwap>( byte_pointer + segment_size(11) );
						multiple64_128bit( state_array[ 5 ], state_array[ 0 ], ring_accumulator_values );
						low5 = ring_accumulator_values.first;
						high5 = ring_accumulator_values.second;
						state_array[ 5 ] = ( low4 ^ high5 );
						// Directly set state with low4 and high5
						// 直接使用low4和high5设置状态
					}
					
					byte_pointer += segment_size(12);
					offset -= segment_size(12);
				};

				state_array[0] ^= low5;
			}

			if ( offset >= segment_size( 6 ) ) [[unlikely]]
			{
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) ), &state_array[ 0 ], &state_array[ 1 ] );
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) ), &state_array[ 2 ], &state_array[ 3 ] );
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 4 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 5 ) ), &state_array[ 4 ], &state_array[ 5 ] );

				byte_pointer += segment_size( 6 );
				offset -= segment_size( 6 );
			}

			if ( offset >= segment_size( 2 ) ) [[likely]]
			{
				mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 0 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 1 ) ), &state_array[ 0 ], &state_array[ 3 ] );
				if ( offset >= segment_size( 4 ) ) [[likely]]
				{
					mumix<BlindFast>( read_u64<ByteSwap>( byte_pointer + segment_size( 2 ) ), read_u64<ByteSwap>( byte_pointer + segment_size( 3 ) ), &state_array[ 1 ], &state_array[ 4 ] );
				}
			}

			//Bug fixed
			// 当剩余 >=16 字节时，才进行这次尾部混合
			mumix<BlindFast>
			(
				read_u64<ByteSwap>( byte_pointer + offset - segment_size(2) ),
				read_u64<ByteSwap>( byte_pointer + offset - segment_size(1) ),
				&state_array[2], &state_array[5]
			);

			/*-------- epilogue loong 128-bit --------*/

			Values3<uint64_t> half_hash_state{0, 0, 0};
			auto& [i, j, k] = half_hash_state;

			i = state_array[0] - state_array[1];
			j = state_array[2] - state_array[3];
			k = state_array[4] - state_array[5];

			i = std::rotl(i, length & 63);
			j = std::rotr(j, length & 63);
			k ^= length;

			Values2<uint64_t> a{0, 0}, b{0, 0}, c{0, 0};

			// (i,j) → (low0, high0)
			multiple64_128bit(i, j, a);
			low0  = a.first;  high0 = a.second;

			// (j,k) → (low1, high1)
			multiple64_128bit(j, k, b);
			low1  = b.first;  high1 = b.second;

			// (k,i) → (low2, high2)
			multiple64_128bit(k, i, c);
			low2  = c.first;  high2 = c.second;

			// 合并成新的 i,j,k
			i = low0 ^ high2;
			j = low1 ^ high0;
			k = low2 ^ high1;

			// (i,j) → (low0, high0)
			multiple64_128bit(i, j, a);
			low0  = a.first;  high0 = a.second;

			// (j,k) → (low1, high1)
			multiple64_128bit(j, k, b);
			low1  = b.first;  high1 = b.second;

			// (k,i) → (low2, high2)
			multiple64_128bit(k, i, c);
			low2  = c.first;  high2 = c.second;

			// result
			out_lo = low0 ^ low1 ^ high2;
			out_hi = high0 ^ high1 ^ low2;
		}

		if constexpr(std::endian::native == std::endian::little)
		{
			write_u64<false>((uint8_t*)result + 0, out_lo);
			write_u64<false>((uint8_t*)result + 8, out_hi);
		}
		else
		{
			write_u64<true>((uint8_t*)result + 0, out_lo);
			write_u64<true>((uint8_t*)result + 8, out_hi);
		}
	}
};

#endif // NON_CRYPTOGRAPHIC_HASH_MUSE_AIR_HPP
