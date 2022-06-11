#pragma once
#include <cstdint>
#include <vector>

#include "bc_var.h"

namespace bc
{
#define PAGE_SIZE_4KB 0x1000

	enum class bc_error
	{
		success,
		not_enough_memory
	};

	struct memory_block
	{
		char data[PAGE_SIZE_4KB];
	};

	struct memory_allocation
	{
		ObfuscatedPrimitive64<size_t> id;
		ObfuscatedPrimitive64<size_t> num_blocks;
		ObfuscatedPrimitive64<memory_block*> block = nullptr;

		template <typename T>
		__forceinline T* cast()
		{
			return (T*)block;
		}
	};

	class memory_allocator
	{
	private:
		std::vector<memory_allocation> allocations;
		ObfuscatedPrimitive64<memory_block*> blocks;
		ObfuscatedPrimitive64<bool*> block_allocation_map;
		ObfuscatedPrimitive64<size_t> total_block_count;
		ObfuscatedPrimitive64<size_t> allocation_id = 1;

	public:
		memory_allocator(size_t num_blocks);
		memory_allocator(memory_allocator& other);

	private:
		bc_error find_range(size_t num_blocks, memory_block** begin, size_t* block_index);

	public:
		bc_error alloc_int(memory_allocation* allocation, size_t num_bytes);

		/// <summary>
		/// Frees the provided allocation.
		/// </summary>
		void free(memory_allocation* allocation);

		/// <summary>
		/// Reallocates the provided allocation at the end of the memory heap.
		/// </summary>
		bc_error reallocate(memory_allocation* allocation);

		/// <summary>
		/// Re-allocates the provided allocations in a random order.
		/// </summary>
		bc_error reallocate(std::vector<memory_allocation*> allocations);
	};
}