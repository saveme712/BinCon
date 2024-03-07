#pragma once
#include <cstdint>
#include <vector>

#include "bc_var.h"
#include "bc_common.h"

namespace bc
{
#define PAGE_SIZE_4KB 0x1000
#define PAGE_ADDR(X) (X & ~(PAGE_SIZE_4KB - 1))

	/// <summary>
	/// A block of memory.
	/// </summary>
	struct memory_block
	{
		char data[PAGE_SIZE_4KB];
	};

	/// <summary>
	/// A memory allocation.
	/// </summary>
	struct memory_allocation
	{
		obfuscated_prim64<size_t, *__TIME__, __LINE__> id;
		obfuscated_prim64<size_t, *__TIME__, __LINE__> num_blocks;
		obfuscated_prim64<memory_block*, *__TIME__, __LINE__> block = nullptr;

		template <typename T>
		__forceinline T* cast()
		{
			return (T*)block.get();
		}
	};

	/// <summary>
	/// A naive memory allocator, without any special optimizations. This memory allocator
	/// is not thread safe. Allocation operations should be kept on one thread per allocator.
	/// </summary>
	class memory_allocator
	{
	private:
		std::vector<memory_allocation> allocations;
		obfuscated_prim64<memory_block*, 0x1337, __LINE__> blocks;
		obfuscated_prim64<bool*, 0x1337, __LINE__> block_allocation_map;
		obfuscated_prim64<size_t, 0x1337, __LINE__> total_block_count;
		obfuscated_prim64<size_t, 0x1337, __LINE__> allocation_id = 1;

	public:
		memory_allocator(size_t num_blocks);
		memory_allocator(memory_allocator& other);

	private:
		/// <summary>
		/// Finds a range of free memory.
		/// </summary>
		bc_error find_range(size_t num_blocks, memory_block** begin, size_t* block_index);

	public:
		/// <summary>
		/// Allocates a range of memory.
		/// </summary>
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