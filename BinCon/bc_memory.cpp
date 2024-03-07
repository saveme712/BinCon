#include <bc_memory.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <random>
#include <ctime>

#define BYTES_TO_BLOCKS(X) (((X) / PAGE_SIZE_4KB) + (((X) % PAGE_SIZE_4KB) != 0))
#define BLOCKS_TO_BYTES(X) ((X) * PAGE_SIZE_4KB)

namespace bc
{
	memory_allocator::memory_allocator(size_t num_blocks)
	{
		blocks = (memory_block*)malloc(sizeof(memory_block) * num_blocks);
		assert(blocks != nullptr);
		memset(blocks, 0, sizeof(memory_block) * num_blocks);

		block_allocation_map = (bool*)malloc(sizeof(bool) * num_blocks);
		assert(block_allocation_map != nullptr);
		memset(block_allocation_map, 0, sizeof(bool) * num_blocks);

		total_block_count = num_blocks;
	}

	memory_allocator::memory_allocator(memory_allocator& other)
	{
		blocks = other.blocks;
		block_allocation_map = other.block_allocation_map;
		total_block_count = other.total_block_count;
		allocations = other.allocations;
		allocation_id = other.allocation_id;
	}

	bc_error memory_allocator::find_range(size_t num_blocks, memory_block** begin, size_t* block_index)
	{
		bc_error err = bc_error::not_enough_memory;
		bool found = false;

		*begin = nullptr;
		for (size_t i = 0; i < total_block_count - num_blocks && !found; i++)
		{
			size_t range_size = 0;
			for (size_t j = i; range_size < num_blocks && !block_allocation_map[j]; j++, range_size++);

			if (range_size >= num_blocks)
			{
				*begin = &blocks[i];
				*block_index = i;
				err = bc_error::success;
				found = true;
			}
		}

		return err;
	}

	bc_error memory_allocator::alloc_int(memory_allocation* allocation, size_t num_bytes)
	{
		memory_block* block = nullptr;
		size_t block_index;
		bc_error err;

		err = find_range(BYTES_TO_BLOCKS(num_bytes), &block, &block_index);
		if (err != bc_error::success)
		{
			goto _ret;
		}

		for (size_t i = 0; i < BYTES_TO_BLOCKS(num_bytes); i++)
		{
			block_allocation_map[block_index + i] = true;
		}

		allocation->id.set(allocation_id++);
		allocation->block = block;
		allocation->num_blocks = BYTES_TO_BLOCKS(num_bytes);
		allocations.push_back(*allocation);

	_ret:
		return err;
	}

	void memory_allocator::free(memory_allocation* allocation)
	{
		size_t block_index = (size_t)(allocation->block - blocks);
		for (size_t i = 0; i < allocation->num_blocks; i++)
		{
			block_allocation_map[block_index + i] = false;
		}

		for (auto it = allocations.begin(); it != allocations.end();)
		{
			if (it->id == allocation->id)
			{
				it = allocations.erase(it);
			}
			else
			{
				it += 1;
			}
		}

		allocation->id = 0;
		allocation->block = nullptr;
		allocation->num_blocks = 0;
	}

	bc_error memory_allocator::reallocate(memory_allocation* allocation)
	{
		bc_error err;
		memory_allocation n;
		err = alloc_int(&n, BLOCKS_TO_BYTES(allocation->num_blocks));
		if (err != bc_error::success)
		{
			goto _ret;
		}

		memcpy(n.block, allocation->block, PAGE_SIZE_4KB);
		free(allocation);
		*allocation = n;

	_ret:
		return err;
	}

	bc_error memory_allocator::reallocate(std::vector<memory_allocation*> allocations)
	{
		bc_error err = bc_error::success;

		std::random_device rd;
		std::mt19937 rng(rd());

		std::shuffle(allocations.begin(), allocations.end(), rng);
		for (auto alloc : allocations)
		{
			err = reallocate(alloc);
			if (err != bc_error::success)
			{
				goto _ret;
			}
		}

	_ret:
		return err;
	}
}