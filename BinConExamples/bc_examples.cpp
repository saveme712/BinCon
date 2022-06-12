#include <bc_memory.h>
#include <bc_var.h>
#include <bc_windows.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>

#include <iostream>
#include <thread>
#include <chrono>

#include <Windows.h>

#include <xorstr.hpp>

struct secret
{
	bc::obfuscated_prim64<uint64_t> health;
	bc::obfuscated_prim64<uint64_t> start_time;
};

static bc::memory_allocation* sec_allocation;

static std::vector<bc::memory_allocation*> allocations;
static bc::memory_allocator allocator(150);

bc::memory_allocation* new_alloc(size_t bytes)
{
	auto alloc = new bc::memory_allocation();
	allocator.alloc_int(alloc, bytes);
	allocations.push_back(alloc);
	return alloc;
}

void fill_rand(void* buffer, size_t amount)
{
	auto bits = (int8_t*)buffer;
	for (size_t i = 0; i < amount; i++)
	{
		bits[i] = (int8_t)rand();
	}
}

void fill_allocator_rnd()
{
	auto alloc_count = 1 + (rand() % 50);
	for (int i = 0; i < alloc_count; i++)
	{
		if (auto alloc = new_alloc(PAGE_SIZE_4KB))
		{
			fill_rand(alloc->cast<void>(), PAGE_SIZE_4KB);
		}
	}
}

void init_secret()
{
	sec_allocation = new_alloc(PAGE_SIZE_4KB);
	fill_rand(sec_allocation->cast<void>(), PAGE_SIZE_4KB);

	sec_allocation->cast<secret>()->health = 100;
	sec_allocation->cast<secret>()->start_time = GetTickCount64();
}

int main()
{
	BEGIN_VM(__FUNCTION__);

	std::srand(std::time(0));
	bc::init_crc32_table();
	bc::install_anti_debug();
	fill_allocator_rnd();
	init_secret();

	while (true)
	{
		std::cout << "Health: " << sec_allocation->cast<secret>()->health.get() << std::endl;
		std::cout << "Start Time: " << sec_allocation->cast<secret>()->start_time.get() << std::endl;

		allocator.reallocate(allocations);
		bc::verify_anti_debug([](auto err)
		{
			std::cout << "Anti debug verification failed!" << std::endl;
			bc::hang_system();
		});

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	END_VM(__FUNCTION__);
}
