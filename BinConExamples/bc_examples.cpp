#include <bc_memory.h>
#include <bc_var.h>

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
static bc::memory_allocator allocator(4096);

bc::memory_allocation* new_alloc(size_t bytes)
{
	auto alloc = new bc::memory_allocation();
	allocator.alloc_int(alloc, bytes);
	allocations.push_back(alloc);
	return alloc;
}

void fill_allocator_rnd()
{
	auto alloc_count = (20 + (std::rand() % 50));
	for (int i = 0; i < alloc_count; i++)
	{
		new_alloc(1 + (std::rand() % 0x1200));
	}
}

void init_secret()
{
	sec_allocation = new_alloc(sizeof(secret));
	sec_allocation->cast<secret>()->health = 100;
	sec_allocation->cast<secret>()->start_time = GetTickCount64();
}

int main()
{
	std::srand(std::time(0));
	fill_allocator_rnd();
	init_secret();

	while (true)
	{
		std::cout << xorstr_("Health: ") << sec_allocation->cast<secret>()->health.get() << std::endl;
		std::cout << xorstr_("Start Time: ") << sec_allocation->cast<secret>()->start_time.get() << std::endl;

		allocator.reallocate(allocations);
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}
