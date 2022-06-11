#include <bc_memory.h>
#include <bc_var.h>

#include <iostream>
#include <thread>
#include <chrono>

#include <Windows.h>

struct secret
{
	bc::obfuscated_prim64<uint64_t> health;
	bc::obfuscated_prim64<uint64_t> start_time;
};

static bc::memory_allocation* sec_allocation;

static std::vector<bc::memory_allocation*> allocations;
static bc::memory_allocator allocator(4096);

void fill_allocator_rnd()
{
	auto alloc_count = (20 + (std::rand() % 50));
	for (int i = 0; i < alloc_count; i++)
	{
		auto alloc = new bc::memory_allocation();
		allocator.alloc_int(alloc, 1 + std::rand() % 0x1200);
		allocations.push_back(alloc);
	}
}

int main()
{
	std::srand(std::time(0));
	fill_allocator_rnd();

	sec_allocation = new bc::memory_allocation();
	allocator.alloc_int(sec_allocation, sizeof(secret));
	allocations.push_back(sec_allocation);
	sec_allocation->cast<secret>()->health = 100;
	sec_allocation->cast<secret>()->start_time = GetTickCount64();

	while (true)
	{
		std::cout << "Health: " << sec_allocation->cast<secret>()->health.get() << std::endl;
		std::cout << "Start Time: " << sec_allocation->cast<secret>()->start_time.get() << std::endl;

		allocator.reallocate(allocations);
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}
