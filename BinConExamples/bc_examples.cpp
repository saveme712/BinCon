#include <bc_memory.h>
#include <bc_var.h>
#include <bc_windows.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_stub.h>

#include <iostream>
#include <thread>
#include <chrono>

#include <Windows.h>

#include <xorstr.hpp>

struct secret
{
	bc::obfuscated_prim64<uint64_t> health;
	bc::obfuscated_prim64<uint64_t> start_time;
	bc::obfuscated_prim64<uint64_t> tick;
	uint32_t arr[4];
};

secret* emulated_secret = nullptr;

void init_secret()
{
	emulated_secret = (secret*)bc::get_chal_entry()->alloc_enc(sizeof(secret));
	emulated_secret->health = 100;
	emulated_secret->start_time = GetTickCount64();
	emulated_secret->tick = 0;
}

void test_encrypted_arr(uint32_t* arr, size_t amount)
{
	for (auto i = 0ull; i < amount; i++)
	{
		arr[i] = 0x69696969;
	}
}

int main()
{
	BEGIN_VM(__FUNCTION__);

	std::srand(std::time(0));
	init_secret();
	std::cout << "Secret: " << std::hex << (uint64_t)emulated_secret << std::endl;

	test_encrypted_arr(emulated_secret->arr, ARRAYSIZE(emulated_secret->arr));
	for (auto i = 0; i < ARRAYSIZE(emulated_secret->arr); i++)
	{
		std::cout << "Test Arr: " << std::hex << emulated_secret->arr[i] << std::endl;
	}

	auto ce = bc::get_chal_entry();
	ce->verify_anti_debug([](auto err)
	{

	});

	while (true)
	{
		std::cout << "Health: " << emulated_secret->health.get() << std::endl;
		std::cout << "Start Time: " << emulated_secret->start_time.get() << std::endl;
		std::cout << "Tick: " << emulated_secret->tick.get() << std::endl;

		emulated_secret->tick += 1;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	END_VM(__FUNCTION__);
}
