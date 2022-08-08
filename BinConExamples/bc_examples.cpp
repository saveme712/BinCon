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
};

secret* emulated_secret = nullptr;

void init_secret()
{
	emulated_secret = (secret*)bc::get_chal_entry()->encrypt_ptr(malloc(sizeof(secret)));
	std::cout << "emulated_secret: " << emulated_secret << std::endl;
	emulated_secret->health = 100;
	emulated_secret->start_time = GetTickCount64();
}

int main()
{
	BEGIN_VM(__FUNCTION__);

	std::srand(std::time(0));
	init_secret();

	auto ce = bc::get_chal_entry();
	//ce->re_encrypt_code
	while (true)
	{
		std::cout << "Secret: " << std::hex << (uint64_t)emulated_secret << std::endl;
		std::cout << "Health: " << emulated_secret->health.get() << std::endl;
		std::cout << "Start Time: " << emulated_secret->start_time.get() << std::endl;

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	END_VM(__FUNCTION__);
}
