
#include <iostream>
#include <thread>
#include <chrono>

#include <Windows.h>

#include <xorstr.hpp>

#include <bc_var.h>
#include <bc_windows.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_stub.h>
#include <bc_dyn_struct.h>


typedef bc::obfuscated_prim64<uint64_t, 0x1337, __LINE__> health_obf_type;
typedef bc::obfuscated_prim64<uint64_t, 0x1337, __LINE__> start_time_obf_type;
typedef bc::obfuscated_prim64<uint64_t, 0x1337, __LINE__> tick_obf_type;

struct secret
{

	bc::dynamic_struct<0x10> dynamic;
	bc::dynamic_struct_key health_key;
	bc::dynamic_struct_key start_time_key;
	bc::dynamic_struct_key tick_key;
	bc::dynamic_struct_key arr_key;

	__forceinline health_obf_type* health()
	{
		return dynamic.ref_field<health_obf_type>(health_key);
	}

	__forceinline start_time_obf_type* start_time()
	{
		return dynamic.ref_field<start_time_obf_type>(start_time_key);
	}

	__forceinline tick_obf_type* tick()
	{
		return dynamic.ref_field<tick_obf_type>(tick_key);
	}

	__forceinline uint32_t* arr()
	{
		return dynamic.ref_field<uint32_t>(arr_key);
	}

	__forceinline void init()
	{
		health_key = dynamic.add_field_typed<health_obf_type>();
		start_time_key = dynamic.add_field_typed<start_time_obf_type>();
		tick_key = dynamic.add_field_typed<tick_obf_type>();
		arr_key = dynamic.add_field(sizeof(uint32_t) * 4);
	}
};

secret* emulated_secret = nullptr;

void init_secret()
{
	emulated_secret = new(bc::get_chal_entry()->alloc_enc(sizeof(secret)))secret;
	emulated_secret->init();
	*emulated_secret->health() = 100;
	*emulated_secret->start_time() = GetTickCount64();
	*emulated_secret->tick() = 0;
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
	srand(std::time(0));

	std::cout << "Initializing secret... " << std::endl;
	init_secret();

	std::cout << "Secret: " << std::hex << (uint64_t)emulated_secret << std::endl;

	test_encrypted_arr(emulated_secret->arr(), 4);
	for (auto i = 0; i < 4; i++)
	{
		std::cout << "Test Arr: " << std::hex << emulated_secret->arr()[i] << std::endl;
	}

	auto ce = bc::get_chal_entry();
	ce->verify_anti_debug([](auto err)
	{

	});

	while (true)
	{
		std::cout << "Health: " << emulated_secret->health()->get() << std::endl;
		std::cout << "Start Time: " << emulated_secret->start_time()->get() << std::endl;
		std::cout << "Tick: " << emulated_secret->tick()->get() << std::endl;

		*emulated_secret->tick() += 1;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	END_VM(__FUNCTION__);
}
