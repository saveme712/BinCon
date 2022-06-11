#include "pch.h"
#include "CppUnitTest.h"

#include "../BinCon/bc_memory.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace bc
{
	static std::wstring ToString(const bc::bc_error& err)
	{
		return L"??";
	}

	static std::wstring ToString(bc::memory_block* err)
	{
		return L"??";
	}

	TEST_CLASS(memory_allocation_tests)
	{
	public:
		TEST_METHOD(test_scramble)
		{
			memory_allocation allocation1;
			memory_allocation allocation2;
			bc_error err;

			memory_allocator mc(100);

			err = mc.alloc_int(&allocation1, 0x1001);
			Assert::AreEqual(err, bc_error::success); 
			
			err = mc.alloc_int(&allocation2, 0x1001);
			Assert::AreEqual(err, bc_error::success);

			memory_block* orig_block = allocation1.block;
			mc.reallocate(&allocation1);

			Assert::AreNotEqual(orig_block, allocation1.block.get());

		}
		
		TEST_METHOD(test_rnd_scramble)
		{
			std::srand(std::time(0));

			bc_error err;
			std::vector<memory_allocation> allocations(50);
			std::vector<memory_allocation*> allocation_ptrs(25);
			memory_allocator mc(50);

			for (size_t i = 0; i < 25; i++)
			{
				err = mc.alloc_int(&allocations[i], 0x10);
				Assert::AreEqual(err, bc_error::success);

				allocation_ptrs[i] = &allocations[i];
				memset(allocations[i].block, i, 0x10);
			}

			for (size_t i = 0; i < 50; i++)
			{
				mc.reallocate(allocation_ptrs);
			}
		}
	};
}
