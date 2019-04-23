#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "PSI_Tests.h"
#include "miniPSI_Tests.h"
#include "NcoOT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_libOTe
{
    TEST_CLASS(nOPRF_Tests)
    {
    public:

		
		TEST_METHOD(Hashing_TestVS)
		{
			InitDebugPrinting();
			Hashing_Test_Impl();
		}
		TEST_METHOD(myTestVS)
		{
			InitDebugPrinting();
			myTest();
		}

		TEST_METHOD(NTL_Poly_TestVS)
		{
			InitDebugPrinting();
			NTL_Poly_Test_Impl();
		}

		TEST_METHOD(FFT_Poly_TestVS)
		{
			InitDebugPrinting();
			Poly_Test_Impl();
		}
		TEST_METHOD(Prty_PSI_Impl_TestVS)
		{
			InitDebugPrinting();
			Prty_PSI_impl();
		}
		
		TEST_METHOD(prfOtRow_PSI_Impl_TestVS)
		{
			InitDebugPrinting();
			prfOtRow_Test_Impl();
		}

		TEST_METHOD(exp_Impl_TestVS)
		{
			InitDebugPrinting();
			exp_test();
		}
		TEST_METHOD(MiniPSI_TestVS)
		{
			InitDebugPrinting();
			MiniPSI_impl1();
		}

		TEST_METHOD(DhPSI_TestVS)
		{
			InitDebugPrinting();
			DhPSI_impl();
		}


		

	};
}
#endif


