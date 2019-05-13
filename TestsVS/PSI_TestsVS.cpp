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
			MiniPSI_impl2();
		}

		TEST_METHOD(MiniPSI_hasing_TestVS)
		{
			InitDebugPrinting();
			MiniPSI_hasing_impl();
		}

		TEST_METHOD(DhPSI_TestVS)
		{
			InitDebugPrinting();
			DhPSI_impl();
		}

		TEST_METHOD(subsetSum_TestVS)
		{
			InitDebugPrinting();
			subsetSum_test();
		}


		TEST_METHOD(JL10PSI_TestVS)
		{
			InitDebugPrinting();
			JL10PSI_impl();
		}

		TEST_METHOD(JL10PSI_subsetsum_TestVS)
		{
			InitDebugPrinting();
			JL10PSI_subsetsum_impl();
		}

		TEST_METHOD(JL10PSI_subsetsum_malicious_TestVS)
		{
			InitDebugPrinting();
			JL10PSI_subsetsum_malicious_impl();
		}

		TEST_METHOD(schnorrZKDL_TestVS)
		{
			InitDebugPrinting();
			schnorrZKDL();
		}

		TEST_METHOD(MiniPSI_malicious_TestVS)
		{
			InitDebugPrinting();
			MiniPSI_malicious_impl();
		}

		TEST_METHOD(evalExp_TestVS)
		{
			InitDebugPrinting();
			evalExp();
		}

		TEST_METHOD(testNewGroup_TestVS)
		{
			InitDebugPrinting();
			testNewGroup();
		}

		TEST_METHOD(Simple_TestVS)
		{
			InitDebugPrinting();
			Simple_Test_Impl();
		}

		TEST_METHOD(Ristretoo_TestVS)
		{
			InitDebugPrinting();
			Ristretoo_Test_Impl();
		}

		TEST_METHOD(curve_TestVS)
		{
			InitDebugPrinting();
			curveTest();
		}


	};
}
#endif


