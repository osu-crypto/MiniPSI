#include "miniPSI_Tests.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include "Poly/polyNTL.h"
#include "Poly/polyFFT.h"
#include "PsiDefines.h"
#include "MiniPSI/MiniReceiver.h"
#include "MiniPSI/MiniSender.h"
#include "Tools/BalancedIndex.h"
#include "Tools/SimpleIndex.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "Common.h"
#include <thread>
#include <vector>
#include "ECDH/EcdhPsiReceiver.h"
#include "ECDH/EcdhPsiSender.h"

#include "ECDH/JL10PsiReceiver.h"
#include "ECDH/JL10PsiSender.h"

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#endif //  _MSC_VER


using namespace osuCrypto;

namespace tests_libOTe
{

	void MiniPSI_impl2()
	{
		setThreadName("Sender");
		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 6, psiSecParam = 40, numThreads(1);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < setSenderSize; ++i)
		{
			sendSet[i] = recvSet[i];
			//std::cout << "intersection: " <<sendSet[i] << "\n";
		}

		// set up networking
		std::string name = "n";
		IOService ios;
		Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
		Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

		std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
			recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}


		MiniSender sender;
		MiniReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.init(recvSet.size(), sendSet.size(), 40, prng1, recvChls);
			recv.outputBigPoly(recvSet, recvChls);

		});

		sender.init(sendSet.size(), recvSet.size(), 40, prng0, sendChls);
		sender.outputBigPoly(sendSet, sendChls);

		thrd.join();

		std::cout << gTimer << std::endl;


		std::cout << "recv.mIntersection.size(): " << recv.mIntersection.size() << std::endl;
		for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
		{
			std::cout << "#id: " << recv.mIntersection[i] <<
				"\t" << recvSet[recv.mIntersection[i]] << std::endl;
		}

		u64 dataSent = 0, dataRecv(0);
		for (u64 g = 0; g < recvChls.size(); ++g)
		{
			dataSent += recvChls[g].getTotalDataSent();
			dataRecv += recvChls[g].getTotalDataRecv();
			recvChls[g].resetStats();
		}

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void DhPSI_impl()
	{
		setThreadName("Sender");
		int curveType = 0;

		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 6, psiSecParam = 40, numThreads(1);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < setSenderSize; ++i)
		{
			sendSet[i] = recvSet[i];
			//std::cout << "intersection: " <<sendSet[i] << "\n";
		}

		// set up networking
		std::string name = "n";
		IOService ios;
		Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
		Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

		std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
			recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}


		EcdhPsiSender sender;
		EcdhPsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.init(recvSet.size(), 40, prng1.get<block>());
			recv.sendInput(recvSet, recvChls, curveType);

		});

		sender.init(sendSet.size(), 40, prng0.get<block>());
		sender.sendInput(sendSet, sendChls, curveType);


		thrd.join();

		std::cout << gTimer << std::endl;


		std::cout << "recv.mIntersection.size(): " << recv.mIntersection.size() << std::endl;
		for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
		{
			std::cout << "#id: " << recv.mIntersection[i] <<
				"\t" << recvSet[recv.mIntersection[i]] << std::endl;
		}

		u64 dataSent = 0, dataRecv(0);
		for (u64 g = 0; g < recvChls.size(); ++g)
		{
			dataSent += recvChls[g].getTotalDataSent();
			dataRecv += recvChls[g].getTotalDataRecv();
			recvChls[g].resetStats();
		}

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void JL10PSI_impl()
	{
		setThreadName("Sender");
		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 6, psiSecParam = 40, numThreads(1);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < setSenderSize; ++i)
		{
			sendSet[i] = recvSet[i];
			//std::cout << "intersection: " <<sendSet[i] << "\n";
		}

		// set up networking
		std::string name = "n";
		IOService ios;
		Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
		Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

		std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
			recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}


		JL10PsiSender sender;
		JL10PsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.startPsi(recvSet.size(), sendSet.size(), 40, prng1.get<block>(),recvSet, recvChls);

		});

		sender.startPsi(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

		thrd.join();

		std::cout << gTimer << std::endl;


		std::cout << "recv.mIntersection.size(): " << recv.mIntersection.size() << std::endl;
		for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
		{
			std::cout << "#id: " << recv.mIntersection[i] <<
				"\t" << recvSet[recv.mIntersection[i]] << std::endl;
		}

		u64 dataSent = 0, dataRecv(0);
		for (u64 g = 0; g < recvChls.size(); ++g)
		{
			dataSent += recvChls[g].getTotalDataSent();
			dataRecv += recvChls[g].getTotalDataRecv();
			recvChls[g].resetStats();
		}

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void exp_test()
	{
		std::cout << "curveParam = k283\n";
		int n = 10, k = 3;
		PRNG prng(ZeroBlock);

		EllipticCurve curve(p256k1, ZeroBlock);
		curve.getMiracl().IOBASE = 10;

		 auto& g = curve.getGenerator();
		
		std::cout << g << std::endl;

		std::vector<EccNumber> mSeeds;
		std::vector<EccPoint> mGseeds;

		mSeeds.reserve(n);
		mGseeds.reserve(n);

		for (u64 i = 0; i < n; i++)
		{
			// get a random value from Z_p
			mSeeds.emplace_back(curve);
			mSeeds[i].randomize(prng);

			// using brickexp which has the base of g, compute
			//
			//      PK_sigma[i] = g ^ pK[i]
			//
			// where pK[i] is just a random number in Z_p
			mGseeds.emplace_back(curve);
			mGseeds[i] = g * mSeeds[i];
			std::cout << mGseeds[i] << std::endl;

		}

		std::cout << mGseeds[0] << std::endl;
		std::cout << mGseeds[1] << std::endl;

		auto newG = mGseeds[1] + mGseeds[0];

		std::cout << newG << std::endl;


	}


	inline std::string arrU8toString(u8* Z, int size)
	{
		std::string sss;
		for (int j = 0; j < size; j++)
			sss.append(ToString(static_cast<unsigned int>(Z[j])));

		return sss;
	}

	void subsetSum_test() {
		
		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		EllipticCurve mCurve(p256k1, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		u64 mMyInputSize = 1 << 20, mSetSeedsSize, mChoseSeedsSize;
		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;
		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(prng);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
		}

		std::vector<string> checkUnique;

		std::vector<u64> indices(mSetSeedsSize);
		int cnt = 0;

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			std::iota(indices.begin(), indices.end(), 0);
			std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

			EccPoint g_sum(mCurve);

			for (u64 j = 0; j < mChoseSeedsSize; j++)
				g_sum = g_sum + pG_seeds[indices[j]]; //g^sum

			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);

			string str_sum = arrU8toString(temp, g_sum.sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum <<"\n";
				cnt++;
			}

		}
		std::cout << "cnt= " << cnt<<"\t checkUnique.size()= " << checkUnique.size()<<"\n";

		for (int i = 0; i < checkUnique.size(); i++)
		{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

		}
	}
}