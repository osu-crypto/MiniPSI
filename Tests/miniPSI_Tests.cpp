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
		setThreadName("EchdSender");
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

		//sendSet[0] = ZeroBlock;
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
			recv.outputBigPoly(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputBigPoly(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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


	void MiniPSI_hasing_impl()
	{
		setThreadName("EchdSender");
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
			recv.outputHashing(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputHashing(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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


	void MiniPSI_malicious_impl()
	{
		setThreadName("EchdSender");
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

		//sendSet[0] = ZeroBlock;
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
			recv.outputBigPoly_malicious(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputBigPoly_malicious(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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
		setThreadName("EchdSender");
		int curveType = 0;

		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 7, psiSecParam = 40, numThreads(1);

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
			recv.sendInput(recvSet.size(), setSenderSize, 40, prng1.get<block>(), recvSet, recvChls, curveType);

		});

		sender.sendInput(sendSet.size(), setRecvSize, 40, prng0.get<block>(), sendSet, sendChls, curveType);


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
		setThreadName("EchdSender");
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
			recv.startPsi(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

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



	void JL10PSI_subsetsum_impl()
	{
		setThreadName("EchdSender");
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
			recv.startPsi_subsetsum(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

		});

		sender.startPsi_subsetsum(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

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




	void JL10PSI_subsetsum_malicious_impl()
	{
		setThreadName("EchdSender");
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
			recv.startPsi_subsetsum_malicious(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

		});

		sender.startPsi_subsetsum_malicious(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

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



	void evalExp()
	{
		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		EllipticCurve mCurve(k283, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		u64 mMyInputSize = 1 << 10;
#if 1
		//////============clasic g^ri==========

		{
			gTimer.reset();
			gTimer.setTimePoint("clasic g^ri starts");
			std::vector<EccPoint> g_r;
			g_r.reserve(mMyInputSize);

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				EccNumber r(mCurve);
				r.randomize(prng);
				g_r.emplace_back(mCurve);
				g_r[i] = mG*r;
			}
			gTimer.setTimePoint("clasic g^ri done");
			std::cout << gTimer << "\n";


			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[g_r[i].sizeBytes()];
				g_r[i].toBytes(temp);

				string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";
		}
#endif
		//////============HSS g^ri==========
		{	gTimer.reset();
		gTimer.setTimePoint("HSS g^ri starts");

		u64 mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs;
		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

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
		gTimer.setTimePoint("HSS g^seed done");

		std::vector<u64> indices(mSetSeedsSize);
		std::vector<EccPoint> g_r;
		g_r.reserve(mMyInputSize);

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			if (mMyInputSize < (1 << 9))
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
			}
			else
			{
				indices.resize(0);
				while (indices.size() < mChoseSeedsSize)
				{
					int rnd = rand() % mSetSeedsSize;
					if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
						indices.push_back(rnd);
				}
			}



			if (mBoundCoeffs == 2)
			{
				g_r.emplace_back(pG_seeds[indices[0]]);

				for (u64 j = 1; j < mChoseSeedsSize; j++)
					g_r[i] = g_r[i] + pG_seeds[indices[j]]; //g^sum //h=2   ci=1

			}
			else
			{
				g_r.emplace_back(mCurve);
				for (u64 j = 0; j < mChoseSeedsSize; j++)
				{
					int rnd = 1 + rand() % (mBoundCoeffs - 1);
					EccNumber ci(mCurve, rnd);
					g_r[i] = g_r[i] + pG_seeds[indices[j]] * ci; //g^sum
				}
			}
	}

		gTimer.setTimePoint("HDD g^ri done");
		std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
		int cnt = 0;
		std::vector<string> checkUnique;

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			u8* temp = new u8[g_r[i].sizeBytes()];
			g_r[i].toBytes(temp);

			string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}
		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

#endif // DOUBLE-CHECK


	}

		//////============recursive h=2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h=2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestH1RecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<EccNumber> nSeeds; //level
			std::vector<std::vector<EccPoint>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.reserve(mSeqParams[0].numSeeds);
			pG_seeds[0].reserve(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds.emplace_back(mCurve);
				nSeeds[i].randomize(prng);

				pG_seeds[0].emplace_back(mCurve);
				pG_seeds[0][i] = mG * nSeeds[i];  //g^ri
			}
			gTimer.setTimePoint("Recursive h=2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].reserve(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}

					pG_seeds[idxLvl + 1].emplace_back(pG_seeds[idxLvl][indices[0]]);

					for (u64 j = 1; j < mSeqParams[idxLvl].numChosen; j++)
					{
						pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; //\sum g^ri
					}
				}
			}


			gTimer.setTimePoint("Recursive h=2 HDD g^ri done");
			std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
			int lvlLast = mSeqParams.size();
			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

		//////============recursive h>2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h>2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestRecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<EccNumber> nSeeds; //level
			std::vector<std::vector<EccPoint>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.reserve(mSeqParams[0].numSeeds);
			pG_seeds[0].reserve(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds.emplace_back(mCurve);
				nSeeds[i].randomize(prng);

				pG_seeds[0].emplace_back(mCurve);
				pG_seeds[0][i] = mG * nSeeds[i];  //g^ri
			}
			gTimer.setTimePoint("Recursive h>2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].reserve(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{
					//std::iota(indices.begin(), indices.end(), 0);
					//std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}


					pG_seeds[idxLvl + 1].emplace_back(mCurve);

					if (mSeqParams[idxLvl].boundCoeff == 2)
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; //\sum g^ri
						}
					else if (mSeqParams[idxLvl].boundCoeff == (1 << 2))
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							int ci = 1 + rand() % (mSeqParams[idxLvl].boundCoeff - 1);

							for (u64 idxRep = 0; idxRep < ci; idxRep++) //repeat ci time
							{
								pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; // (g^ri)^ci
							}

						}
					else
					{
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							//need <2^104 but implemnt 2^128
							int rnd = rand() % mSeqParams[idxLvl].boundCoeff;
							EccNumber ci(mCurve, prng);
							pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]] * ci; //\sum g^ri
						}
					}

				}
			}


			gTimer.setTimePoint("Recursive h>2 HDD g^ri done");
			std::cout << gTimer << "\n";

			//#ifdef DOUBLE-CHECK
#if 1
			int lvlLast = mSeqParams.size();

			std::cout << "pG_seeds[lvlLast].size()=" << pG_seeds[lvlLast].size() << "\n";

			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

}


	void subsetSum_test() {

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		EllipticCurve mCurve(k283, OneBlock);
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
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}

		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n";

		for (int i = 0; i < checkUnique.size(); i++)
		{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

		}
	}



	void subsetSum(vector<EccPoint>& g_sum) { //fail

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		EllipticCurve mCurve(k283, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		u64 mMyInputSize = 1 << 6, mSetSeedsSize, mChoseSeedsSize;
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

		g_sum.reserve(mMyInputSize);

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			std::iota(indices.begin(), indices.end(), 0);
			std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

			g_sum.emplace_back(mCurve);

			for (u64 j = 0; j < mChoseSeedsSize; j++)
				g_sum[i] = g_sum[i] + pG_seeds[indices[j]]; //g^sum

			u8* temp = new u8[g_sum[i].sizeBytes()];
			g_sum[i].toBytes(temp);

			string str_sum = arrU8toString(temp, g_sum[i].sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}

		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n";

		for (int i = 0; i < checkUnique.size(); i++)
		{
			//std::cout << "checkUnique. : " << checkUnique[i] << "\n";

		}

	}


	void schnorrZKDL()
	{
		PRNG prng(ZeroBlock);
		EllipticCurve mCurve(k283, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		EccPoint pG(mCurve);
		pG = mCurve.getGenerator();

		EccNumber nK(mCurve);
		nK.randomize(prng);
		auto g_k = pG*nK;  //g^k

		EccNumber nV(mCurve);
		nV.randomize(prng);
		auto g_v = pG*nV;  //g^v

		std::vector<u8*> challeger_bytes(3);

		challeger_bytes[0] = new u8[pG.sizeBytes()];
		pG.toBytes(challeger_bytes[0]);

		challeger_bytes[1] = new u8[g_k.sizeBytes()];
		g_k.toBytes(challeger_bytes[1]);

		challeger_bytes[2] = new u8[g_v.sizeBytes()];
		g_v.toBytes(challeger_bytes[2]);


		block* challenger = new block[numSuperBlocks]; //g + g^k+g^v
		std::vector<block> cipher_challenger(numSuperBlocks);// 

		for (int i = 0; i < numSuperBlocks; i++)
			challenger[i] = ZeroBlock;

		block temp = ZeroBlock;
		for (int i = 0; i < numSuperBlocks; i++)
		{
			memcpy((u8*)&temp, challeger_bytes[i] + i * sizeof(block), sizeof(block));
			challenger[i] = challenger[i] + temp;
		}

		mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data());  //c=H(g,g^k, g^v)
		EccNumber nC(mCurve);
		u8* nC_bytes = new u8[nC.sizeBytes()];
		memcpy(nC_bytes, cipher_challenger.data(), nC.sizeBytes());
		nC.fromBytes(nC_bytes);

		EccNumber nR(mCurve);
		nR = nV - nC*nK; //r=v-ck

		std::cout << "t=" << g_v << "\n";
		auto g_r = pG*nR;  //g^r
		auto y_c = g_k*nC;  //g^r

		auto gryc = g_r + y_c;
		std::cout << "g^r*y^c=" << gryc << "\n";




		auto thrd = std::thread([&]() { //prover



		});

		//verifier

		thrd.join();



	}
	/*void subsetSum_test() {

		vector<EccPoint> points;
		subsetSum(points);
		std::cout << "points: " << points.size() << "\n";

	}*/
}