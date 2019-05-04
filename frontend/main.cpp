#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include <cryptoTools/gsl/span>

#include <cryptoTools/Common/Matrix.h>

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>


#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/bch511.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "CLP.h"
#include "main.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "Poly/polyNTL.h"
#include "PsiDefines.h"

#include "PRTY/PrtySender.h"
#include "PRTY/PrtyReceiver.h"
#include "Tools/BalancedIndex.h"

#include <thread>
#include <vector>
#include <stdarg.h> 
#include "ecdhMain.h"
#include "MiniPSI/MiniReceiver.h"
#include "MiniPSI/MiniSender.h"
#include "libPSI/ECDH/EcdhPsiReceiver.h"
#include "libPSI/ECDH/EcdhPsiSender.h"
#include "libPSI/ECDH/JL10PsiReceiver.h"
#include "libPSI/ECDH/JL10PsiSender.h"
#include "libPSI/MiniPSI/MiniReceiver.h"
#include "libPSI/MiniPSI/MiniSender.h"

template<typename ... Args>
std::string string_format(const std::string& format, Args ... args)
{
	size_t size = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
	std::unique_ptr<char[]> buf(new char[size]);
	std::snprintf(buf.get(), size, format.c_str(), args ...);
	return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

static u64 expectedIntersection = 100;
u64 protocolId = 0; //bin 
//u64 protocolId = 1;  //sender.outputBigPoly(inputs, sendChls);


void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test (balanced PSI): " << argv0 << " -t" << std::endl;
	std::cout << "\t 2. For simulation (2 terminals): " << std::endl;;
	std::cout << "\t\t EchdSender terminal: " << argv0 << " -r 0" << std::endl;
	std::cout << "\t\t Receiver terminal: " << argv0 << " -r 1" << std::endl;

	std::cout << "\t 2. For 2 machines: " << std::endl;
	std::cout << "\t\t Balanced PSI with best communication: " << std::endl;
	std::cout << "\t\t\t EchdSender terminal: " << argv0 << "-r 0 -n <log(setsize)> -t <#thread> -p 0 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(setsize)> -t <#thread> -p 0 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t EchdSender Example: " << argv0 << "-r 0 -n 16 -t 1 -p 0 -ip 172.31.22.179:1212" << std::endl;


	std::cout << "\t\t Balanced PSI with running time: " << std::endl;
	std::cout << "\t\t\t EchdSender terminal: " << argv0 << "-r 0 -n <log(setsize)> -t <#thread> -p 1 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(setsize)> -t <#thread> -p 1 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t EchdSender Example: " << argv0 << "-r 0 -n 16 -t 1 -p 1 -ip 172.31.22.179:1212" << std::endl;


	std::cout << "\t\t Unbalanced PSI: " << std::endl;
	std::cout << "\t\t\t EchdSender terminal: " << argv0 << "-r 0 -n <log(largesize)> -N <smallsize> -t <#thread> -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(largesize)> -N <smallsize> -t <#thread> -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t EchdSender Example: " << argv0 << "-r 0 -n 20 -N 5000 -t 1 -ip 172.31.22.179:1212" << std::endl;


}


void EchdSender(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	u64 psiSecParam = 40;
	PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	
		// set up networking
		std::string name = "n";
		IOService ios;
		Endpoint ep1(ios, ipAddr_Port, EpMode::Server, name);

		std::vector<Channel> sendChls(numThreads);
		for (u64 i = 0; i < numThreads; ++i)
			sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

		std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";

		std::vector<block> inputs(mySetSize);
		for (u64 i = 0; i < inputs.size(); ++i)
			inputs[i] = prngSet.get<block>();

		
		EcdhPsiSender sender;
		sender.sendInput(inputs.size(), 40, prng0.get<block>(),inputs, sendChls, 0);
		gTimer.setTimePoint("r psi done");
		std::cout << gTimer << std::endl;


		for (u64 i = 0; i < numThreads; ++i)
			sendChls[i].close();

		ep1.stop();	ios.stop();
}

void EchdReceiver(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads=1)
{
		u64 psiSecParam = 40;
		PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
		
		
			std::string name = "n";
			IOService ios;
			Endpoint ep0(ios, ipAddr_Port, EpMode::Client, name);

			std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
			for (u64 i = 0; i < numThreads; ++i)
				recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

			std::cout << "====================================Echd====================================\n";
			std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";


			std::vector<block> inputs(mySetSize);

			for (u64 i = 0; i < 10; ++i)
				inputs[i] = prng1.get<block>();

			for (u64 i = 10; i < expectedIntersection+10; ++i)
				inputs[i] = prngSet.get<block>();

			for (u64 i = 10+expectedIntersection; i < inputs.size(); ++i)
				inputs[i] = prng1.get<block>();

			EcdhPsiReceiver recv;
			recv.sendInput(inputs.size(), 40, prng1.get<block>(),inputs, recvChls, 0);
			gTimer.setTimePoint("r psi done");

			std::cout << gTimer << std::endl;

			std::cout << "recv.mIntersection  : " << recv.mIntersection.size() << std::endl;
			std::cout << "expectedIntersection: " << expectedIntersection << std::endl;
			for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
			{
				/*std::cout << "#id: " << recv.mIntersection[i] <<
					"\t" << inputs[recv.mIntersection[i]] << std::endl;*/
			}

			u64 dataSent = 0, dataRecv(0);
			for (u64 g = 0; g < recvChls.size(); ++g)
			{
				dataSent += recvChls[g].getTotalDataSent();
				dataRecv += recvChls[g].getTotalDataRecv();
				recvChls[g].resetStats();
			}

			std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";


			for (u64 i = 0; i < numThreads; ++i)
				recvChls[i].close();

			ep0.stop(); ios.stop();
}


void JL10Sender(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	u64 psiSecParam = 40;
	PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep1(ios, ipAddr_Port, EpMode::Server, name);
	std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";
	std::vector<Channel> sendChls(numThreads);
	std::vector<block> inputs(mySetSize);
	for (u64 i = 0; i < inputs.size(); ++i)
		inputs[i] = prngSet.get<block>();

	JL10PsiSender sender;

	
	//====================JL psi
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	sender.startPsi(inputs.size(), theirSetSize, 40, prng0.get<block>(), inputs, sendChls);
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();


	//====================JL psi startPsi_subsetsum
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i+ numThreads), "chl" + std::to_string(i+ numThreads));

	sender.startPsi_subsetsum(inputs.size(), theirSetSize, 40, prng0.get<block>(), inputs, sendChls);
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();



	ep1.stop();	ios.stop();
}

void JL10Receiver(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	u64 psiSecParam = 40;
	PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	std::string name = "n";
	IOService ios;
	Endpoint ep0(ios, ipAddr_Port, EpMode::Client, name);
	std::vector<Channel> recvChls(numThreads);

	std::cout << "====================================JL10====================================\n";
	std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";

	std::vector<block> inputs(mySetSize);
	for (u64 i = 0; i < expectedIntersection; ++i)
		inputs[i] = prngSet.get<block>();

	for (u64 i = expectedIntersection; i < inputs.size(); ++i)
		inputs[i] = prng1.get<block>();


	JL10PsiReceiver recv;

	//====================JL psi
	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	recv.startPsi(inputs.size(), theirSetSize, 40, prng1.get<block>(), inputs, recvChls);


	std::cout << gTimer << std::endl;

	u64 dataSent = 0, dataRecv(0);
	for (u64 g = 0; g < recvChls.size(); ++g)
	{
		dataSent += recvChls[g].getTotalDataSent();
		dataRecv += recvChls[g].getTotalDataRecv();
		recvChls[g].resetStats();
	}
	std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";
	std::cout << "recv.mIntersection vs exp : " << recv.mIntersection.size() << " vs " << expectedIntersection << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i].close();


	//====================JL psi startPsi_subsetsum
	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i] = ep0.addChannel("chl" + std::to_string(numThreads+i), "chl" + std::to_string(numThreads+i));

	recv.startPsi_subsetsum(inputs.size(), theirSetSize, 40, prng1.get<block>(), inputs, recvChls);
	std::cout << gTimer << std::endl;


	for (u64 g = 0; g < recvChls.size(); ++g)
	{
		dataSent += recvChls[g].getTotalDataSent();
		dataRecv += recvChls[g].getTotalDataRecv();
		recvChls[g].resetStats();
	}
	std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";
	std::cout << "recv.mIntersection vs exp : " << recv.mIntersection.size() << " vs " << expectedIntersection << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i].close();



	ep0.stop(); ios.stop();
}



void Mini19Sender(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	u64 psiSecParam = 40;
	PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep1(ios, ipAddr_Port, EpMode::Server, name);
	std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";
	std::vector<Channel> sendChls(numThreads);
	std::vector<block> inputs(mySetSize);
	for (u64 i = 0; i < inputs.size(); ++i)
		inputs[i] = prngSet.get<block>();

	MiniSender sender;

	//====================outputBigPoly psi
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	sender.outputHashing(inputs.size(), theirSetSize, 40, prng0, inputs, sendChls);
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();


	//std::cout << "\n\n";
	////====================
	//for (u64 i = 0; i < numThreads; ++i)
	//	sendChls[i] = ep1.addChannel("chl" + std::to_string(i + numThreads), "chl" + std::to_string(i + numThreads));

	//sender.outputHashing(inputs.size(), theirSetSize, 40, prng0, inputs, sendChls);
	//std::cout << gTimer << std::endl;

	//for (u64 i = 0; i < numThreads; ++i)
	//	sendChls[i].close();



	ep1.stop();	ios.stop();
}

void Mini19Receiver(u64 mySetSize, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	expectedIntersection = mySetSize;

	u64 psiSecParam = 40;
	PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	std::string name = "n";
	IOService ios;
	Endpoint ep0(ios, ipAddr_Port, EpMode::Client, name);
	std::vector<Channel> recvChls(numThreads);

	std::cout << "\n\n====================================Mini19Receiver====================================\n";
	std::cout << "SetSize: " << mySetSize << " vs " << theirSetSize << "   |  numThreads: " << numThreads << "\t";

	std::vector<block> inputs(mySetSize);
	for (u64 i = 0; i < expectedIntersection; ++i)
		inputs[i] = prngSet.get<block>();

	for (u64 i = expectedIntersection; i < inputs.size(); ++i)
		inputs[i] = prng1.get<block>();


	MiniReceiver recv;

	//====================Mini19Receiver outputBigPoly
	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	recv.outputHashing(inputs.size(), theirSetSize, 40, prng1, inputs, recvChls);


	std::cout << gTimer << std::endl;

	u64 dataSent = 0, dataRecv(0);
	for (u64 g = 0; g < recvChls.size(); ++g)
	{
		dataSent += recvChls[g].getTotalDataSent();
		dataRecv += recvChls[g].getTotalDataRecv();
		recvChls[g].resetStats();
	}
	std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";
	std::cout << "recv.mIntersection vs exp : " << recv.mIntersection.size() << " vs " << expectedIntersection << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i].close();


	////====================JL psi startPsi_subsetsum
	//std::cout << "\n\n";
	//for (u64 i = 0; i < numThreads; ++i)
	//	recvChls[i] = ep0.addChannel("chl" + std::to_string(numThreads + i), "chl" + std::to_string(numThreads + i));

	//recv.outputHashing(inputs.size(), theirSetSize, 40, prng1, inputs, recvChls);

	//std::cout << gTimer << std::endl;


	//for (u64 g = 0; g < recvChls.size(); ++g)
	//{
	//	dataSent += recvChls[g].getTotalDataSent();
	//	dataRecv += recvChls[g].getTotalDataRecv();
	//	recvChls[g].resetStats();
	//}
	//std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";
	//std::cout << "recv.mIntersection vs exp : " << recv.mIntersection.size() << " vs " << expectedIntersection << std::endl;

	//for (u64 i = 0; i < numThreads; ++i)
	//	recvChls[i].close();



	ep0.stop(); ios.stop();
}


void MiniPSI_impl()
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
		/*recv.outputBigPoly(recvSet.size(), sendSet.size(), 40, prng1, recvChls);
		recv.outputBigPoly(recvSet, recvChls);
*/
	});

	/*sender.init(sendSet.size(), recvSet.size(), 40, prng0, sendChls);
	sender.outputBigPoly(sendSet, sendChls);*/

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

	std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




	for (u64 i = 0; i < numThreads; ++i)
	{
		sendChls[i].close();
		recvChls[i].close();
	}

	ep0.stop(); ep1.stop();	ios.stop();


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

	/*for (int i = 0; i < checkUnique.size(); i++)
		std::cout << "checkUnique. : " << checkUnique[i] << "\n";*/

}


void testExp(u64 curStepSize)
{
	EllipticCurve mCurve(k283, OneBlock);
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	EccNumber nK(mCurve);
	EccPoint pG(mCurve);
	nK.randomize(prng0);
	pG = mCurve.getGenerator();
	auto g_k = pG*nK;
	
	std::vector<EccNumber> nSeeds;
	nSeeds.reserve(curStepSize);

	for (u64 i = 0; i < curStepSize; i++)
	{
		// get a random value from Z_p
		nSeeds.emplace_back(mCurve);
		nSeeds[i].randomize(prng0);
	}

	gTimer.reset();
	gTimer.setTimePoint("r online g^k^ri start ");
	std::vector<EccPoint> pgK_seeds;
	pgK_seeds.reserve(curStepSize);

	for (u64 k = 0; k < curStepSize; k++)
	{
		pgK_seeds.emplace_back(mCurve);
		pgK_seeds[k] = g_k * nSeeds[k];  //(g^k)^ri
	}
	gTimer.setTimePoint("r online g^k^ri done ");
	//std::cout << gTimer << std::endl;


	SHA1 inputHasher;
	u8 hashOut[SHA1::HashSize];

	std::vector<block> inputs(curStepSize);
	for (u64 i = 0; i < curStepSize; ++i)
		inputs[i] = prng0.get<block>();


	EccNumber b(mCurve);
	EccPoint yb(mCurve), point(mCurve);
	b.randomize(prng0.get<block>());


	//gTimer.reset();
	gTimer.setTimePoint("r online H(x)^b start ");

	//send H(y)^b
	for (u64 k = 0; k < curStepSize; ++k)
	{

		inputHasher.Reset();
		inputHasher.Update(inputs[k]);
		inputHasher.Final(hashOut);
		point.randomize(toBlock(hashOut));

		yb = (point * b);
	}
	gTimer.setTimePoint("r online H(x)^b done ");

	std::cout << gTimer << std::endl;

}

int main(int argc, char** argv)
{

	//u64 curStepSize = 1 << 12;
	//testExp(curStepSize);
	//return 0;
	//#####################ECHD##############
	//curveType = 0 =>k286
	//./bin/frontend.exe -r 0 -echd -c 1 -n 8 & ./bin/frontend.exe -r 1 -echd -c 1 -n 8                                       

	/*subsetSum_test();
	return 0;

	

	MiniPSI_impl();
	return 0;*/
	

	string ipadrr = "localhost:1212";
	u64 sendSetSize = 1 << 8, recvSetSize = 1 << 8, numThreads = 1;

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	if (argc == 7 
		&& argv[3][0] == '-' && argv[3][1] == 'n'
		&& argv[5][0] == '-' && argv[5][1] == 't')
	{
		sendSetSize = 1 << atoi(argv[4]);
		recvSetSize = sendSetSize;
		numThreads = atoi(argv[6]);
	}


	if (argc == 5
		&& argv[3][0] == '-' && argv[3][1] == 'n')
	{
		sendSetSize = 1 << atoi(argv[4]);
		recvSetSize = sendSetSize;
	}

	std::vector<block> sendSet(sendSetSize), recvSet(recvSetSize);

	std::cout << "SetSize: " << sendSetSize << " vs " << recvSetSize << "   |  numThreads: " << numThreads << "\n";
	
#if 0
	std::thread thrd = std::thread([&]() {
		//EchdSender(sendSetSize, recvSetSize, ipadrr, numThreads);
		//JL10Sender(sendSetSize, recvSetSize, "localhost:1212", numThreads);
		Mini19Sender(sendSetSize, recvSetSize, "localhost:1212", numThreads);
	});

	//EchdReceiver(recvSetSize, sendSetSize, ipadrr, numThreads);
	//JL10Receiver(recvSetSize, sendSetSize, "localhost:1212", numThreads);
	Mini19Receiver(recvSetSize, sendSetSize, "localhost:1212", numThreads);

	thrd.join();
	return 0;
#endif

	

	if (argv[1][0] == '-' && argv[1][1] == 't') {
		
		std::thread thrd = std::thread([&]() {
			EchdSender(sendSetSize, recvSetSize, "localhost:1214", numThreads);
			JL10Sender(sendSetSize, recvSetSize,"localhost:1214", numThreads);
		});

		EchdReceiver(recvSetSize, sendSetSize, "localhost:1214", numThreads);
		JL10Receiver(recvSetSize, sendSetSize, "localhost:1214", numThreads);

		thrd.join();

	}
	else if (argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {

		//EchdSender(sendSetSize, recvSetSize, ipadrr, numThreads);
		//JL10Sender(sendSetSize, recvSetSize, "localhost:1212", numThreads);
		Mini19Sender(sendSetSize, recvSetSize, "localhost:1214", numThreads);


	}
	else if (argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {
		//EchdReceiver(recvSetSize, sendSetSize, ipadrr, numThreads);
		//JL10Receiver(recvSetSize, sendSetSize, "localhost:1212", numThreads);
		Mini19Receiver(recvSetSize, sendSetSize, "localhost:1214", numThreads);

	}
	else {
		usage(argv[0]);
	}

	
  
	return 0;
}
