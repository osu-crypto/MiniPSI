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
	std::cout << "\t\t Sender terminal: " << argv0 << " -r 0" << std::endl;
	std::cout << "\t\t Receiver terminal: " << argv0 << " -r 1" << std::endl;

	std::cout << "\t 2. For 2 machines: " << std::endl;
	std::cout << "\t\t Balanced PSI with best communication: " << std::endl;
	std::cout << "\t\t\t Sender terminal: " << argv0 << "-r 0 -n <log(setsize)> -t <#thread> -p 0 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(setsize)> -t <#thread> -p 0 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Sender Example: " << argv0 << "-r 0 -n 16 -t 1 -p 0 -ip 172.31.22.179:1212" << std::endl;


	std::cout << "\t\t Balanced PSI with running time: " << std::endl;
	std::cout << "\t\t\t Sender terminal: " << argv0 << "-r 0 -n <log(setsize)> -t <#thread> -p 1 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(setsize)> -t <#thread> -p 1 -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Sender Example: " << argv0 << "-r 0 -n 16 -t 1 -p 1 -ip 172.31.22.179:1212" << std::endl;


	std::cout << "\t\t Unbalanced PSI: " << std::endl;
	std::cout << "\t\t\t Sender terminal: " << argv0 << "-r 0 -n <log(largesize)> -N <smallsize> -t <#thread> -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Receiver terminal: " << argv0 << "-r 1 -n <log(largesize)> -N <smallsize> -t <#thread> -ip <ip:port>" << std::endl;
	std::cout << "\t\t\t Sender Example: " << argv0 << "-r 0 -n 20 -N 5000 -t 1 -ip 172.31.22.179:1212" << std::endl;


}


void Sender(span<block> inputs, u64 theirSetSize, string ipAddr_Port, u64 numThreads = 1)
{
	u64 psiSecParam = 40;

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep1(ios, ipAddr_Port, EpMode::Server, name);

	std::vector<Channel> sendChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	MiniSender sender;
	gTimer.reset();
	gTimer.setTimePoint("s_start");
	sender.init(inputs.size(), theirSetSize,40, prng0,sendChls);
	gTimer.setTimePoint("s_offline");

	sender.outputBigPoly(inputs, sendChls);

	gTimer.setTimePoint("s_end");
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();

	ep1.stop();	ios.stop();
}


void Receiver( span<block> inputs, u64 theirSetSize, string ipAddr_Port, u64 numThreads=1)
{
	u64 psiSecParam = 40;

	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep0(ios, ipAddr_Port, EpMode::Client, name);

	std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	MiniReceiver recv;
	gTimer.reset();
	gTimer.setTimePoint("r_start");

	recv.init(inputs.size(), theirSetSize,40, prng1,recvChls); //offline
	
	gTimer.setTimePoint("r_offline");
	
	recv.outputBigPoly(inputs, recvChls);
	
	gTimer.setTimePoint("r_end");

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



void MiniPSI_impl()
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
			std::cout << "dupl. : " << str_sum << "\n";
			cnt++;
		}

	}
	std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n";

	/*for (int i = 0; i < checkUnique.size(); i++)
		std::cout << "checkUnique. : " << checkUnique[i] << "\n";*/

}


int main(int argc, char** argv)
{
	//#####################ECHD##############
	//curveType = 0 =>k286
	//./bin/frontend.exe -r 0 -echd -c 1 -n 8 & ./bin/frontend.exe -r 1 -echd -c 1 -n 8                                       

	subsetSum_test();
	return 0;

	string ipadrr = "localhost:1212";

	MiniPSI_impl();
	return 0;
	
	u64 sendSetSize = 1 << 12, recvSetSize = 1 << 12, numThreads = 1;

		
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<block> sendSet(sendSetSize), recvSet(recvSetSize);
	
	std::cout << "SetSize: " << sendSetSize << " vs " << recvSetSize << "   |  numThreads: " << numThreads<< "\t";
	

	
	for (u64 i = 0; i < sendSetSize; ++i)
		sendSet[i] = prng0.get<block>();

	for (u64 i = 0; i < recvSetSize; ++i)
		recvSet[i] = prng0.get<block>();

	for (u64 i = 0; i < expectedIntersection; ++i)
	{
		sendSet[i] = recvSet[i];
	}

	
#if 1
	std::thread thrd = std::thread([&]() {
		Sender(sendSet, recvSetSize, ipadrr, numThreads);

	});

	Receiver(recvSet, sendSetSize, ipadrr, numThreads);


	thrd.join();
	return 0;
#endif

	

	if (argv[1][0] == '-' && argv[1][1] == 't') {
		
		std::thread thrd = std::thread([&]() {
			Sender(sendSet, recvSetSize,"localhost:1212", numThreads);
		});

		Receiver(recvSet, sendSetSize, "localhost:1212", numThreads);

		thrd.join();

	}
	else if (argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {
		Sender(sendSet, recvSetSize, ipadrr, numThreads);
	}
	else if (argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {
		Receiver(recvSet, sendSetSize, ipadrr, numThreads);
	}
	else {
		usage(argv[0]);
	}

	
  
	return 0;
}
