#include "JL10PsiSender.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"

namespace osuCrypto
{

    JL10PsiSender::JL10PsiSender()
    {
    }


    JL10PsiSender::~JL10PsiSender()
    {
    }
    void JL10PsiSender::startPsi(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
    {
		//####################### offline #########################
		gTimer.setTimePoint("s offline start ");

        mSecParam = secParam;
        mPrng.SetSeed(seed);

		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;

		mPrng.SetSeed(seed);
		
		EllipticCurve mCurve(p256k1, OneBlock);
		mFieldSize = mCurve.bitCount();


		EccNumber nK(mCurve);
		EccPoint pG(mCurve);
		nK.randomize(mPrng);
		pG = mCurve.getGenerator();

		auto g_k = pG*nK;

		u8* mG_K = new u8[g_k.sizeBytes()];
		g_k.toBytes(mG_K); //g^k

    
		//####################### online #########################
		gTimer.setTimePoint("s online start ");

		chls[0].asyncSend(mG_K); //send g^k

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

		
		std::vector<std::vector<u8>> sendBuff_mask(chls.size()); //H(x)^k


		//##################### compute H(x*)^k. compute/send yi^k#####################

		auto start = timer.setTimePoint("start");

		auto routine = [&](u64 t)
		{

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			sendBuff_mask[t].resize(n1n2MaskBytes*subsetInputSize);
			int idxSendMaskIter = 0;


			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			//EllipticCurve mCurve(p256k1, OneBlock);
			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve);

			u8* temp= new u8[xk.sizeBytes()];


			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{
				auto curStepSize = std::min(stepSize, inputEndIdx - i);

				//	std::cout << "send H(y)^b" << std::endl;

		//compute H(x)^k
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut)); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;
					xk = (point * nK); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "s xk[" << i+k << "] " << xk << std::endl;
#endif
					xk.toBytes(temp);
					memcpy(sendBuff_mask[t].data()+ idxSendMaskIter, temp, n1n2MaskBytes);
					idxSendMaskIter += n1n2MaskBytes;
				}

#if 1
				//receive yi=H(.)*g^ri
				std::vector<u8> recvBuff(xk.sizeBytes() * curStepSize); //receiving yi^k = H(.)*g^ri

				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}

				auto recvIter = recvBuff.data();

				std::vector<u8> sendBuff_yik(yik.sizeBytes() * curStepSize);
				auto sendIter_yik = sendBuff_yik.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yi.fromBytes(recvIter); recvIter += yi.sizeBytes();
					yik = yi*nK; //yi^k
					yik.toBytes(sendIter_yik);
					sendIter_yik += yik.sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff_yik));  //sending yi^k
#endif
			}
		

		};


		for (u64 i = 0; i < numThreads; ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


		//#####################Send Mask #####################

#if 1
		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);
			u64 subsetInputSize = endIdx - startIdx;



			auto myMasks = sendBuff_mask[t].data();
			std::cout << "s toBlock(sendBuff_mask): " << t << " - " << toBlock(myMasks) << std::endl;

			chl.asyncSend(std::move(sendBuff_mask[t]));


		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("s Psi done");
		std::cout << "s gkr done\n";


	}
	
	void JL10PsiSender::startPsi_subsetsum(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
		gTimer.setTimePoint("s offline start ");

		mSecParam = secParam;
		mPrng.SetSeed(seed);

		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;

		mPrng.SetSeed(seed);

		EllipticCurve mCurve(p256k1, OneBlock);
		mFieldSize = mCurve.bitCount();


		EccNumber nK(mCurve);
		EccPoint pG(mCurve);
		nK.randomize(mPrng);
		pG = mCurve.getGenerator();

		auto g_k = pG*nK;

		u8* mG_K = new u8[g_k.sizeBytes()];
		g_k.toBytes(mG_K); //g^k


						   //####################### online #########################
		gTimer.setTimePoint("s online start ");

		chls[0].asyncSend(mG_K); //send g^k

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;


		std::vector<std::vector<u8>> sendBuff_mask(chls.size()); //H(x)^k


																 //##################### compute H(x*)^k. compute/send yi^k#####################

		auto start = timer.setTimePoint("start");

		auto routine = [&](u64 t)
		{

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			sendBuff_mask[t].resize(n1n2MaskBytes*subsetInputSize);
			int idxSendMaskIter = 0;


			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			//EllipticCurve mCurve(p256k1, OneBlock);
			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve);

			u8* temp = new u8[xk.sizeBytes()];


			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{
				auto curStepSize = std::min(stepSize, inputEndIdx - i);

				//	std::cout << "send H(y)^b" << std::endl;

				//compute H(x)^k
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut)); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;
					xk = (point * nK); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "s xk[" << i + k << "] " << xk << std::endl;
#endif
					xk.toBytes(temp);
					memcpy(sendBuff_mask[t].data() + idxSendMaskIter, temp, n1n2MaskBytes);
					idxSendMaskIter += n1n2MaskBytes;
				}

#if 1
				//receive yi=H(.)*g^ri
				std::vector<u8> recvBuff(xk.sizeBytes() * curStepSize); //receiving yi^k = H(.)*g^ri

				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}

				auto recvIter = recvBuff.data();

				std::vector<u8> sendBuff_yik(yik.sizeBytes() * curStepSize);
				auto sendIter_yik = sendBuff_yik.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yi.fromBytes(recvIter); recvIter += yi.sizeBytes();
					yik = yi*nK; //yi^k
					yik.toBytes(sendIter_yik);
					sendIter_yik += yik.sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff_yik));  //sending yi^k
#endif
			}


		};


		for (u64 i = 0; i < numThreads; ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


		//#####################Send Mask #####################

#if 1
		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);
			u64 subsetInputSize = endIdx - startIdx;



			auto myMasks = sendBuff_mask[t].data();
			std::cout << "s toBlock(sendBuff_mask): " << t << " - " << toBlock(myMasks) << std::endl;

			chl.asyncSend(std::move(sendBuff_mask[t]));


		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("s Psi done");
		std::cout << "s gkr done\n";


	}

	bool JL10PsiSender::startPsi_subsetsum_malicious(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
		gTimer.setTimePoint("s offline start ");

		mSecParam = secParam;
		mPrng.SetSeed(seed);

		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;

		mPrng.SetSeed(seed);

		EllipticCurve mCurve(p256k1, OneBlock);
		mFieldSize = mCurve.bitCount();


		EccNumber nK(mCurve);
		EccPoint pG(mCurve);
		nK.randomize(mPrng);
		pG = mCurve.getGenerator();

		auto g_k = pG*nK;

		u8* mG_K = new u8[g_k.sizeBytes()];
		g_k.toBytes(mG_K); //g^k

		EccNumber nV(mCurve);
		nV.randomize(mPrng); //g^v for ZKDL

		std::vector<block> hashX(inputs.size());

						   //####################### online #########################
		gTimer.setTimePoint("s online start ");

		chls[0].asyncSend(mG_K); //send g^k

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;


		std::vector<block> xik(inputs.size()); //H(x)^k //todo: not really secure here


																 //##################### compute H(x*)^k. compute/send yi^k#####################

		auto start = timer.setTimePoint("start");

		auto routine = [&](u64 t)
		{
			
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			auto& chl = chls[t];
			SHA1 inputHasher;
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			//EllipticCurve mCurve(p256k1, OneBlock);
			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve);

			u8* temp = new u8[xk.sizeBytes()];


			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{
				auto curStepSize = std::min(stepSize, inputEndIdx - i);
				std::vector<u8*> challeger_bytes(2); //(yi^k, yi^v)
				block* challenger = new block[numSuperBlocks]; //H(yi^k, yi^v)
				block temp_challenger = ZeroBlock;

				//	std::cout << "send H(y)^b" << std::endl;

				//compute H(x)^k
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					hashX[i + k] = toBlock(hashOut);
					point.randomize(hashX[i + k]); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;
					xk = (point * nK); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "s xk[" << i + k << "] " << xk << std::endl;
#endif
					u8* temp= new u8[xk.sizeBytes()];
					xk.toBytes(temp);

					block blkTemp = ZeroBlock;
					for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
					{
						auto minsize = std::min(sizeof(block), xk.sizeBytes() - idxBlock * sizeof(block));
						memcpy((u8*)&blkTemp, temp+minsize, minsize);
						xik[i+k] = xik[i + k] + blkTemp;
					}
				}

#if 1
				//receive yi=H(.)*g^ri
				std::vector<u8> recvBuff(xk.sizeBytes() * curStepSize); //receiving yi^k = H(.)*g^ri

				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}

				auto recvIter = recvBuff.data();

				std::vector<u8> sendBuff_yik((yik.sizeBytes()*2+1) * curStepSize); //sending yi^k, yi^v, r s.t. r=v-c*k
				auto sendIter_yik = sendBuff_yik.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yi.fromBytes(recvIter); recvIter += yi.sizeBytes();
					yik = yi*nK; //yi^k

					challeger_bytes[0] = new u8[yik.sizeBytes()];
					yik.toBytes(challeger_bytes[0]); //yi^k  


					auto yiv = yi*nV;
					challeger_bytes[1] = new u8[yiv.sizeBytes()];
					yiv.toBytes(challeger_bytes[1]); //yi^v

					
					for (int idxChall = 0; idxChall < challeger_bytes.size(); idxChall++)
						for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
						{
							auto minsize = std::min(sizeof(block), yiv.sizeBytes() - idxBlock * sizeof(block));
							memcpy((u8*)&temp_challenger, challeger_bytes[idxChall] + idxBlock * minsize, minsize);
							challenger[idxBlock] = challenger[idxBlock] + temp_challenger;
						}

					yik.toBytes(sendIter_yik);//todo: optimzing this
					sendIter_yik += yik.sizeBytes();

					yiv.toBytes(sendIter_yik);// sending yi^v
					sendIter_yik += yik.sizeBytes();
				}

				std::vector<block> cipher_challenger(numSuperBlocks);
				mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data()); //compute H(sum (yi^k+ yi^v))
				EccNumber nC(mCurve);
				u8* nC_bytes = new u8[nC.sizeBytes()];
				memcpy(nC_bytes, cipher_challenger.data(), nC.sizeBytes());
				nC.fromBytes(nC_bytes); //c=H(sum (yi^k+ yi^v))

				std::cout << "s nC= " << nC << " idx= " << i << "\n";

				EccNumber nR(mCurve);
				nR = nV - nC*nK; //r=v-ck
				nR.toBytes(sendIter_yik);

				chl.asyncSend(std::move(sendBuff_yik));  //sending yi^k||yi^v...||r

				u8* onebit;
				chl.recv(onebit);
				if (onebit[0] == 1)
					return false;
#endif
			}


		};


		for (u64 i = 0; i < numThreads; ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


		//#####################Send Mask #####################

#if 1
		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);
			u64 subsetInputSize = endIdx - startIdx;

			SHA1 inputHasher;
			u8 hashOut[SHA1::HashSize];

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{

				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
				std::vector<u8> sendBuff_mask(n1n2MaskBytes * curStepSize);

				for (u64 k = 0; k < curStepSize; ++k)
				{
					inputHasher.Reset();
					xik[i + k] = xik[i + k] + hashX[i + k];//not really secur here
					//inputHasher.Update(hashX[i + k]);
					inputHasher.Update(xik[i+k]);
					inputHasher.Final(hashOut);

					memcpy(sendBuff_mask.data() + k*n1n2MaskBytes, hashOut, n1n2MaskBytes);
				}
			//	std::cout << "s toBlock(sendBuff_mask): " << t << " - " << toBlock(sendBuff_mask) << std::endl;
				chl.asyncSend(std::move(sendBuff_mask));
			}
		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("s Psi done");
		std::cout << "s gkr done\n";

		return true;

	}

}