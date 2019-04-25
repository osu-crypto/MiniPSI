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
    void JL10PsiSender::init(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed)
    {
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

		mG_K = new u8[g_k.sizeBytes()];
		mK = new u8[nK.sizeBytes()];

		g_k.toBytes(mG_K); //g^k
		nK.toBytes(mK);  //k

    }


    void JL10PsiSender::sendInput_k283(span<block> inputs, span<Channel> chls)
	{
		chls[0].asyncSend(mG_K);

		EllipticCurve mCurve(p256k1, OneBlock);
		EccNumber nK(mCurve);
		nK.fromBytes(mK);


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;  //64 / 8;// (n1n2MaskBits + 7) / 8;

		
		std::vector<std::vector<u8>> sendBuff_mask(chls.size()); //H(x)^k


		//##################### compute H(x*)^k. compute/send yi^k#####################

		auto start = timer.setTimePoint("start");

		auto routine = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			sendBuff_mask[t].resize(n1n2MaskBytes*subsetInputSize);
			auto sendMaskIter = sendBuff_mask[t].data();


			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			EllipticCurve mCurve(p256k1, OneBlock);
			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve);


			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{
				auto curStepSize = std::min(stepSize, inputEndIdx - i);

				//	std::cout << "send H(y)^b" << std::endl;

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut)); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;
					xk = (point * nK); //H(x)^k

#ifdef PRINT
					if (i == 0)
						std::cout << "yb[" << i << "] " << yb << std::endl;
#endif
					xk.toBytes(sendMaskIter);
					sendMaskIter += n1n2MaskBytes;
				}

				
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
			}
		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}


		//#####################Send Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);
			u64 subsetInputSize = endIdx - startIdx;

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

		gTimer.setTimePoint("r on masks done");
		std::cout << "r gkr done\n";


	}


	

}