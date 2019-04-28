#include "MiniSender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <unordered_map>

namespace osuCrypto
{
    using namespace std;
	using namespace NTL;


	void MiniSender::outputBigPoly(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;

		mPrng.SetSeed(prng.get<block>());
		mCurveSeed = mPrng.get<block>();
	
		simple.init(mTheirInputSize, recvMaxBinSize, recvNumDummies);

		EllipticCurve mCurve(p256k1, OneBlock);
		mFieldSize = mCurve.bitCount();

		//std::cout << "s mFieldSize= " << mFieldSize << "\n";


		EccNumber nK(mCurve);
		EccPoint pG(mCurve);
		nK.randomize(mPrng);
		pG = mCurve.getGenerator();
		mPolyBytes = pG.sizeBytes();
		//std::cout << "s mPolyBytes= " << mPolyBytes << "\n";

		auto g_k = pG*nK;
		mG_K = new u8[g_k.sizeBytes()];
		g_k.toBytes(mG_K); //g^k

		//EccPoint pGtest(mCurve);
		//EccNumber nKTest(mCurve);
		//pGtest.fromBytes(mG_K);
		//nKTest.fromBytes(mK);
		//std::cout << "s g^k= " << g_k << std::endl;
		//std::cout << "s g^k= " << pGtest << std::endl;
		//std::cout << "s k= " << nK << std::endl;
		//std::cout << "s k= " << nKTest << std::endl;
	

		//####################### online #########################
		gTimer.setTimePoint("r online start ");
		chls[0].asyncSend(mG_K);


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes =  (n1n2MaskBits + 7) / 8;


		//=====================Poly=====================
		u64 degree = mTheirInputSize - 1;
		
			mPrime = mPrime264;
			ZZ_p::init(ZZ(mPrime));

			ZZ_p* zzX = new ZZ_p[inputs.size()];
			ZZ_p* zzY = new ZZ_p[inputs.size()];
			ZZ zz;

			for (u64 idx = 0; idx < inputs.size(); idx++)
			{
				ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
				zzX[idx] = to_ZZ_p(zz);
			}

			ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
			ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];
			

			build_tree(p_tree, zzX, degree * 2 + 1, numThreads, mPrime);
			u8* rcvBlk=new u8[mPolyBytes];

			ZZ_pX recvPolynomial;

			std::vector<u8> recvBuffs;

			
				u64 iterRecvs = 0;
				chls[0].recv(recvBuffs);

				//std::cout << "s recvBuffs[idxBlk].size(): " << recvBuffs.size() << std::endl;

				for (int c = 0; c <= degree; c++) {
					memcpy(rcvBlk, recvBuffs.data() + iterRecvs, mPolyBytes);
					iterRecvs += mPolyBytes;

					//std::cout << "s SetCoeff rcvBlk= " <<c << " - " << toBlock(rcvBlk) << std::endl;

					ZZFromBytes(zz, rcvBlk, mPolyBytes);
					SetCoeff(recvPolynomial, c, to_ZZ_p(zz));
				}
				evaluate(recvPolynomial, p_tree, reminders, degree * 2 + 1, zzY, numThreads, mPrime);

				//for (u64 idx = 0; idx < inputs.size(); idx++)
				//{
				//	u8* pY=new u8[mPolyBytes];
				//	BytesFromZZ(pY, rep(zzY[idx]), mPolyBytes);
				//	std::cout << "s P(y)= " << idx << " - " << toBlock(pY) << std::endl;
				//}



		auto computeGlobalHash = [&](u64 t)
		{
			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				std::vector<u8> sendBuff(n1n2MaskBytes * curStepSize);

				//std::cout << "s startIdx= " << startIdx << "s endIdx= " << endIdx << std::endl;

				EccPoint point_ri(mCurve);
				u8* temp = new u8[point_ri.sizeBytes()];

				for (u64 idx = 0; idx < curStepSize; idx++) 
				{
					//std::cout << "s idx= " << idx << std::endl;
					u64 idxItem = i + idx;

					u8* yri = new u8[point_ri.sizeBytes()];
					BytesFromZZ(yri, rep(zzY[idxItem]), mPolyBytes);

					//if(mPolyBytes!= point_ri.sizeBytes())
					//	std::cout << "mPolyBytes!= point_ri.sizeBytes()" << mPolyBytes <<" != "<< point_ri.sizeBytes() << std::endl;

					//std::cout << "s yri= " << toBlock(yri) <<" - " << toBlock(yri+ sizeof(block)) << std::endl;

					point_ri.fromBytes(yri);

					//std::cout << "s point_ri= " << point_ri << std::endl;

					auto yri_K = point_ri*nK;
					//std::cout << "s yri_K= " << yri_K << std::endl;


					yri_K.toBytes(temp);
					memcpy(sendBuff.data() + idx*n1n2MaskBytes, temp, n1n2MaskBytes);

					std::cout << "s sendIter= " << idxItem << " - " << toBlock(temp) << std::endl;
				}

				std::cout << "s toBlock(sendBuff): "<< toBlock(sendBuff.data()) << std::endl;

				chls[t].asyncSend(std::move(sendBuff));	// some bits of g^(subsum ri)^k
			}
		};


		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				computeGlobalHash(i);
			});
		}
		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("computeMask");

		std::cout << "s mask done\n";


#if 0
		//=====================Sort=====================



		//std::cout << globalHash.size() << " globalHash.size()\n";

		auto compareBlockFunction = [](const block& lhs, const block& rhs) -> bool {
			return memcmp(&lhs, &rhs, sizeof(block)) < 0;
		};

		std::sort(globalHash.begin(), globalHash.end(), compareBlockFunction);
		gTimer.setTimePoint("s_sort");

		//block 
		block boundMaskDiff = ZeroBlock;
		for (u64 i = 0; i < hashMaskBytes * 8; i++)
			boundMaskDiff = boundMaskDiff^mOneBlocks[i];
		//std::cout << boundMaskDiff << "  boundMaskDiff\n";

		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t];

			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);

			
			/*block aaa = ZeroBlock;
			memcpy((u8*)&aaa, sendBuff.data(), n1n2MaskBytes);
			std::cout << aaa << " sendBuff[0] \t" << globalHash[0] << "\n";*/


			block diff;
			for (u64 i = startIdx; i < endIdx - 1; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx-1 - i);


				std::vector<u8> sendBuff(1.02*curStepSize*(hashMaskBytes));

				u64 iterSendDiff = 0;

				memcpy(sendBuff.data(), (u8*)&globalHash[i], n1n2MaskBytes);
				iterSendDiff += n1n2MaskBytes;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 idx = i + k;

					diff = globalHash[idx + 1] - globalHash[idx];

					if (memcmp(&diff, &boundMaskDiff, hashMaskBytes) < 0)
					{
						//std::cout << diff << "  " << idx << "\t ==diff==\t" << globalHash[idx + 1] << "\t" << globalHash[idx] << "\n";
						memcpy(sendBuff.data() + iterSendDiff, (u8*)&diff, hashMaskBytes);
						iterSendDiff += hashMaskBytes;
					}
					else
					{
						//std::cout << diff << "  " << idx << "\t ==dddddiff==\t" << globalHash[idx + 1] << "\t" << globalHash[idx] << "\n";

						memcpy(sendBuff.data() + iterSendDiff, (u8*)&ZeroBlock, hashMaskBytes);
						iterSendDiff += hashMaskBytes;

						memcpy(sendBuff.data() + iterSendDiff, (u8*)& globalHash[idx + 1], n1n2MaskBytes);
						iterSendDiff += n1n2MaskBytes;
					}
					if (iterSendDiff > sendBuff.size())
					{
						std::cout << "iterSendDiff > sendBuff.size(): " << iterSendDiff << "\t" << sendBuff.size() << "\n";
						sendBuff.resize(sendBuff.size() + (inputs.size() - iterSendDiff)*hashMaskBytes);
					}

					//std::cout << "s mask: " << idx << "  " << globalHash[idx+1] << " - " <<globalHash[idx] << " ===diff:===" << diff << "\n";

				}
				//memcpy(sendBuff.data() + iterSendDiff, (u8*)& ZeroBlock, sendBuff.size()- iterSendDiff);


				chl.asyncSend(std::move(sendBuff));
			}
		};

	
		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				sendingMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


#endif
	}


}

