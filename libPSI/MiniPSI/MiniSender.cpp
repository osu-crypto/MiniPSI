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


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");
		chls[0].asyncSend(mG_K);


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


		


	}


	void MiniSender::outputHashing(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
#pragma region Offline
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

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;
		simple.init(mTheirInputSize, recvMaxBinSize, recvNumDummies);

#pragma endregion

		//####################### online #########################
		gTimer.setTimePoint("r online start ");
		simple.insertItems(inputs);
		gTimer.setTimePoint("s_binning");

		chls[0].asyncSend(mG_K);

		std::vector<std::vector<u8>> sendBuff_mask(chls.size()); //H(x)^k
		std::array<std::vector<u8>, 2> globalHash;
		globalHash[0].resize(inputs.size()*n1n2MaskBytes);
		globalHash[1].resize(inputs.size()*n1n2MaskBytes);
		std::array<std::vector<u64>, 2>permute;
		int idxPermuteDone[2];
		for (u64 j = 0; j < 2; j++)
		{
			permute[j].resize(inputs.size());
			for (u64 i = 0; i < inputs.size(); i++)
				permute[j][i] = i;

			//permute position
			//std::shuffle(permute[j].begin(), permute[j].end(), mPrng);
			idxPermuteDone[j] = 0; //count the number of permutation that is done.
		}


		//=====================compute P(x)^k=====================
		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = simple.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (simple.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, simple.mNumBins);
			
			polyNTL poly;
			poly.NtlPolyInit(mPolyBytes);

			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);
				
				
				//=====================receive Poly=====================
				std::vector<u8> recvBuff;
				chl.recv(recvBuff); 
				u64 iterSend = 0, iterRecv = 0;

				if (recvBuff.size() != curStepSize * simple.mTheirMaxBinSize*mPolyBytes)
				{
					std::cout << "error @ recvBuff.size() != curStepSize * simple.mTheirMaxBinSize*mPolyBytes " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}


				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					//std::cout << "bIdx= " << bIdx << std::endl;

					u64 realNumItem = simple.mBins[bIdx].blks.size();

					u64 degree = simple.mTheirMaxBinSize - 1;
					std::vector<std::array<block, numSuperBlocks>> YRi_bytes(realNumItem), coeffs(degree + 1); //
					block rcvBlk;


					for (int c = 0; c < coeffs.size(); c++)
					{
						memcpy((u8*)&coeffs[c], recvBuff.data() + iterRecv, mPolyBytes);
						iterRecv += mPolyBytes;

						//for (int iii = 0; iii < numSuperBlocks; iii++)
							//std::cout << coeffs[c][iii] << "  s coeff bin#" << bIdx<<"\n";
					}


					poly.evalSuperPolynomial(coeffs, simple.mBins[bIdx].blks, YRi_bytes); //P(x)
					//std::cout << "poly.evalSuperPolynomial done YRi_bytes.size()=" << YRi_bytes.size() << std::endl;

					
					/*for (u64 idx = 0; idx < YRi_bytes.size(); ++idx)
					{
						std::cout << simple.mBins[bIdx].blks[idx] << "\n";
						for (int iii = 0; iii < numSuperBlocks; iii++)
							std::cout << YRi_bytes[idx][iii] << " s P(x)\n";
						
						std::cout << "\n";
					}*/


					


					for (u64 idx = 0; idx < YRi_bytes.size(); ++idx)
					{
						
						EccPoint point_ri(mCurve);

						u8* yri = new u8[mPolyBytes];
						memcpy(yri, (u8*)&YRi_bytes[idx], mPolyBytes);
						
						//std::cout << simple.mBins[bIdx].blks[idx] << "  s x bin#" << bIdx << "\n";
						//std::cout << toBlock(yri) << "\n";
						//std::cout << toBlock(yri + sizeof(block)) << "\n";
						//std::cout << toBlock(yri+2*sizeof(block)) << "\n";
						//for (int iii = 0; iii < numSuperBlocks; iii++)
						//	std::cout << YRi_bytes[idx][iii] << " s evalP(x) bin#" << bIdx << "\n";


						
						point_ri.fromBytes(yri);
						//std::cout << "s point_ri= " << point_ri << std::endl;

						auto yri_K = point_ri*nK; //P(x)^k
						//std::cout << "s yri_K[" << idx << "]= " << yri_K << std::endl;
						u8* temp = new u8[mPolyBytes];
						yri_K.toBytes(temp);

						u64 hashIdx = simple.mBins[bIdx].hashIdxs[idx];
						memcpy(globalHash[hashIdx].data() + permute[hashIdx][idxPermuteDone[hashIdx]++] * n1n2MaskBytes
							, temp, n1n2MaskBytes);

						//std::cout << "s sendIter= " << idxItem << " - " << toBlock(temp) << std::endl;
					}
				}
			}
		};


		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}
		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("s P(x)^k done");

		std::cout << "s P(x)^k done\n";


		//#####################Send Mask #####################

#if 1
		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					std::vector<u8> sendBuff(curStepSize*n1n2MaskBytes);
					memcpy(sendBuff.data(), globalHash[hIdx].data() + i*n1n2MaskBytes, curStepSize*n1n2MaskBytes);
					chl.asyncSend(std::move(sendBuff));
				}

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
		gTimer.setTimePoint("r Psi done");
		std::cout << "s gkr done\n";

	}

}

