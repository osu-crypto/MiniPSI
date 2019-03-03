#include "MiniReceiver.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "Poly/polyFFT.h"


using namespace std;
using namespace NTL;

namespace osuCrypto
{
	void MiniReceiver::init(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<Channel> chls)
	{

		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(prng.get<block>());

		mBalance.init(mMyInputSize, recvMaxBinSize, recvNumDummies);


		//seed for subset-sum exp
		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();

		std::cout << "r mFieldSize= " << mFieldSize << "\n";


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		std::cout << mG << std::endl;

		std::vector<EccNumber> mSeeds;
		std::vector<EccPoint> mG_seeds;
		mSeeds.reserve(mSetSeedsSize);
		mG_seeds.reserve(mSetSeedsSize);

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			mSeeds.emplace_back(mCurve);
			mSeeds[i].randomize(prng);

			//      mG_seeds[i] = g ^ mSeeds[i]
			mG_seeds.emplace_back(mCurve);
			mG_seeds[i] = mG * mSeeds[i];
			//std::cout << mG_seeds[i] << std::endl;
		}

		//generate all pairs from seeds
		mG_pairs.reserve(myInputSize);
		mSubsetSum.reserve(myInputSize);

		std::vector<u64> indices(mSetSeedsSize);


		for (u64 i = 0; i < myInputSize; i++)
		{
			std::iota(indices.begin(), indices.end(), 0);
			std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

			EccPoint g_sum(mCurve);
			int sum = 0;

			for (u64 j = 0; j < mChoseSeedsSize; j++)
			{
				sum += indices[j]; //sum
				g_sum = g_sum + mG_seeds[indices[j]]; //g^sum
			}

			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);
			mG_pairs.push_back(std::make_pair(sum, temp));

			std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
			mSubsetSum.push_back(std::make_pair(mG_pairs[i].first, subIdx));

			std::cout << "r sum= " << mG_pairs[i].first
				<< " - " << sizeof(mG_pairs[i].second)
				<< " - " << g_sum.sizeBytes()
				<< " - " << toBlock(mG_pairs[i].second)
				<< " - " << toBlock(mG_pairs[i].second + sizeof(block))
				<< " - " << toBlock(mG_pairs[i].second + g_sum.sizeBytes() - 2 * sizeof(block)) << std::endl;

			EccPoint g_sumTest(mCurve);
			g_sumTest.fromBytes(mG_pairs[i].second);
			std::cout << g_sum << "\n";
			std::cout << g_sumTest << "\n";

			u8* tempBlk = new u8[g_sum.sizeBytes()];
			tempBlk = mG_pairs[i].second;
			g_sumTest.fromBytes(tempBlk);
			std::cout << g_sumTest << "\n";

		}
	}

#if 0
	void MiniReceiver::output(span<block> inputs, span<Channel> chls)
	{

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 lastPolyMaskBytes = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
		u64 hashMaskBytes = (40 + log2(mTheirInputSize*mMyInputSize) + 7) / 8;

		//=====================Balaced Allocation=====================
		//gTimer.reset();
		mBalance.insertItems(inputs);
		gTimer.setTimePoint("r_binning");
		//std::cout << gTimer << std::endl;

	/*	std::cout << IoStream::lock;
		mBalance.print(inputs);
		std::cout << IoStream::unlock;*/

		std::array<std::unordered_map<u64, std::pair<block, u64>>, 2> localMasks; //for hash 0 and 1
		localMasks[0].reserve(inputs.size());//for hash 0
		localMasks[1].reserve(inputs.size());//for hash 1


		//=====================Poly=====================
		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = mBalance.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (mBalance.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, mBalance.mNumBins);

			polyNTL poly;

#ifdef GF2X_Slicing
			poly.NtlPolyInit(sizeof(block));
			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/
#else
			poly.NtlPolyInit(polyMaskBytes);
#endif // GF2X_Slicing


			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);

				std::vector<u8> sendBuff(curStepSize*mBalance.mMaxBinSize*polyMaskBytes);

				std::vector<std::vector<std::array<block, numSuperBlocks>>> rowT(curStepSize);

				u64 iterSend = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					rowT[k].resize(mBalance.mBins[bIdx].cnt);
					std::vector<std::array<block, numSuperBlocks>> rowU(mBalance.mBins[bIdx].cnt);
					std::vector<std::array<block, numSuperBlocks>> rowR(mBalance.mBins[bIdx].cnt);

					//=====================Compute OT row=====================
					prfOtRows(mBalance.mBins[bIdx].blks, rowT[k], mAesT);
					prfOtRows(mBalance.mBins[bIdx].blks, rowU, mAesU);

					//comput R=T+U
					for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
						for (u64 j = 0; j < numSuperBlocks; ++j)
							rowR[idx][j] = rowT[k][idx][j] ^ rowU[idx][j];

					//=====================Pack=====================
					u64 degree = mBalance.mMaxBinSize - 1;
					std::vector<std::array<block, numSuperBlocks>> coeffs;

					poly.getSuperBlksCoefficients(degree, mBalance.mBins[bIdx].blks, rowR, coeffs);


					for (int c = 0; c < coeffs.size(); c++) {
						memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], polyMaskBytes);
						iterSend += polyMaskBytes;
					}

				}
				//std::cout << sendBuff.size() << "  sendBuff.size()\n";

				chl.asyncSend(std::move(sendBuff)); //send poly

#if 1
				std::vector<block> cipher(4);
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;

					for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
					{
						rowT[k][idx][numSuperBlocks - 1] = rowT[k][idx][numSuperBlocks - 1] & mTruncateBlk; //get last 440-3*128 bits
						mBalance.mAesHasher.ecbEncFourBlocks(rowT[k][idx].data(), cipher.data());

						for (u64 j = 1; j < numSuperBlocks; ++j)
							cipher[0] = cipher[0] ^ cipher[j];

						/*if (bIdx== bIdxForDebug && idx==iIdxForDebug)
						{
							std::cout << "recvMask " << cipher << " X= "<< inputs[it.mIdx]<< " hIdx " << it.mHashIdx<< "\n";
							recvMaskForDebug = cipher;
						}*/

						//std::cout << IoStream::lock;
						if (isMultiThreaded)
						{
							std::lock_guard<std::mutex> lock(mtx);
							localMasks[mBalance.mBins[bIdx].hashIdxs[idx]].emplace(*(u64*)&cipher[0]
								, std::pair<block, u64>(cipher[0], mBalance.mBins[bIdx].idxs[idx]));
						}
						else
						{
							localMasks[mBalance.mBins[bIdx].hashIdxs[idx]].emplace(*(u64*)&cipher[0]
								, std::pair<block, u64>(cipher[0], mBalance.mBins[bIdx].idxs[idx]));
						}


						//std::cout << IoStream::unlock;
					}
				}

			}

		};


		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("r_poly");

#ifdef PSI_PRINT
		for (int j = 0; j < 2; j++)
			for (auto it = localMasks[j].begin(); it != localMasks[j].end(); ++it)//for each bin, list all alter light bins
			{
				block globalTest;
				memcpy((u8*)&globalTest, (u8*)&it->first, sizeof(u64));
				std::cout << "localMasks " << j << "\t" << globalTest << "\n";
			}
#endif // PSI_PRIN
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
				std::vector<u8> recvBuffs;

				//receive the sender's marks, we have 2 buffs that corresponding to the mask of elements used hash index 0,1
				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					chl.recv(recvBuffs); //receive Hash

					auto theirMasks = recvBuffs.data();

					if (hashMaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							auto& msk = *(u64*)(theirMasks);
							// check 64 first bits
							auto match = localMasks[hIdx].find(msk);

							//if match, check for whole bits
							if (match != localMasks[hIdx].end())
							{
								if (memcmp(theirMasks, &match->second.first, hashMaskBytes) == 0) // check full mask
								{
									if (isMultiThreaded)
									{
										std::lock_guard<std::mutex> lock(mtx);
										mIntersection.push_back(match->second.second);
									}
									else
									{
										mIntersection.push_back(match->second.second);
									}
								}
							}
							theirMasks += hashMaskBytes;
						}
					}
					else //for small set, do O(n^2) check
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							for (auto match = localMasks[hIdx].begin(); match != localMasks[hIdx].end(); ++match)
							{
								if (memcmp(theirMasks, &match->second.first, hashMaskBytes) == 0) // check full mask
								{
									mIntersection.push_back(match->second.second);
								}
								theirMasks += hashMaskBytes;
							}
						}
					}


				}

#endif



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

	}

	void MiniReceiver::outputBestComm(span<block> inputs, span<Channel> chls)
	{

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40 + log2(mMyInputSize) + 2 + 7) / 8;
		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;


		//=====================Balaced Allocation=====================
		//gTimer.reset();
		mBalance.insertItems(inputs);
		gTimer.setTimePoint("r_binning");
		//std::cout << gTimer << std::endl;

		/*	std::cout << IoStream::lock;
		mBalance.print(inputs);
		std::cout << IoStream::unlock;*/

		std::array<std::unordered_map<u32, std::pair<block, u64>>, 2> localMasks; //for hash 0 and 1
		localMasks[0].reserve(inputs.size());//for hash 0
		localMasks[1].reserve(inputs.size());//for hash 1


											 //=====================Poly=====================
		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = mBalance.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (mBalance.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, mBalance.mNumBins);

			polyNTL poly;

#ifdef GF2X_Slicing
			poly.NtlPolyInit(sizeof(block));
			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/
#else
			poly.NtlPolyInit(polyMaskBytes);
#endif // GF2X_Slicing


			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);

				std::vector<u8> sendBuff(curStepSize*mBalance.mMaxBinSize*polyMaskBytes);

				std::vector<std::vector<std::array<block, numSuperBlocks>>> rowT(curStepSize);

				u64 iterSend = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					rowT[k].resize(mBalance.mBins[bIdx].cnt);
					std::vector<std::array<block, numSuperBlocks>> rowU(mBalance.mBins[bIdx].cnt);
					std::vector<std::array<block, numSuperBlocks>> rowR(mBalance.mBins[bIdx].cnt);

					//=====================Compute OT row=====================
					prfOtRows(mBalance.mBins[bIdx].blks, rowT[k], mAesT);
					prfOtRows(mBalance.mBins[bIdx].blks, rowU, mAesU);

					//comput R=T+U
					for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
						for (u64 j = 0; j < numSuperBlocks; ++j)
							rowR[idx][j] = rowT[k][idx][j] ^ rowU[idx][j];

					//=====================Pack=====================
#ifdef GF2X_Slicing
					std::vector<std::vector<item>> subIdxItems(curStepSize);
					u64 degree = mBalance.mMaxBinSize - 1;
					std::vector<block> X(cntRows), Y(cntRows), coeffs;
					for (u64 idx = 0; idx < cntRows; ++idx)
						memcpy((u8*)&X[idx], (u8*)&inputs[subIdxItems[k*mBalance.mMaxBinSize + idx].mIdx], sizeof(block));

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (u64 idx = 0; idx < cntRows; ++idx)
							memcpy((u8*)&Y[idx], (u8*)&rowR[idx][j], sizeof(block));

						//if (j == numSuperBlocks - 1)
						//{
						//	poly_lastBlk.getBlkCoefficients(degree, X, Y, coeffs);  //pad with dummy here
						//	for (int c = 0; c < coeffs.size(); c++) {
						//		memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], lastBlkByteSize);
						//		iterSend += lastBlkByteSize;
						//	}
						//}
						//else
						{
							poly.getBlkCoefficients(degree, X, Y, coeffs);  //pad with dummy here
							for (int c = 0; c < coeffs.size(); c++) {
								memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], sizeof(block));
								iterSend += sizeof(block);
							}
						}
					}
#else
					u64 degree = mBalance.mMaxBinSize - 1;
					std::vector<std::array<block, numSuperBlocks>> coeffs;

					poly.getSuperBlksCoefficients(degree, mBalance.mBins[bIdx].blks, rowR, coeffs);


					for (int c = 0; c < coeffs.size(); c++) {
						memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], polyMaskBytes);
						iterSend += polyMaskBytes;
					}

#endif // GF2X_Slicing

				}

				chl.asyncSend(std::move(sendBuff)); //send poly
				sendBuff.clear();

				std::vector<block> cipher(4);
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;

					for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
					{
						rowT[k][idx][numSuperBlocks - 1] = rowT[k][idx][numSuperBlocks - 1] & mTruncateBlk; //get last 440-3*128 bits
						mBalance.mAesHasher.ecbEncFourBlocks(rowT[k][idx].data(), cipher.data());

						for (u64 j = 1; j < numSuperBlocks; ++j)
							cipher[0] = cipher[0] ^ cipher[j];

						/*if (bIdx== bIdxForDebug && idx==iIdxForDebug)
						{
						std::cout << "recvMask " << cipher << " X= "<< inputs[it.mIdx]<< " hIdx " << it.mHashIdx<< "\n";
						recvMaskForDebug = cipher;
						}*/

						if (isMultiThreaded)
						{
							std::lock_guard<std::mutex> lock(mtx);
							localMasks[mBalance.mBins[bIdx].hashIdxs[idx]].emplace(*(u32*)&cipher[0]
								, std::pair<block, u64>(cipher[0], mBalance.mBins[bIdx].idxs[idx]));
						}
						else
						{
							localMasks[mBalance.mBins[bIdx].hashIdxs[idx]].emplace(*(u32*)&cipher[0]
								, std::pair<block, u64>(cipher[0], mBalance.mBins[bIdx].idxs[idx]));
						}

					}
				}

			}

		};


		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("r_poly");

#ifdef PSI_PRINT
		for (int j = 0; j < 2; j++)
			for (auto it = localMasks[j].begin(); it != localMasks[j].end(); ++it)//for each bin, list all alter light bins
			{
				block globalTest;
				memcpy((u8*)&globalTest, (u8*)&it->first, sizeof(u64));
				std::cout << "localMasks " << j << "\t" << globalTest << "\n";
			}
#endif // PSI_PRIN
		//#####################Receive Mask #####################



		auto receivingMasks = [&](u64 hIdx, Channel chl)
		{

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash


			/*block aaa;
			memcpy((u8*)&aaa, recvBuffs.data(), n1n2MaskBytes);
			std::cout << aaa << " recvBuffs[0] \n";*/

			block theirMasks, theirDiff;

			memcpy((u8*)&theirMasks, recvBuffs.data(), n1n2MaskBytes);
			memcpy((u8*)&theirDiff, recvBuffs.data() + n1n2MaskBytes, n1n2MaskBytes);


			/*auto theirMasks = recvBuffs.data();

			auto theirMasks = recvBuffs.data();
			auto theirDiff = recvBuffs.data()+ n1n2MaskBytes;*/

			bool isOverBound = true;
			u64 maskLength = hashMaskBytes;


			u64 iterTheirMask = 0;
			u64 iterTheirDiff = n1n2MaskBytes;
			u64 iterX = 0;

			while (iterTheirDiff < recvBuffs.size())
			{

				auto match = localMasks[hIdx].find(*(u32*)&theirMasks);

				maskLength = isOverBound ? n1n2MaskBytes : hashMaskBytes;

				if (match != localMasks[hIdx].end())//if match, check for whole bits
				{
					if (memcmp((u8*)&theirMasks, &match->second.first, maskLength) == 0) // check full mask
					{
						if (isMultiThreaded)
						{
							std::lock_guard<std::mutex> lock(mtx);
							mIntersection.push_back(match->second.second);
						}
						else
						{
							mIntersection.push_back(match->second.second);
						}

						//std::cout << "r mask: " << match->second.first << "\n";

					}
				}

				if (memcmp((u8*)&theirDiff, &ZeroBlock, hashMaskBytes) == 0)
				{
					isOverBound = true;
					iterTheirMask = iterTheirDiff + hashMaskBytes;
					memcpy((u8*)&theirMasks, recvBuffs.data() + iterTheirMask, n1n2MaskBytes);

					iterTheirDiff = iterTheirMask + n1n2MaskBytes;
					memcpy((u8*)&theirDiff, recvBuffs.data() + iterTheirDiff, n1n2MaskBytes);

				}
				else
				{
					block next = theirDiff + theirMasks;

					/*std::cout << IoStream::lock;
					std::cout << "r mask: " << iterX << "  " << next << " - " << theirMasks << " ===diff:===" << theirDiff << "\n";
					std::cout << IoStream::unlock;*/

					theirMasks = next;


					if (isOverBound)
						iterTheirMask += n1n2MaskBytes;
					else
						iterTheirMask += hashMaskBytes;

					iterTheirDiff += hashMaskBytes;
					memcpy((u8*)&theirDiff, recvBuffs.data() + iterTheirDiff, hashMaskBytes);
					isOverBound = false;
				}
				iterX++;
			}
		};


		if (isMultiThreaded)
		{
			for (u64 i = 0; i < 2; ++i)
			{
				thrds[i] = std::thread([=] {
					receivingMasks(i, chls[i]);
				});
			}

			for (u64 i = 0; i < 2; ++i)
				thrds[i].join();
		}
		else
		{
			receivingMasks(0, chls[0]);
			receivingMasks(1, chls[0]);
		}



	}

#endif

	void MiniReceiver::outputBigPoly(span<block> inputs, span<Channel> chls)
	{


		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;

		u8* mG_K;
		chls[0].recv(mG_K);
		EccPoint g_k(mCurve);
		g_k.fromBytes(mG_K);

		std::cout << "r g^k= " << g_k << std::endl;




		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);

		std::mutex mtx;
		u64 polyMaskBytes = g_k.sizeBytes();
		u64 hashMaskBytes = (40 + log2(mMyInputSize) + 2 + 7) / 8;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

		std::unordered_map<u32, std::pair<block, u64>> localMasks;
		//localMasks.reserve(inputs.size());

		//=====================Poly=====================
		mPrime = mPrime264;
		ZZ_p::init(ZZ(mPrime));

		u64 degree = inputs.size() - 1;
		ZZ_p* zzX = new ZZ_p[inputs.size()];
		ZZ_p* zzY = new ZZ_p[inputs.size()];

		ZZ zz;
		ZZ_pX *M = new ZZ_pX[degree * 2 + 1];;
		ZZ_p *a = new ZZ_p[degree + 1];;
		ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];
		ZZ_pX Polynomial;
		std::vector<u8> sendBuff;


		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);
		}

		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			u8* yri = new u8[polyMaskBytes];

			ZZFromBytes(zz, mG_pairs[idx].second, polyMaskBytes);
			std::cout << "r P(x)= " << idx << " - " << toBlock(mG_pairs[idx].second) << std::endl;
			zzY[idx] = to_ZZ_p(zz);

			BytesFromZZ(yri, rep(zzY[idx]), polyMaskBytes);
			std::cout << "rr P(x)= " << idx << " - " << toBlock(yri) << std::endl;

			EccPoint g_sumTest(mCurve);
			g_sumTest.fromBytes(mG_pairs[idx].second);
			std::cout << sizeof(mG_pairs[idx].second) << "\n";
			std::cout << g_sumTest << "\n";

			//memcpy(yri, mG_pairs[idx].second, mFieldSize);
			g_sumTest.fromBytes(yri);
			std::cout << sizeof(yri) << "\n";
			std::cout << g_sumTest << "\n";

		}


		prepareForInterpolate(zzX, degree, M, a, numThreads, mPrime);


		iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, numThreads, mPrime);

		u64 iterSends = 0;
		sendBuff.resize(inputs.size() * polyMaskBytes);
		for (int c = 0; c <= degree; c++) {
			BytesFromZZ(sendBuff.data() + iterSends, rep(Polynomial.rep[c]), polyMaskBytes);

			std::cout << "r SetCoeff rcvBlk= " << c << " - " << toBlock(sendBuff.data() + iterSends) << std::endl;

			iterSends += polyMaskBytes;

		}

		chls[0].asyncSend(std::move(sendBuff));



		//for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
		//	chls[0].asyncSend(std::move(sendBuffs[j]));


		gTimer.setTimePoint("r_Poly");

		//std::cout << localMasks.size() << " localMasks.size()\n";

		//#####################Receive Mask #####################

#if 0
		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

			for (u64 i = startIdx; i < endIdx - 1; i += stepSizeMaskSent)
			{

				std::vector<u8> recvBuffs;
				chl.recv(recvBuffs); //receive Hash


			/*block aaa;
			memcpy((u8*)&aaa, recvBuffs.data(), n1n2MaskBytes);
			std::cout << aaa << " recvBuffs[0] \n";*/


				block theirMasks, theirDiff;

				memcpy((u8*)&theirMasks, recvBuffs.data(), n1n2MaskBytes);
				memcpy((u8*)&theirDiff, recvBuffs.data() + n1n2MaskBytes, n1n2MaskBytes);


				/*auto theirMasks = recvBuffs.data();

				auto theirMasks = recvBuffs.data();
				auto theirDiff = recvBuffs.data()+ n1n2MaskBytes;*/

				bool isOverBound = true;
				u64 maskLength = hashMaskBytes;


				u64 iterTheirMask = 0;
				u64 iterTheirDiff = n1n2MaskBytes;
				u64 iterX = 0;

				while (iterTheirDiff < recvBuffs.size())
				{

					auto match = localMasks.find(*(u32*)&theirMasks);

					maskLength = isOverBound ? n1n2MaskBytes : hashMaskBytes;

					if (match != localMasks.end())//if match, check for whole bits
					{
						if (memcmp((u8*)&theirMasks, &match->second.first, maskLength) == 0) // check full mask
						{
							if (isMultiThreaded)
							{
								std::lock_guard<std::mutex> lock(mtx);
								mIntersection.push_back(match->second.second);
							}
							else
							{
								mIntersection.push_back(match->second.second);
							}

							//std::cout << "r mask: " << match->second.first << "\n";

						}
					}

					if (memcmp((u8*)&theirDiff, &ZeroBlock, hashMaskBytes) == 0)
					{
						isOverBound = true;
						iterTheirMask = iterTheirDiff + hashMaskBytes;
						memcpy((u8*)&theirMasks, recvBuffs.data() + iterTheirMask, n1n2MaskBytes);

						iterTheirDiff = iterTheirMask + n1n2MaskBytes;
						memcpy((u8*)&theirDiff, recvBuffs.data() + iterTheirDiff, n1n2MaskBytes);

					}
					else
					{
						block next = theirDiff + theirMasks;
						//std::cout << "r mask: " << iterX << "  " << next << " - " << theirMasks << " ===diff:===" << theirDiff << "\n";

						theirMasks = next;


						if (isOverBound)
							iterTheirMask += n1n2MaskBytes;
						else
							iterTheirMask += hashMaskBytes;

						iterTheirDiff += hashMaskBytes;
						memcpy((u8*)&theirDiff, recvBuffs.data() + iterTheirDiff, hashMaskBytes);
						isOverBound = false;
					}
					iterX++;
				}
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

	}

}
