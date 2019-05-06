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
	void MiniReceiver::outputBigPoly(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(prng.get<block>());
		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		//seed for subset-sum exp
		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(k283, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();
		//std::cout << "r mFieldSize= " << mFieldSize << "\n";


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		//std::cout << pG << std::endl;
		mPolyBytes = mG.sizeBytes();
		//std::cout << "r mPolyBytes= " << mPolyBytes << "\n";


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

			//      pG_seeds[i] = g ^ mSeeds[i]
			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
			//std::cout << mG_seeds[i] << std::endl;
		}
		std::cout << "pG_seeds done" << std::endl;
		gTimer.setTimePoint("r off pG_seeds done");

		//generate all pairs from seeds
		std::vector<std::pair<std::vector<u64>, EccPoint>> mG_pairs; //{index of sub ri}, g^(subsum ri)
		mG_pairs.reserve(myInputSize);

		std::vector<u64> indices(mSetSeedsSize);

		for (u64 i = 0; i < myInputSize; i++)
		{
			std::iota(indices.begin(), indices.end(), 0);
			std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

			EccPoint g_sum(mCurve);

			for (u64 j = 0; j < mChoseSeedsSize; j++)
				g_sum = g_sum + pG_seeds[indices[j]]; //g^sum

			std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
			mG_pairs.push_back(std::make_pair(subIdx, g_sum));


			//std::cout << "r sum= " << mG_pairs[i].first[0]
			//	<< " - " << g_sum.sizeBytes()
			//	<< " - " << toBlock(mG_pairs[i].second)
			//	<< " - " << toBlock(mG_pairs[i].second + sizeof(block))
			//	<< " - " << toBlock(mG_pairs[i].second + g_sum.sizeBytes() - 2 * sizeof(block)) << std::endl;

			//EccPoint g_sumTest(mCurve);
			//g_sumTest.fromBytes(mG_pairs[i].second);
			//std::cout << g_sum << "\n";
			//std::cout << g_sumTest << "\n";

			//u8* tempBlk = new u8[g_sum.sizeBytes()];
			//tempBlk = mG_pairs[i].second;
			//g_sumTest.fromBytes(tempBlk);
			//std::cout << g_sumTest << "\n";

		}

		std::cout << "mG_pairs done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		std::vector<u8> mG_K; chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k

		//std::cout << "r g^k= " << g_k << std::endl;


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

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
			u8* yri = new u8[mPolyBytes];

			u8* temp = new u8[mG_pairs[idx].second.sizeBytes()];
			mG_pairs[idx].second.toBytes(temp);
			ZZFromBytes(zz, temp, mPolyBytes);
			//std::cout << "r P(x)= " << idx << " - " << toBlock(mG_pairs[idx].second) << std::endl;
			zzY[idx] = to_ZZ_p(zz);

			//BytesFromZZ(yri, rep(zzY[idx]), mPolyBytes);
			//std::cout << "rr P(x)= " << idx << " - " << toBlock(yri) << std::endl;

			//EccPoint g_sumTest(mCurve);
			//g_sumTest.fromBytes(mG_pairs[idx].second);
			//std::cout << sizeof(mG_pairs[idx].second) << "\n";
			//std::cout << g_sumTest << "\n";

			////memcpy(yri, mG_pairs[idx].second, mFieldSize);
			//g_sumTest.fromBytes(yri);
			//std::cout << sizeof(yri) << "\n";
			//std::cout << g_sumTest << "\n";

		}


		prepareForInterpolate(zzX, degree, M, a, numThreads, mPrime);


		iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, numThreads, mPrime);

		u64 iterSends = 0;
		sendBuff.resize(inputs.size() * mPolyBytes);
		for (int c = 0; c <= degree; c++) {
			BytesFromZZ(sendBuff.data() + iterSends, rep(Polynomial.rep[c]), mPolyBytes);

			//std::cout << "r SetCoeff rcvBlk= " << c << " - " << toBlock(sendBuff.data() + iterSends) << std::endl;

			iterSends += mPolyBytes;

		}

		chls[0].asyncSend(std::move(sendBuff));

		gTimer.setTimePoint("r_Poly");
		std::cout << "r Poly done\n";




		//#####################(g^K)^ (subsum ri) #####################

		//compute seeds (g^K)^ri
		std::vector<EccPoint> pgK_seeds;
		pgK_seeds.reserve(mSetSeedsSize);


		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^ri
			//std::cout << mG_seeds[i] << std::endl;		
		}

		//generate all pairs from seeds
			std::unordered_map<u64, std::pair<block, u64>> localMasks;
			localMasks.reserve(inputs.size());


			for (u64 i = 0; i < inputs.size(); i++)
			{
				EccPoint gk_sum(mCurve);

				for (u64 j = 0; j < mG_pairs[i].first.size(); j++) //for all subset ri
					gk_sum = gk_sum + pgK_seeds[mG_pairs[i].first[j]]; //(g^k)^(subsum ri)


				u8* gk_sum_byte = new u8[gk_sum.sizeBytes()];
				gk_sum.toBytes(gk_sum_byte);

				//std::cout << "r gk_sum: " << i << " - " << gk_sum << std::endl;
				//std::cout << "r toBlock(gk_sum_byte): " << i << " - " << toBlock(gk_sum_byte) << std::endl;
				block temp = toBlock(gk_sum_byte);
				localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));

			}
			std::cout << "r gkr done\n";

			gTimer.setTimePoint("r_gkr done");


			//#####################Receive Mask #####################


			auto receiveMask = [&](u64 t)
			{
				auto& chl = chls[t]; //parallel along with inputs
				u64 startIdx = mTheirInputSize * t / numThreads;
				u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
				u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

				//std::cout << startIdx << " vs  " << endIdx << " rrrendIdx \n";

				for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
				{
					auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
					std::vector<u8> recvBuffs;

					chl.recv(recvBuffs); //receive Hash


					auto theirMasks = recvBuffs.data();
					//std::cout << "r toBlock(recvBuffs): " << i << " - " << toBlock(theirMasks) << std::endl;


					if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							auto& msk = *(u64*)(theirMasks);

							//std::cout << "r msk: " << i+k << " - " << toBlock(msk) << std::endl;

							// check 64 first bits
							auto match = localMasks.find(msk);

							//if match, check for whole bits
							if (match != localMasks.end())
							{
								//std::cout << "match != localMasks.end()" << std::endl;

								if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
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
							theirMasks += n1n2MaskBytes;
						}
					}
					else //for small set, do O(n^2) check
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{
							//std::cout << "r theirMasks: " << i + k << " - " << toBlock(theirMasks) << std::endl;
							for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
							{
								//std::cout << "r myMasks: " << i + k << " - " << match->second.first << std::endl;

								if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
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
							theirMasks += n1n2MaskBytes;

						}
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

			gTimer.setTimePoint("r on masks done");
			std::cout << "psi done\n";

		}

	void MiniReceiver::outputHashing(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
		{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();
			//####################### offline #########################
#pragma region Offline
			gTimer.setTimePoint("r offline start ");

			mPsiSecParam = psiSecParam;
			mMyInputSize = myInputSize;
			mTheirInputSize = theirInputSize;
			mPrng.SetSeed(prng.get<block>());
			getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);

			std::cout << "MiniReceiver::outputHashing r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

			//seed for subset-sum exp
			mCurveSeed = mPrng.get<block>();
			EllipticCurve mCurve(k283, OneBlock);
			//mCurve.getMiracl().IOBASE = 10;
			mFieldSize = mCurve.bitCount();
			//std::cout << "r mFieldSize= " << mFieldSize << "\n";


			EccPoint mG(mCurve);
			mG = mCurve.getGenerator();
			//std::cout << pG << std::endl;
			mPolyBytes = mG.sizeBytes();
			//std::cout << "r mPolyBytes= " << mPolyBytes << "\n";


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

				//      pG_seeds[i] = g ^ mSeeds[i]
				pG_seeds.emplace_back(mCurve);
				pG_seeds[i] = mG * nSeeds[i];  //g^ri
											   //std::cout << mG_seeds[i] << std::endl;
			}
			std::cout << "pG_seeds done" << std::endl;
			gTimer.setTimePoint("r off pG_seeds done");

			//generate all pairs from seeds
			std::vector<std::pair<std::vector<u64>, EccPoint>> mG_pairs; //{index of sub ri}, g^(subsum ri)
			mG_pairs.reserve(myInputSize);

			std::vector<u64> indices(mSetSeedsSize);

			for (u64 i = 0; i < myInputSize; i++)
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

				EccPoint g_sum(mCurve);

				for (u64 j = 0; j < mChoseSeedsSize; j++)
					g_sum = g_sum + pG_seeds[indices[j]]; //g^sum

				std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
				mG_pairs.push_back(std::make_pair(subIdx, g_sum));


				//std::cout << "r sum= " << mG_pairs[i].first[0]
				//	<< " - " << g_sum.sizeBytes()
				//	<< " - " << toBlock(mG_pairs[i].second)
				//	<< " - " << toBlock(mG_pairs[i].second + sizeof(block))
				//	<< " - " << toBlock(mG_pairs[i].second + g_sum.sizeBytes() - 2 * sizeof(block)) << std::endl;

				//EccPoint g_sumTest(mCurve);
				//g_sumTest.fromBytes(mG_pairs[i].second);
				//std::cout << g_sum << "\n";
				//std::cout << g_sumTest << "\n";

				//u8* tempBlk = new u8[g_sum.sizeBytes()];
				//tempBlk = mG_pairs[i].second;
				//g_sumTest.fromBytes(tempBlk);
				//std::cout << g_sumTest << "\n";

			}
			mBalance.init(mMyInputSize, recvMaxBinSize, recvNumDummies);

			u64 numThreads(chls.size());
			const bool isMultiThreaded = numThreads > 1;
			std::vector<std::thread> thrds(numThreads);
			std::mutex mtx;

			u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
			u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;
			EccPoint g_k(mCurve);
			std::vector<EccPoint> pgK_seeds;
			pgK_seeds.reserve(mSetSeedsSize);
			for (u64 i = 0; i < mSetSeedsSize; i++)
				pgK_seeds.emplace_back(mCurve);

			std::array<std::unordered_map<u64, std::pair<block, u64>>, 2> localMasks; //for hash 0 and 1
			localMasks[0].reserve(inputs.size());//for hash 0
			localMasks[1].reserve(inputs.size());//for hash 1

			std::cout << "mG_pairs done" << std::endl;

#pragma endregion 

			//####################### online #########################
			gTimer.setTimePoint("r online start ");
			mBalance.insertItems(inputs);//Balaced Allocation=====================
			gTimer.setTimePoint("r_binning");
			std::cout << "r_binning done" << std::endl;

			
			std::vector<u8> mG_K; chls[0].recv(mG_K);
			g_k.fromBytes(mG_K.data()); //receiving g^k
			//std::cout << "r g^k= " << g_k << std::endl;

			//#####################(g^K)^ (subsum ri) #####################

			//computing (g^k)^seeds
			for (u64 i = 0; i < mSetSeedsSize; i++)
			{
				pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^ri
												 //std::cout << mG_seeds[i] << std::endl;		
			}


			//=====================Poly=====================
			auto routine = [&](u64 t)
			{
				auto& chl = chls[t];
				u64 binStartIdx = mBalance.mNumBins * t / numThreads;
				u64 tempBinEndIdx = (mBalance.mNumBins * (t + 1) / numThreads);
				u64 binEndIdx = std::min(tempBinEndIdx, mBalance.mNumBins);

				polyNTL poly;
				poly.NtlPolyInit(mPolyBytes);


				for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
				{
					auto curStepSize = std::min(stepSize, binEndIdx - i);
					std::vector<u8> sendBuff(curStepSize*mBalance.mMaxBinSize*mPolyBytes);

					u64 iterSend = 0;
					for (u64 k = 0; k < curStepSize; ++k)
					{
						u64 bIdx = i + k;
						//std::cout << "r bIdx= " << bIdx << std::endl;

						std::vector<std::array<block, numSuperBlocks>> listGRi(mBalance.mBins[bIdx].cnt);

						//get list of g^ri for xi in bin
						for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
						{
							for (u64 j = 0; j < numSuperBlocks; ++j)
								listGRi[idx][j] = ZeroBlock; //init

							u8* temp = new u8[mPolyBytes];
							mG_pairs[mBalance.mBins[bIdx].idxs[idx]].second.toBytes(temp);
							memcpy((u8*)&listGRi[idx], temp, mPolyBytes);
						}
													

						//=====================Pack=====================
						u64 degree = mBalance.mMaxBinSize - 1;
						std::vector<std::array<block, numSuperBlocks>> coeffs;

						poly.getSuperBlksCoefficients(degree, mBalance.mBins[bIdx].blks, listGRi, coeffs);
						for (int c = 0; c < coeffs.size(); c++) {

							//for (int iii = 0; iii < numSuperBlocks; iii++)
							//	std::cout << coeffs[c][iii] << "  r coeff\n bin#" << bIdx << "\n";

							memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], mPolyBytes);
							iterSend += mPolyBytes;
						}

						//std::vector<std::array<block, numSuperBlocks>> YRi_bytes(mBalance.mBins[bIdx].blks.size());
						//poly.evalSuperPolynomial(coeffs, mBalance.mBins[bIdx].blks, YRi_bytes); //P(x)


						//for (u64 idx = 0; idx < YRi_bytes.size(); ++idx)
						//{
						//	std::cout << mBalance.mBins[bIdx].blks[idx] << " r x bin#" << bIdx << "\n";
						//	for (int iii = 0; iii < numSuperBlocks; iii++)
						//		std::cout << listGRi[idx][iii] << "  r P(x)\n";

						//	for (int iii = 0; iii < numSuperBlocks; iii++)
						//		std::cout << YRi_bytes[idx][iii] << "  r evalP(x) bin#" << bIdx << "\n";

						//	EccPoint point_ri(mCurve);
						//	u8* yri = new u8[point_ri.sizeBytes()];
						//	memcpy(yri, (u8*)&YRi_bytes[idx], mPolyBytes);
						//	point_ri.fromBytes(yri);
						//	std::cout << "r point_ri= " << point_ri << std::endl;
						//	std::cout << "\n";
						//}



					}
					//std::cout << sendBuff.size() << "  r sendBuff.size()\n";
					chl.asyncSend(std::move(sendBuff)); //send poly P(x)=g^ri


					//compute (g^k)^sum ri
					for (u64 k = 0; k < curStepSize; ++k)
					{
						u64 bIdx = i + k;
					
						for (u64 idx = 0; idx < mBalance.mBins[bIdx].cnt; ++idx)
						{
							EccPoint gk_sum(mCurve);
							int idxItem = mBalance.mBins[bIdx].idxs[idx];
							int idxItemHash = mBalance.mBins[bIdx].hashIdxs[idx];

							for (u64 j = 0; j < mG_pairs[idxItem].first.size(); j++) //for all subset ri
								gk_sum = gk_sum + pgK_seeds[mG_pairs[idxItem].first[j]]; //(g^k)^(subsum ri)

							u8* gk_sum_byte = new u8[gk_sum.sizeBytes()];
							gk_sum.toBytes(gk_sum_byte);

							//std::cout << "r gk_sum: " << i << " - " << gk_sum << std::endl;
							//std::cout << "r toBlock(gk_sum_byte): " << i << " - " << toBlock(gk_sum_byte) << std::endl;
							block temp = toBlock(gk_sum_byte);
							localMasks[idxItemHash].emplace(*(u64*)&temp, std::pair<block, u64>(temp, idxItem));
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

			gTimer.setTimePoint("send poly + g^ri^k done");

			std::cout << " r send poly + g^ri^k done\n";


			//#####################Receive Mask #####################
#if 1
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
#if 1
						if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
						{
							for (u64 k = 0; k < curStepSize; ++k)
							{

								auto& msk = *(u64*)(theirMasks);
								// check 64 first bits
								auto match = localMasks[hIdx].find(msk);

								//if match, check for whole bits
								if (match != localMasks[hIdx].end())
								{
									if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
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
								theirMasks += n1n2MaskBytes;
							}
						}
						else //for small set, do O(n^2) check
						{
							for (u64 k = 0; k < curStepSize; ++k)
							{

								for (auto match = localMasks[hIdx].begin(); match != localMasks[hIdx].end(); ++match)
								{
									if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
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
								theirMasks += n1n2MaskBytes;

							}
						}
					
#endif				
					
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
			gTimer.setTimePoint("r on masks done");
			std::cout << "r gkr done\n";

		}


	bool MiniReceiver::outputBigPoly_malicious(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
		{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();
			//####################### offline #########################
			gTimer.setTimePoint("r offline start ");

			mPsiSecParam = psiSecParam;
			mMyInputSize = myInputSize;
			mTheirInputSize = theirInputSize;
			mPrng.SetSeed(prng.get<block>());
			getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);

			std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

			//seed for subset-sum exp
			mCurveSeed = mPrng.get<block>();
			EllipticCurve mCurve(k283, OneBlock);
			//mCurve.getMiracl().IOBASE = 10;
			mFieldSize = mCurve.bitCount();
			//std::cout << "r mFieldSize= " << mFieldSize << "\n";


			EccPoint pG(mCurve);
			pG = mCurve.getGenerator();
			//std::cout << pG << std::endl;
			mPolyBytes = pG.sizeBytes();
			//std::cout << "r mPolyBytes= " << mPolyBytes << "\n";


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

				//      pG_seeds[i] = g ^ mSeeds[i]
				pG_seeds.emplace_back(mCurve);
				pG_seeds[i] = pG * nSeeds[i];  //g^ri
											   //std::cout << mG_seeds[i] << std::endl;
			}
			std::cout << "pG_seeds done" << std::endl;
			gTimer.setTimePoint("r off pG_seeds done");

			//generate all pairs from seeds
			std::vector<std::pair<std::vector<u64>, EccPoint>> mG_pairs; //{index of sub ri}, g^(subsum ri)
			mG_pairs.reserve(myInputSize);

			std::vector<u64> indices(mSetSeedsSize);

			for (u64 i = 0; i < myInputSize; i++)
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

				EccPoint g_sum(mCurve);

				for (u64 j = 0; j < mChoseSeedsSize; j++)
					g_sum = g_sum + pG_seeds[indices[j]]; //g^sum

				std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
				mG_pairs.push_back(std::make_pair(subIdx, g_sum));


				//std::cout << "r sum= " << mG_pairs[i].first[0]
				//	<< " - " << g_sum.sizeBytes()
				//	<< " - " << toBlock(mG_pairs[i].second)
				//	<< " - " << toBlock(mG_pairs[i].second + sizeof(block))
				//	<< " - " << toBlock(mG_pairs[i].second + g_sum.sizeBytes() - 2 * sizeof(block)) << std::endl;

				//EccPoint g_sumTest(mCurve);
				//g_sumTest.fromBytes(mG_pairs[i].second);
				//std::cout << g_sum << "\n";
				//std::cout << g_sumTest << "\n";

				//u8* tempBlk = new u8[g_sum.sizeBytes()];
				//tempBlk = mG_pairs[i].second;
				//g_sumTest.fromBytes(tempBlk);
				//std::cout << g_sumTest << "\n";

			}

			std::cout << "mG_pairs done" << std::endl;

			//####################### online #########################
			u8* onebit = new u8[1];
			gTimer.setTimePoint("r online start ");
			
			u8* mG_K; u8* g_v_bytes; u8* nR_bytes; u8* nC_bytes;
			chls[0].recv(mG_K);
			chls[0].recv(g_v_bytes);
			chls[0].recv(nR_bytes);
			//chls[0].recv(nC_bytes); //for simpler, verifier recv c from prover
			EccPoint g_k(mCurve), g_v(mCurve);
			EccNumber nR(mCurve), nC(mCurve);

			g_k.fromBytes(mG_K);
			g_v.fromBytes(g_v_bytes);
			nR.fromBytes(nR_bytes);
			//nC.fromBytes(nC_bytes);

			//std::cout << "r g_k=" << g_k << "\n";
			//std::cout << "r g_v=" << g_v << "\n";
			//std::cout << "r nR=" << nR << "\n";


			std::vector<u8*> challeger_bytes(3);

			challeger_bytes[0] = new u8[pG.sizeBytes()];
			pG.toBytes(challeger_bytes[0]); //g

			challeger_bytes[1] = new u8[g_k.sizeBytes()];
			g_k.toBytes(challeger_bytes[1]); //g^k

			challeger_bytes[2] = new u8[g_v.sizeBytes()];
			g_v.toBytes(challeger_bytes[2]); //g^v

			block* challenger = new block[numSuperBlocks]; //g + g^k+g^v
			//block* cipher_challenger = new block[numSuperBlocks];
			std::vector<block> cipher_challenger(numSuperBlocks);// = new block[numSuperBlocks];
			for (int i = 0; i < numSuperBlocks; i++)
				challenger[i] = ZeroBlock;

			block temp_challenger = ZeroBlock;
			for (int i = 0; i < numSuperBlocks; i++)
			{
				auto minsize = min(sizeof(block), g_v.sizeBytes() - i * sizeof(block));
				memcpy((u8*)&temp_challenger, challeger_bytes[i] + i * minsize, minsize);
				challenger[i] = challenger[i] + temp_challenger;
			}

			mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data()); //c=H(g,g^k, g^v)

			nC_bytes = new u8[nC.sizeBytes()];
			memcpy(nC_bytes, cipher_challenger.data(), nC.sizeBytes());
			nC.fromBytes(nC_bytes);


			/*std::cout << "r nC_bytes[0]=" << toBlock(nC_bytes) << "\n";
			std::cout << "r nC_bytes[1]=" << toBlock(nC_bytes + sizeof(block)) << "\n";
			std::cout << "r nC_bytes[2]=" << toBlock(nC_bytes + 2 * sizeof(block)) << "\n";

			std::cout << "r nC_bytes[0]=" << toBlock(nC_bytes2) << "\n";
			std::cout << "r nC_bytes[1]=" << toBlock(nC_bytes2 + sizeof(block)) << "\n";
			std::cout << "r nC_bytes[2]=" << toBlock(nC_bytes2+ 2 * sizeof(block)) << "\n";*/


			//=============compute g^r*(g^k)^c
			auto gryc = pG*nR + g_k*nC; //g^r*(g^k)^c
			//std::cout << "r gryc=" << gryc << "\n";
			

			if (gryc != g_v)
			{
				std::cout << "Malicious Sender!" << std::endl;
				onebit[0] = 1;
			}

			chls[0].asyncSend(onebit);
			if (onebit[0] == 1)
				return false;


			//std::cout << "r g^k= " << g_k << std::endl;


			u64 numThreads(chls.size());
			const bool isMultiThreaded = numThreads > 1;
			std::vector<std::thread> thrds(numThreads);
			std::mutex mtx;

			u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
			u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

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
				u8* yri = new u8[mPolyBytes];

				u8* temp = new u8[mG_pairs[idx].second.sizeBytes()];
				mG_pairs[idx].second.toBytes(temp);
				ZZFromBytes(zz, temp, mPolyBytes);
				//std::cout << "r P(x)= " << idx << " - " << toBlock(mG_pairs[idx].second) << std::endl;
				zzY[idx] = to_ZZ_p(zz);

				//BytesFromZZ(yri, rep(zzY[idx]), mPolyBytes);
				//std::cout << "rr P(x)= " << idx << " - " << toBlock(yri) << std::endl;

				//EccPoint g_sumTest(mCurve);
				//g_sumTest.fromBytes(mG_pairs[idx].second);
				//std::cout << sizeof(mG_pairs[idx].second) << "\n";
				//std::cout << g_sumTest << "\n";

				////memcpy(yri, mG_pairs[idx].second, mFieldSize);
				//g_sumTest.fromBytes(yri);
				//std::cout << sizeof(yri) << "\n";
				//std::cout << g_sumTest << "\n";

			}


			prepareForInterpolate(zzX, degree, M, a, numThreads, mPrime);


			iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, numThreads, mPrime);

			u64 iterSends = 0;
			sendBuff.resize(inputs.size() * mPolyBytes);
			for (int c = 0; c <= degree; c++) {
				BytesFromZZ(sendBuff.data() + iterSends, rep(Polynomial.rep[c]), mPolyBytes);

				//std::cout << "r SetCoeff rcvBlk= " << c << " - " << toBlock(sendBuff.data() + iterSends) << std::endl;

				iterSends += mPolyBytes;

			}

			chls[0].asyncSend(std::move(sendBuff));

			gTimer.setTimePoint("r Poly done");
			//std::cout << "r Poly done\n";




			//#####################(g^K)^ (subsum ri) #####################

			//compute seeds (g^K)^ri
			std::vector<EccPoint> pgK_seeds;
			pgK_seeds.reserve(mSetSeedsSize);


			//seeds
			for (u64 i = 0; i < mSetSeedsSize; i++)
			{
				pgK_seeds.emplace_back(mCurve);
				pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^ri
												 //std::cout << mG_seeds[i] << std::endl;		
			}

			//generate all pairs from seeds
			std::unordered_map<u64, std::pair<block, u64>> localMasks;
			localMasks.reserve(inputs.size());


			for (u64 i = 0; i < inputs.size(); i++)
			{
				EccPoint gk_sum(mCurve);

				for (u64 j = 0; j < mG_pairs[i].first.size(); j++) //for all subset ri
					gk_sum = gk_sum + pgK_seeds[mG_pairs[i].first[j]]; //(g^k)^(subsum ri)


				u8* gk_sum_byte = new u8[gk_sum.sizeBytes()];
				gk_sum.toBytes(gk_sum_byte);

				//std::cout << "r gk_sum: " << i << " - " << gk_sum << std::endl;
				//std::cout << "r toBlock(gk_sum_byte): " << i << " - " << toBlock(gk_sum_byte) << std::endl;
				block temp = toBlock(gk_sum_byte);
				localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));

			}
			//std::cout << "r gkr done\n";

			gTimer.setTimePoint("r gkr done");


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

					chl.recv(recvBuffs); //receive Hash


					auto theirMasks = recvBuffs.data();
					//std::cout << "r toBlock(recvBuffs): " << i << " - " << toBlock(theirMasks) << std::endl;


					if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							auto& msk = *(u64*)(theirMasks);

							//std::cout << "r msk: " << i+k << " - " << toBlock(msk) << std::endl;

							// check 64 first bits
							auto match = localMasks.find(msk);

							//if match, check for whole bits
							if (match != localMasks.end())
							{
								//std::cout << "match != localMasks.end()" << std::endl;

								if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
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
							theirMasks += n1n2MaskBytes;
						}
					}
					else //for small set, do O(n^2) check
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{
							//std::cout << "r theirMasks: " << i + k << " - " << toBlock(theirMasks) << std::endl;
							for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
							{
								//std::cout << "r myMasks: " << i + k << " - " << match->second.first << std::endl;

								if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
									mIntersection.push_back(match->second.second);
							}
							theirMasks += n1n2MaskBytes;

						}
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

			gTimer.setTimePoint("r on masks done");
			std::cout << "psi done\n";
			return true;
		}

		
	}
