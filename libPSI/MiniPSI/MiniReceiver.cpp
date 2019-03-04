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
		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);

		std::cout << "r mSetSeedsSize= " << mMyInputSize <<" - " <<mSetSeedsSize  << " - "<< mChoseSeedsSize << "\n";

		//seed for subset-sum exp
		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();

		//std::cout << "r mFieldSize= " << mFieldSize << "\n";


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		//std::cout << mG << std::endl;
		mPolyBytes = mG.sizeBytes();
		//std::cout << "r mPolyBytes= " << mPolyBytes << "\n";


		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;
		
		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		mSeeds.resize(mSetSeedsSize);
		

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(prng);

			mSeeds[i] = new u8[nSeeds[i].sizeBytes()];
			nSeeds[i].toBytes(mSeeds[i]); //store mSeeds byte for computing (g^k)^(subsum ri) later

			//      pG_seeds[i] = g ^ mSeeds[i]
			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
			//std::cout << mG_seeds[i] << std::endl;
		}
		std::cout <<"pG_seeds done" << std::endl;
		gTimer.setTimePoint("r off pG_seeds done");

		//generate all pairs from seeds
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

			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);
			mG_pairs.push_back(std::make_pair(subIdx, temp));


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
		gTimer.setTimePoint("r off mG_pairs done");

	
	}

	void MiniReceiver::outputBigPoly(span<block> inputs, span<Channel> chls)
	{

		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;

		u8* mG_K;
		chls[0].recv(mG_K);
		EccPoint g_k(mCurve);
		g_k.fromBytes(mG_K);

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

			ZZFromBytes(zz, mG_pairs[idx].second, mPolyBytes);
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
		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pgK_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pgK_seeds.reserve(mSetSeedsSize);
		

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			nSeeds.emplace_back(mCurve);
			nSeeds[i].fromBytes(mSeeds[i]); //restore mSeeds byte for computing (g^k)^(subsum ri) later
			
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

			localMasks.emplace(*(u64*)&gk_sum_byte, std::pair<block, u64>(toBlock(gk_sum_byte), i));

		}
		std::cout << "r gkr done\n";

		gTimer.setTimePoint("r_gkr");


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
							// check 64 first bits
							auto match = localMasks.find(msk);

							//if match, check for whole bits
							if (match != localMasks.end())
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

							for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
							{
								if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
								{
									mIntersection.push_back(match->second.second);
								}
								theirMasks += n1n2MaskBytes;
							}
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
		std::cout << "r gkr done\n";

	}

}
