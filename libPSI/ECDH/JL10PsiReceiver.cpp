#include "JL10PsiReceiver.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/Log.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include <unordered_map>
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{

    JL10PsiReceiver::JL10PsiReceiver()
    {
    }
    JL10PsiReceiver::~JL10PsiReceiver()
    {
    }
    
	void JL10PsiReceiver::startPsi(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed,span<block> inputs, span<Channel> chls)
    {
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

        mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
        mPrng.SetSeed(seed);
        mIntersection.clear();
		mSetSeedsSize = myInputSize; //compute g^ri without using subset-sum

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);

		//compute g^ri
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
		}
		std::cout << "g^ri done" << std::endl;


		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		std::vector<u8> mG_K; chls[0].recv(mG_K);

	//	u8* mG_K= new u8[g_k.sizeBytes()]; chls[0].recv(mG_K);
	//	u8* ttt = new u8[g_k.sizeBytes()];
	//	memcpy(ttt, mG_K.data(), g_k.sizeBytes());
		g_k.fromBytes(mG_K.data()); //receiving g^k

		std::cout << "r g^k= " << g_k << std::endl;

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes =  (n1n2MaskBits + 7) / 8;

	//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################

#if 1
		auto routine = [&](u64 t)
		{

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			EccPoint point(mCurve), yik(mCurve), xk(mCurve), gri(mCurve), xab(mCurve);

			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			yi.reserve(subsetInputSize);
			int idxYi = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(stepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;
			

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut)); //H(x)
					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					yi[idxYi] = (point + pG_seeds[i+k]); //H(x) *g^ri

#ifdef PRINT
					if (i+k==10)
						std::cout << "r yi[" << idxYi << "] " << yi[idxYi] << std::endl;
#endif
					yi[idxYi].toBytes(sendIter);
					sendIter += yi[idxYi++].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri

				
				//compute  (g^K)^ri
				std::vector<EccPoint> pgK_seeds;
				pgK_seeds.reserve(curStepSize);
				
				for (u64 k = 0; k < curStepSize; k++)
				{
					pgK_seeds.emplace_back(mCurve);
					pgK_seeds[k] = g_k * nSeeds[i + k];  //(g^k)^ri
													 //std::cout << mG_seeds[i] << std::endl;		
				}



				std::vector<u8> recvBuff(yi[0].sizeBytes() * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[yi[0].sizeBytes()];
				block temp;
#if 1				
				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi[0].sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yik.fromBytes(recvIter); recvIter += yik.sizeBytes();
					xk = yik - pgK_seeds[k]; //H(x)^k
					xk.toBytes(xk_byte);
					temp = toBlock(xk_byte); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "xk[" << i+k << "] " << xk << std::endl;
#endif // PRINT

					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i+k));
					}
					else
					{
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i + k));
					}
				}

#endif
			}

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
				
				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);
						
						/*if (i + k == 10)
							std::cout << "r msk: " << i+k << " - " << toBlock(msk) << std::endl;*/

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

		gTimer.setTimePoint("r psi done");
		std::cout << "r gkr done\n";

#endif

	}
	
	void JL10PsiReceiver::startPsi_subsetsum(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();
		
		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);


		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
		}
		std::cout << "g^seed done" << std::endl;


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
		}

		std::cout << "mG_pairs done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		u8* mG_K; chls[0].recv(mG_K);
		EccPoint g_k(mCurve); 	g_k.fromBytes(mG_K); //receiving g^k
		std::cout << "r g^k= " << g_k << std::endl;

		//compute seeds (g^k)^ri
		std::vector<EccPoint> pgK_seeds;
		pgK_seeds.reserve(mSetSeedsSize);

		//seeds //todo: paralel
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^seeds
		}

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

#if 1	//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################

		auto routine = [&](u64 t)
		{

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			EccPoint point(mCurve), yik(mCurve), xk(mCurve), gri(mCurve), xab(mCurve);

			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			yi.reserve(subsetInputSize);
			int idxYi = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(stepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut)); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					yi[idxYi] = (point + mG_pairs[i + k].second); //H(x) *g^ri

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << idxYi << "] " << yi[idxYi] << std::endl;
#endif
					yi[idxYi].toBytes(sendIter);
					sendIter += yi[idxYi++].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


				 //compute  (g^K)^ri from seeds
				std::vector<EccPoint> pgK_sum;
				pgK_sum.reserve(curStepSize);

				for (u64 k = 0; k < curStepSize; k++)
				{
					pgK_sum.emplace_back(mCurve);
					for (u64 j = 0; j < mG_pairs[i+k].first.size(); j++) //for all subset ri
						pgK_sum[k] = pgK_sum[k] + pgK_seeds[mG_pairs[i+k].first[j]]; //(g^k)^(subsum ri)
				}



				std::vector<u8> recvBuff(yi[0].sizeBytes() * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[yi[0].sizeBytes()];
				block temp;
#if 1				
				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi[0].sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yik.fromBytes(recvIter); recvIter += yik.sizeBytes();
					xk = yik - pgK_sum[k]; //H(x)^k
					xk.toBytes(xk_byte);
					temp = toBlock(xk_byte); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "xk[" << i + k << "] " << xk << std::endl;
#endif // PRINT

					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i + k));
					}
					else
					{
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i + k));
					}
				}

#endif
			}

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

						if (i + k == 10)
							std::cout << "r msk: " << i + k << " - " << toBlock(msk) << std::endl;

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

		gTimer.setTimePoint("r psi done");
		std::cout << "r gkr done\n";

#endif
#endif
	}
	bool JL10PsiReceiver::startPsi_subsetsum_malicious(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();

		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);


		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(p256k1, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
		}
		//std::cout << "g^seed done" << std::endl;


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
		}

		u8* onebit = new u8[1]; //return bit
		std::vector<block> hashX(inputs.size());

		//std::cout << "mG_pairs done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		u8* mG_K; chls[0].recv(mG_K);
		EccPoint g_k(mCurve); 	g_k.fromBytes(mG_K); //receiving g^k
		//std::cout << "r g^k= " << g_k << std::endl;

		//compute seeds (g^k)^ri
		std::vector<EccPoint> pgK_seeds;
		pgK_seeds.reserve(mSetSeedsSize);

		//seeds //todo: paralel
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^seeds
		}

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

#if 1	//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());
		std::vector<block> xik(inputs.size()); //H(x)^k 

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################

		auto routine = [&](u64 t)
		{
			SHA1 inputHasher;
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			EccPoint point(mCurve),  xk(mCurve), gri(mCurve), xab(mCurve);
			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			std::vector<EccPoint> yik;
			std::vector<EccPoint> yiv;
			
			EccNumber nR(mCurve), nC(mCurve);

			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{
				
				auto curStepSize = std::min(stepSize, inputEndIdx - i);
				yi.reserve(curStepSize);

				yik.reserve(curStepSize);
				yiv.reserve(curStepSize);
				for (u64 k = 0; k < curStepSize; k++)
				{
					yik.emplace_back(mCurve);
					yiv.emplace_back(mCurve);
				}

				std::vector<u8*> challeger_bytes(2); //(yi^k, yi^v)
				block* challenger = new block[numSuperBlocks]; //H(yi^k, yi^v)
				block temp_challenger = ZeroBlock;

				std::vector<u8> sendBuff(yik[0].sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					hashX[i + k] = toBlock(hashOut);
					point.randomize(hashX[i + k]); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					yi[k] = (point + mG_pairs[i + k].second); //H(x) *g^ri

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << k << "] " << yi[k] << std::endl;
#endif
					yi[k].toBytes(sendIter);
					sendIter += yi[k].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


													 //compute  (g^K)^ri from seeds
				std::vector<EccPoint> pgK_sum;
				pgK_sum.reserve(curStepSize);

				for (u64 k = 0; k < curStepSize; k++)
				{
					pgK_sum.emplace_back(mCurve);
					for (u64 j = 0; j < mG_pairs[i + k].first.size(); j++) //for all subset ri
						pgK_sum[k] = pgK_sum[k] + pgK_seeds[mG_pairs[i + k].first[j]]; //(g^k)^(subsum ri)
				}



				std::vector<u8> recvBuff(yi[0].sizeBytes() * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[yi[0].sizeBytes()];
				block temp;
#if 1				
				chl.recv(recvBuff); //recv yi^k||yi^v...||r

				if (recvBuff.size() != curStepSize * (2* yi[0].sizeBytes()+1))
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				nR.fromBytes(recvIter + curStepSize * (2 * yi[0].sizeBytes())); //last sizeBytes() bit
				//std::cout << "r nR= " << nR << " idx= "<< i<<"\n";

				for (u64 k = 0; k < curStepSize; ++k) //ZKDL verifier
				{
					yik[k].fromBytes(recvIter); recvIter += yik[k].sizeBytes();
					yiv[k].fromBytes(recvIter); recvIter += yik[k].sizeBytes();

					challeger_bytes[0] = new u8[yik[k].sizeBytes()]; //todo: optimize
					yik[k].toBytes(challeger_bytes[0]); //yi^k  

					challeger_bytes[1] = new u8[yiv[k].sizeBytes()];
					yiv[k].toBytes(challeger_bytes[1]); //yi^v

					for (int idxChall = 0; idxChall < challeger_bytes.size(); idxChall++)
						for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
						{
							auto minsize = std::min(sizeof(block), yiv[k].sizeBytes() - idxBlock * sizeof(block));
							memcpy((u8*)&temp_challenger, challeger_bytes[idxChall] + idxBlock * minsize, minsize);
							challenger[idxBlock] = challenger[idxBlock] + temp_challenger;
						}
				}


				std::vector<block> cipher_challenger(numSuperBlocks);
				mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data()); //compute H(sum (yi^k+ yi^v))
				EccNumber nC(mCurve);
				u8* nC_bytes = new u8[nC.sizeBytes()];
				memcpy(nC_bytes, cipher_challenger.data(), nC.sizeBytes());
				nC.fromBytes(nC_bytes); //c=H(sum (yi^k+ yi^v))
				//std::cout << "r nC= " << nC << " idx= " << i << "\n";

				for (u64 k = 0; k < curStepSize; ++k) //ZKDL verifier
				{
					auto yiRyiKC =yi[k]*nR+yik[k]*nC ; //yi^r*(yi^k)^c
					if (yiRyiKC != yiv[k])
					{
						std::cout << "Malicious EchdSender!" << std::endl;
						onebit[0] = 1;
						break;
					}
				}

				chl.asyncSend(onebit);
				if (onebit[0] == 1)
					return false;


				for (u64 k = 0; k < curStepSize; ++k)
				{
					xk = yik[k] - pgK_sum[k]; //H(x)^k
					u8* temp_yik = new u8[yik[k].sizeBytes()];
					
					xk.toBytes(temp_yik);
					block blkTemp = ZeroBlock;
					for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
					{
						auto minsize = std::min(sizeof(block), xk.sizeBytes() - idxBlock * sizeof(block));
						memcpy((u8*)&blkTemp, temp_yik + minsize, minsize);
						xik[i + k] = xik[i + k] + blkTemp;
					}

					xik[i + k] = xik[i + k] + hashX[i + k];
					inputHasher.Reset();
					//inputHasher.Update(hashX[i + k]);
					inputHasher.Update(xik[i + k]);
					inputHasher.Final(hashOut);
					temp = toBlock(hashOut); //H(x)^k

#ifdef PRINT
					if (i + k == 10 || i + k == 20)
						std::cout << "xk[" << i + k << "] " << xk << std::endl;
#endif // PRINT

					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i + k));
					}
					else
					{
						localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i + k));
					}
				}

#endif
			}

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


#if 1
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
				//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;

				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

			/*			if (i + k == 10)
							std::cout << "r msk: " << i + k << " - " << toBlock(msk) << std::endl;*/

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

		gTimer.setTimePoint("r psi done");
		std::cout << "r gkr done\n";

#endif
#endif
		return true;
	}

}