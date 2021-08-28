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
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		
		//stepSize = myInputSize;
		//####################### offline #########################
		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

        mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
        mPrng.SetSeed(seed);
        mIntersection.clear();
		mSetSeedsSize = myInputSize; //compute g^ri without using subset-sum
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;


		std::cout << "startPsi r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		mCurveByteSize = mG.sizeBytes();
		tempToFromByteCurve = new u8[mCurveByteSize];

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		mSeeds_Byte.resize(mSetSeedsSize);
		pG_seeds_Byte.resize(mSetSeedsSize);

		//compute g^ri
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);
			mSeeds_Byte[i] = new u8[mCurveByteSize];
			nSeeds[i].toBytes(mSeeds_Byte[i]);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri

			pG_seeds_Byte[i] = new u8[mCurveByteSize];
			pG_seeds[i].toBytes(pG_seeds_Byte[i]);
		}
		std::cout << "g^ri done" << std::endl;

	

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k

		//std::cout << "r g^k= " << g_k << std::endl;

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


		
		auto routine = [&](u64 t)
		{
			//EccPoint g_k_thread(mCurve, g_k);

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));


			EllipticCurve mCurve(myEccpParams, OneBlock);
			std::vector<EccPoint> pgK_seeds;

			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve), g_k(mCurve), gri(mCurve), pG_seed(mCurve);
			EccNumber nSeed(mCurve);
			g_k.fromBytes(mG_K.data()); //receiving g^k

			//std::cout << "r g^k= " << g_k << std::endl;

			pgK_seeds.reserve(subsetInputSize);
			for (u64 k = 0; k < subsetInputSize; k++)
				pgK_seeds.emplace_back(mCurve);

			int idx_pgK = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//gTimer.setTimePoint("r online g^k^ri start ");
				//compute  (g^K)^ri

				for (u64 k = 0; k < curStepSize; k++)
				{
					nSeed.fromBytes(mSeeds_Byte[i + k]);
					pgK_seeds[idx_pgK++] =  g_k * nSeed;
														 //std::cout << mG_seeds[i] << std::endl;		
				}
				//gTimer.setTimePoint("r online g^k^ri done ");

#if 1

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);

					point.randomize(seed); //H(x)
					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					//yi.emplace_back(mCurve);
					pG_seed.fromBytes(pG_seeds_Byte[i + k]);
					yi = (point + pG_seed); //H(x) *g^ri

					

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << i + k << "] " << yi << std::endl;
#endif
					yi.toBytes(sendIter);
					sendIter += yi.sizeBytes();
				}
				//gTimer.setTimePoint("r online H(x) g^k done ");

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri
#endif
			}
#if 1
			idx_pgK = 0;
			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);
				std::vector<u8> recvBuff(yi.sizeBytes() * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[yi.sizeBytes()];
				block temp;
				
				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * yi.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				//gTimer.setTimePoint("r online H(x)^k start");

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yik.fromBytes(recvIter); recvIter += yik.sizeBytes();
					xk = yik - pgK_seeds[idx_pgK++]; //H(x)^k
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
				//gTimer.setTimePoint("r online H(x)^k done");



			}
#endif

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 theirStartIdx = mTheirInputSize * t / numThreads;
			u64 tempTheirEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 theirEndIdx = std::min(tempTheirEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = theirStartIdx; i < tempTheirEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, theirEndIdx - i);
				
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
		//std::cout << "r gkr done\n";

#endif

	}
	
	void JL10PsiReceiver::startPsi_subsetsum(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		//####################### offline #########################

		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;

		mPrng.SetSeed(seed);
		mIntersection.clear();
		
		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);


		std::cout << "startPsi_subsetsum r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();
		

		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		mCurveByteSize = mG.sizeBytes();
		tempToFromByteCurve = new u8[mCurveByteSize];

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		mSeeds_Byte.resize(mSetSeedsSize);
		pG_seeds_Byte.resize(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);
			mSeeds_Byte[i] = new u8[mCurveByteSize];
			nSeeds[i].toBytes(mSeeds_Byte[i]);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
			pG_seeds_Byte[i] = new u8[mCurveByteSize];
			pG_seeds[i].toBytes(pG_seeds_Byte[i]);
		}
		//std::cout << "g^seed done" << std::endl;

		gTimer.setTimePoint("r offline g^seed done ");

		std::vector<std::pair<std::vector<u64>, u8*>> mG_pairs; //{index of sub ri}, g^(subsum ri)
		mG_pairs.reserve(myInputSize);

		std::vector<u64> indices(mSetSeedsSize);
		mIntCi.resize(mMyInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{
			if (mMyInputSize < (1 << 9))
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
			}
			else
			{
				indices.resize(0);
				while (indices.size() < mChoseSeedsSize)
				{
					int rnd = rand() % mSetSeedsSize;
					if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
						indices.push_back(rnd);
				}
			}

			EccPoint g_sum(mCurve);


			if (mBoundCoeffs == 2)
			{
				for (u64 j = 0; j < mChoseSeedsSize; j++)
					g_sum = g_sum + pG_seeds[indices[j]]; //g^sum //h=2   ci=1
			}
			else
			{
				mIntCi[i].resize(mChoseSeedsSize);

				for (u64 j = 0; j < mChoseSeedsSize; j++)
				{
					mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);
					EccNumber ci(mCurve, mIntCi[i][j]);
					g_sum = g_sum + pG_seeds[indices[j]] * ci; //g^ci*sum
				}
			}

			std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);
			mG_pairs.push_back(std::make_pair(subIdx, temp));
		}

		//std::cout << "mG_pairs_subsetsum done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		std::vector<u8> mG_K; chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k
		//std::cout << "r g^k= " << g_k << std::endl;


		//compute seeds (g^k)^ri
		std::vector<EccPoint> pgK_seeds;
		std::vector<u8*> mgK_seeds_bytes;
		pgK_seeds.reserve(mSetSeedsSize);
		mgK_seeds_bytes.resize(mSetSeedsSize);

		//seeds //todo: paralel
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^seeds

			mgK_seeds_bytes[i] = new u8[mCurveByteSize];
			pgK_seeds[i].toBytes(mgK_seeds_bytes[i]);
			
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

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));
			
			EllipticCurve mCurve(myEccpParams, OneBlock);
			EccPoint point(mCurve), yik(mCurve), xk(mCurve), gri(mCurve), xab(mCurve), tempCurve(mCurve);
			std::vector<EccPoint> pgK_sum;
			pgK_sum.reserve(subsetInputSize);
			int idx_pgK = 0;

			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			yi.reserve(subsetInputSize);
			int idxYi = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block hashOut;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					point.randomize(hashOut); //H(x)
													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					tempCurve.fromBytes(mG_pairs[i + k].second);
					yi[idxYi] = (point + tempCurve); //H(x) *g^ri

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << idxYi << "] " << yi[idxYi] << std::endl;
#endif
					yi[idxYi].toBytes(sendIter);
					sendIter += yi[idxYi++].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


				 //compute  (g^K)^ri from seeds
				

				for (u64 k = 0; k < curStepSize; k++)
				{
					pgK_sum.emplace_back(mCurve);
					
					if (mBoundCoeffs == 2)
					{
						for (u64 j = 0; j < mG_pairs[i + k].first.size(); j++) //for all subset ri
						{
							tempCurve.fromBytes(mgK_seeds_bytes[mG_pairs[i + k].first[j]]);
							pgK_sum[idx_pgK] = pgK_sum[idx_pgK] + tempCurve; //(g^k)^(subsum ri)
						}
					}
					else
					{
						for (u64 j = 0; j < mG_pairs[i + k].first.size(); j++) //for all subset ri
						{
							EccNumber ci(mCurve, mIntCi[i][j]);
							tempCurve.fromBytes(mgK_seeds_bytes[mG_pairs[i + k].first[j]]);
							pgK_sum[idx_pgK] = pgK_sum[idx_pgK] + tempCurve*ci; //(g^k)^(subsum ri)
						}
					}

					idx_pgK++;
				}

			}
			
			idx_pgK = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

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
					xk = yik - pgK_sum[idx_pgK++]; //H(x)^k
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

		gTimer.setTimePoint("r exp done");
#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 theirStartIdx = mTheirInputSize * t / numThreads;
			u64 tempTheirEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 theirEndIdx = std::min(tempTheirEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = theirStartIdx; i < tempTheirEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, theirEndIdx - i);

				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

	/*					if (i + k == 10)
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

		gTimer.setTimePoint("r psi done");
		//std::cout << "r gkr done\n";

#endif
#endif
	}
	
	void JL10PsiReceiver::startPsi_gK(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		int cntDataSendRecv = 0;
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}

		//stepSize = myInputSize;
		//####################### offline #########################
		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();
		mSetSeedsSize = myInputSize; //compute g^ri without using subset-sum
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;


		std::cout << "startPsi r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		
		

		mSeeds_Byte.resize(myInputSize);
		pG_seeds_Byte.resize(myInputSize);

		//compute g^ri
		auto routine_gri = [&](u64 t)
		{
			u64 inputStartIdx = myInputSize * t / chls.size();
			u64 inputEndIdx = myInputSize * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;
			EllipticCurve mCurve(myEccpParams, OneBlock);
			EccNumber nSeed(mCurve);
			EccPoint pG_seed(mCurve);
			EccPoint mG(mCurve);
			mG = mCurve.getGenerator();

			for (u64 i = 0; i < subsetInputSize;i++)
			{
				nSeed.randomize(mPrng);
				pG_seed = mG *nSeed;  //g^ri

				mSeeds_Byte[inputStartIdx +i] = new u8[nSeed.sizeBytes()];
				nSeed.toBytes(mSeeds_Byte[inputStartIdx +i]);

				pG_seeds_Byte[inputStartIdx +i] = new u8[pG_seed.sizeBytes()];
				pG_seed.toBytes(pG_seeds_Byte[inputStartIdx +i]);
			}
		};

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine_gri(i);
			});
		}
		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "r g^ri done" << std::endl;



		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k


		cntDataSendRecv += g_k.sizeBytes();

		mCurveByteSize = g_k.sizeBytes();
		tempToFromByteCurve = new u8[mCurveByteSize];

									//std::cout << "r g^k= " << g_k << std::endl;

		

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

		//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################
		std::vector<u8*> pgK_seeds_Bytes(myInputSize);

		auto routine_gkri = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;
			EllipticCurve mCurve(myEccpParams, OneBlock);
			EccNumber nSeed(mCurve);
			EccPoint pgK_seed(mCurve), g_k(mCurve);
			g_k.fromBytes(mG_K.data());

			for (u64 k = 0; k < subsetInputSize; k++)
			{
				nSeed.fromBytes(mSeeds_Byte[inputStartIdx + k]);
				pgK_seed = g_k * nSeed;
				pgK_seeds_Bytes[inputStartIdx+k] = new u8[pgK_seed.sizeBytes()];
				pgK_seed.toBytes(pgK_seeds_Bytes[inputStartIdx+k]);
			}
		};

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine_gkri(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "r g^k^ri done" << std::endl;
		gTimer.setTimePoint("r g^k^ri done");

		auto routine = [&](u64 t)
		{
			//EccPoint g_k_thread(mCurve, g_k);

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));


			EllipticCurve mCurve(myEccpParams, OneBlock);

			EccPoint point(mCurve), yik(mCurve), yi(mCurve), xk(mCurve), g_k(mCurve), gri(mCurve), pG_seed(mCurve), tempCurve(mCurve);
			EccNumber nSeed(mCurve);
			g_k.fromBytes(mG_K.data()); //receiving g^k

										//std::cout << "r g^k= " << g_k << std::endl;

			

			int idx_pgK = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);

				std::lock_guard<std::mutex> lock(mtx);
				cntDataSendRecv += yik.sizeBytes() * curStepSize;


				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;

#if 1

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);

					point.randomize(seed); //H(x)
										   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

										   //yi.emplace_back(mCurve);
					pG_seed.fromBytes(pG_seeds_Byte[i + k]);
					yi = (point + pG_seed); //H(x) *g^ri



#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << i + k << "] " << yi << std::endl;
#endif
					yi.toBytes(sendIter);
					sendIter += yi.sizeBytes();
				}
				//gTimer.setTimePoint("r online H(x) g^k done ");

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri
#endif
			}
#if 1
			idx_pgK = 0;
			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);
				std::vector<u8> recvBuff(yi.sizeBytes() * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[yi.sizeBytes()];
				block temp;

				chl.recv(recvBuff); //recv yi^k

				std::lock_guard<std::mutex> lock(mtx);
				cntDataSendRecv += curStepSize * yi.sizeBytes();

				if (recvBuff.size() != curStepSize * yi.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				//gTimer.setTimePoint("r online H(x)^k start");

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yik.fromBytes(recvIter); recvIter += yik.sizeBytes();
					tempCurve.fromBytes(pgK_seeds_Bytes[i + k]);
					xk = yik - tempCurve; //H(x)^k
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
				//gTimer.setTimePoint("r online H(x)^k done");



			}
#endif

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 theirStartIdx = mTheirInputSize * t / numThreads;
			u64 tempTheirEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 theirEndIdx = std::min(tempTheirEndIdx, mTheirInputSize);
			u64 theirSubsetInputSize = theirEndIdx - theirStartIdx;


			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash


			std::lock_guard<std::mutex> lock(mtx);
			cntDataSendRecv += n1n2MaskBytes*theirSubsetInputSize;

			if (recvBuffs.size() != n1n2MaskBytes*theirSubsetInputSize)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}


			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = theirStartIdx; i < tempTheirEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, theirEndIdx - i);

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
		std::cout << cntDataSendRecv << " r cntDataSendRecv bytes\n";
		//std::cout << "r gkr done\n";

#endif

	}

	void JL10PsiReceiver::startPsi_subsetsum_gK(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		//####################### offline #########################

		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;

		mPrng.SetSeed(seed);
		mIntersection.clear();

		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);


		std::cout << "startPsi_subsetsum r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		mCurveByteSize = mG.sizeBytes();
		tempToFromByteCurve = new u8[mCurveByteSize];

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		mSeeds_Byte.resize(mSetSeedsSize);
		pG_seeds_Byte.resize(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);
			mSeeds_Byte[i] = new u8[mCurveByteSize];
			nSeeds[i].toBytes(mSeeds_Byte[i]);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
			pG_seeds_Byte[i] = new u8[mCurveByteSize];
			pG_seeds[i].toBytes(pG_seeds_Byte[i]);
		}
		//std::cout << "g^seed done" << std::endl;

		gTimer.setTimePoint("r offline g^seed done ");

		std::vector<std::pair<std::vector<u64>, u8*>> mG_pairs; //{index of sub ri}, g^(subsum ri)
		mG_pairs.reserve(myInputSize);

		std::vector<u64> indices(mSetSeedsSize);
		mIntCi.resize(mMyInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{
			if (mMyInputSize < (1 << 9))
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
			}
			else
			{
				indices.resize(0);
				while (indices.size() < mChoseSeedsSize)
				{
					int rnd = rand() % mSetSeedsSize;
					if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
						indices.push_back(rnd);
				}
			}

			EccPoint g_sum(mCurve);


			if (mBoundCoeffs == 2)
			{
				for (u64 j = 0; j < mChoseSeedsSize; j++)
					g_sum = g_sum + pG_seeds[indices[j]]; //g^sum //h=2   ci=1
			}
			else
			{
				mIntCi[i].resize(mChoseSeedsSize);

				for (u64 j = 0; j < mChoseSeedsSize; j++)
				{
					mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);
					EccNumber ci(mCurve, mIntCi[i][j]);
					g_sum = g_sum + pG_seeds[indices[j]] * ci; //g^ci*sum
				}
			}

			std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);
			mG_pairs.push_back(std::make_pair(subIdx, temp));
		}

		//std::cout << "mG_pairs_subsetsum done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		std::vector<u8> mG_K; chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k
									//std::cout << "r g^k= " << g_k << std::endl;


									//compute seeds (g^k)^ri
		std::vector<EccPoint> pgK_seeds;
		std::vector<u8*> mgK_seeds_bytes;
		pgK_seeds.reserve(mSetSeedsSize);
		mgK_seeds_bytes.resize(mSetSeedsSize);

		//seeds //todo: paralel
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^seeds

			mgK_seeds_bytes[i] = new u8[mCurveByteSize];
			pgK_seeds[i].toBytes(mgK_seeds_bytes[i]);

		}


		std::vector<u8*> pgK_sum_bytes(inputs.size());

		for (u64 k = 0; k < inputs.size(); k++)
		{
			EccPoint pgK_sum(mCurve);
			if (mBoundCoeffs == 2)
			{
				for (u64 j = 0; j < mG_pairs[k].first.size(); j++) //for all subset ri
				{
					pgK_sum = pgK_sum + pgK_seeds[mG_pairs[k].first[j]]; //(g^k)^(subsum ri)
				}
			}
			else
			{
				for (u64 j = 0; j < mG_pairs[k].first.size(); j++) //for all subset ri
				{
					EccNumber ci(mCurve, mIntCi[k][j]);
					pgK_sum = pgK_sum + pgK_seeds[mG_pairs[ k].first[j]] *ci; //(g^k)^(subsum ri)
				}
			}
			pgK_sum_bytes[k] = new u8[pgK_sum.sizeBytes()];
			pgK_sum.toBytes(pgK_sum_bytes[k]);
		}

		gTimer.setTimePoint("r g^k^ri done");



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

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));

			EllipticCurve mCurve(myEccpParams, OneBlock);
			EccPoint point(mCurve), yik(mCurve), xk(mCurve), gri(mCurve), xab(mCurve), tempCurve(mCurve);
			
			int idx_pgK = 0;

			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			yi.reserve(subsetInputSize);
			int idxYi = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block hashOut;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					point.randomize(hashOut); //H(x)
											  //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					tempCurve.fromBytes(mG_pairs[i + k].second);
					yi[idxYi] = (point + tempCurve); //H(x) *g^ri

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << idxYi << "] " << yi[idxYi] << std::endl;
#endif
					yi[idxYi].toBytes(sendIter);
					sendIter += yi[idxYi++].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


													 //compute  (g^K)^ri from seeds

			}


			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

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
					tempCurve.fromBytes(pgK_sum_bytes[i + k]);
					xk = yik - tempCurve; //H(x)^k
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

		gTimer.setTimePoint("r exp done");
#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 theirStartIdx = mTheirInputSize * t / numThreads;
			u64 tempTheirEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 theirEndIdx = std::min(tempTheirEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = theirStartIdx; i < tempTheirEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, theirEndIdx - i);

				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

						/*					if (i + k == 10)
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

		gTimer.setTimePoint("r psi done");
		//std::cout << "r gkr done\n";

#endif
#endif
	}

	
	
	bool JL10PsiReceiver::startPsi_subsetsum_malicious(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		//####################### offline #########################
		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();

		getExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize);


		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
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

		//std::cout << "mG_pairs_subsetsum done" << std::endl;

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
			RandomOracle inputHasher(sizeof(block));
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
					inputHasher.Final(hashX[i + k]);
					
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
					inputHasher.Final(temp);//H(x)^k

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
	//std::cout << "r gkr done\n";

#endif
#endif
		return true;
	}

	void JL10PsiReceiver::startPsi_subsetsum_asyn(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		//####################### offline #########################

		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;

		mPrng.SetSeed(seed);
		mIntersection.clear();

		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);


		std::cout << "startPsi_subsetsum_asyn r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mCurveSeed = mPrng.get<block>();
		EllipticCurve mCurve(myEccpParams, OneBlock);
		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = mCurve.bitCount();


		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		mCurveByteSize = mG.sizeBytes();
		tempToFromByteCurve = new u8[mCurveByteSize];

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;

		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		mSeeds_Byte.resize(mSetSeedsSize);
		pG_seeds_Byte.resize(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(mPrng);
			mSeeds_Byte[i] = new u8[mCurveByteSize];
			nSeeds[i].toBytes(mSeeds_Byte[i]);

			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
			pG_seeds_Byte[i] = new u8[mCurveByteSize];
			pG_seeds[i].toBytes(pG_seeds_Byte[i]);
		}
		//std::cout << "g^seed done" << std::endl;

		gTimer.setTimePoint("r offline g^seed done ");

		std::vector<std::pair<std::vector<u64>, u8*>> mG_pairs; //{index of sub ri}, g^(subsum ri)
		mG_pairs.reserve(myInputSize);

		std::vector<u64> indices(mSetSeedsSize);
		mIntCi.resize(mMyInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{
			if (mMyInputSize < (1 << 9))
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
			}
			else
			{
				indices.resize(0);
				while (indices.size() < mChoseSeedsSize)
				{
					int rnd = rand() % mSetSeedsSize;
					if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
						indices.push_back(rnd);
				}
			}

			EccPoint g_sum(mCurve);


			if (mBoundCoeffs == 2)
			{
				for (u64 j = 0; j < mChoseSeedsSize; j++)
					g_sum = g_sum + pG_seeds[indices[j]]; //g^sum //h=2   ci=1
			}
			else
			{
				mIntCi[i].resize(mChoseSeedsSize);

				for (u64 j = 0; j < mChoseSeedsSize; j++)
				{
					mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);
					EccNumber ci(mCurve, mIntCi[i][j]);
					g_sum = g_sum + pG_seeds[indices[j]] * ci; //g^ci*sum
				}
			}

			std::vector<u64> subIdx(indices.begin(), indices.begin() + mChoseSeedsSize);
			u8* temp = new u8[g_sum.sizeBytes()];
			g_sum.toBytes(temp);
			mG_pairs.push_back(std::make_pair(subIdx, temp));
		}

		std::cout << "r mG_pairs done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		EccPoint g_k(mCurve);
		std::vector<u8> mG_K; chls[0].recv(mG_K);
		g_k.fromBytes(mG_K.data()); //receiving g^k
									//std::cout << "r g^k= " << g_k << std::endl;


									//compute seeds (g^k)^ri
		std::vector<EccPoint> pgK_seeds;
		std::vector<u8*> mgK_seeds_bytes;
		pgK_seeds.reserve(mSetSeedsSize);
		mgK_seeds_bytes.resize(mSetSeedsSize);

		//seeds //todo: paralel
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			pgK_seeds.emplace_back(mCurve);
			pgK_seeds[i] = g_k * nSeeds[i];  //(g^k)^seeds

			mgK_seeds_bytes[i] = new u8[mCurveByteSize];
			pgK_seeds[i].toBytes(mgK_seeds_bytes[i]);

		}


		std::vector<u8*> pgK_sum_bytes(inputs.size());

		for (u64 k = 0; k < inputs.size(); k++)
		{
			EccPoint pgK_sum(mCurve);
			if (mBoundCoeffs == 2)
			{
				for (u64 j = 0; j < mG_pairs[k].first.size(); j++) //for all subset ri
				{
					pgK_sum = pgK_sum + pgK_seeds[mG_pairs[k].first[j]]; //(g^k)^(subsum ri)
				}
			}
			else
			{
				for (u64 j = 0; j < mG_pairs[k].first.size(); j++) //for all subset ri
				{
					EccNumber ci(mCurve, mIntCi[k][j]);
					pgK_sum = pgK_sum + pgK_seeds[mG_pairs[k].first[j]] * ci; //(g^k)^(subsum ri)
				}
			}
			pgK_sum_bytes[k] = new u8[pgK_sum.sizeBytes()];
			pgK_sum.toBytes(pgK_sum_bytes[k]);
		}

		std::cout << "r g^k^ri done" << std::endl;
		gTimer.setTimePoint("r g^k^ri done");



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

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));

			EllipticCurve mCurve(myEccpParams, OneBlock);
			EccPoint point(mCurve), yik(mCurve), xk(mCurve), gri(mCurve), xab(mCurve), tempCurve(mCurve);

			int idx_pgK = 0;

			std::vector<EccPoint> yi; //yi=H(xi)*g^ri
			yi.reserve(subsetInputSize);
			int idxYi = 0;

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yik.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block hashOut;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					point.randomize(hashOut); //H(x)
											  //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi.emplace_back(mCurve);
					tempCurve.fromBytes(mG_pairs[i + k].second);
					yi[idxYi] = (point + tempCurve); //H(x) *g^ri

#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << idxYi << "] " << yi[idxYi] << std::endl;
#endif
					yi[idxYi].toBytes(sendIter);
					sendIter += yi[idxYi++].sizeBytes();
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


													 //compute  (g^K)^ri from seeds

			}


			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)  //yH(their xi)^k*(g^ri)^k
			{

				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);

				std::vector<u8> recvBuff(yi[0].sizeBytes() * curStepSize); //receiving  H(their x)^k 
				u8* xk_byte = new u8[yi[0].sizeBytes()];
				block temp;
#if 1				
				chl.recv(recvBuff); //recv H(their x)^k

				if (recvBuff.size() != curStepSize * yi[0].sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					yik.fromBytes(recvIter); recvIter += yik.sizeBytes();
					tempCurve.fromBytes(pgK_sum_bytes[i + k]);
					xk = yik+tempCurve; //H(their x)^k *(g^ri)^k
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

		std::cout<<"r exp done\n";
		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash
			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, inputEndIdx - i);

				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

						/*					if (i + k == 10)
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

		gTimer.setTimePoint("r psi done");
		//std::cout << "r gkr done\n";

#endif
#endif
	}

	void JL10PsiReceiver::startPsi_ristretoo(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}

		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;

		//stepSize = myInputSize;
		//####################### offline #########################
		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();
		mSetSeedsSize = myInputSize; //compute g^ri without using subset-sum
		myStepSize = myInputSize / numStep;
		theirStepSize = mTheirInputSize / numStep;


		std::cout << "startPsi r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		//mCurve.getMiracl().IOBASE = 10;
		mFieldSize = crypto_core_ristretto255_BYTES;

		std::vector<unsigned char*> mSeeds_Byte(mSetSeedsSize);
		std::vector<unsigned char*> pG_seeds_Byte(mSetSeedsSize);

		//compute g^ri
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			mSeeds_Byte[i]= new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(mSeeds_Byte[i]);

			pG_seeds_Byte[i] = new unsigned char[crypto_core_ristretto255_BYTES];
			crypto_core_ristretto255_scalar_random(mSeeds_Byte[i]);
			crypto_scalarmult_ristretto255_base(pG_seeds_Byte[i], (mSeeds_Byte[i]));
		}
		std::cout << "g^ri done" << std::endl;



		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		unsigned char mgk[crypto_core_ristretto255_BYTES];
		chls[0].recv(mgk);

		//std::cout << "r g^k= " << toBlock((u8*)&mgk) << std::endl;

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize * mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

		//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################



		auto routine = [&](u64 t)
		{
			//EccPoint g_k_thread(mCurve, g_k);

			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			RandomOracle inputHasher(sizeof(block));

			unsigned char* point = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* yik = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* yi = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* xk = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* g_k = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* gri = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* pG_seed = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point_hash = new unsigned char[crypto_core_ristretto255_HASHBYTES];

			//std::cout << "r g^k= " << g_k << std::endl;

			/*for (u64 k = 0; k < subsetInputSize; k++)
				pgK_seeds[k]=new unsigned char[crypto_core_ristretto255_BYTES];*/

			int idx_pgK = 0;

		/*	std::cout << inputStartIdx << " " << inputEndIdx << " r inputEndIdx t\n";
			std::cout << myStepSize << " " << theirStepSize << " r myStepSize t\n";*/


			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(myStepSize, inputEndIdx - i);
				std::vector<unsigned char*> pgK_seeds(curStepSize);


				std::vector<u8> sendBuff(crypto_core_ristretto255_BYTES * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;
#if 1

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);
					ristretto255_hash_from_blk(point_hash, seed);
					crypto_core_ristretto255_from_hash(point, point_hash);

					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					//H(x) *g^ri
					crypto_core_ristretto255_add(yi, pG_seeds_Byte[i+k], point);
					
					//std::cout << "r yi  " << toBlock(yi) << std::endl;


#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << i + k << "] " << yi << std::endl;
#endif
					memcpy(sendIter, yi, crypto_core_ristretto255_BYTES);
					sendIter += crypto_core_ristretto255_BYTES;
				}
				//gTimer.setTimePoint("r online H(x) g^k done ");

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri
#endif
			}
#if 1
			idx_pgK = 0;
			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);
				std::vector<u8> recvBuff(crypto_core_ristretto255_BYTES * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[crypto_core_ristretto255_BYTES];
				block temp;

				chl.recv(recvBuff); //recv yi^k

				if (recvBuff.size() != curStepSize * crypto_core_ristretto255_BYTES)
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				//gTimer.setTimePoint("r online H(x)^k start");

				for (u64 k = 0; k < curStepSize; ++k)
				{
					memcpy(yik, recvIter, crypto_core_ristretto255_BYTES);
					recvIter += crypto_core_ristretto255_BYTES;

					unsigned char gkri[crypto_core_ristretto255_BYTES];

					if (crypto_scalarmult_ristretto255(gkri, mSeeds_Byte[i + k], mgk) != 0) {

						std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}

					crypto_core_ristretto255_sub(xk, yik, gkri);
					temp = toBlock(xk); //H(x)^k

					
#ifdef PRINT
					std::cout << "r xk[" << i + k << "] " << temp << std::endl;
					std::cout << "r gkri[" << i + k << "] " << toBlock(gkri) << std::endl;
					std::cout << "r yik[" << i + k << "] " << toBlock(yik) << std::endl;

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
				//gTimer.setTimePoint("r online H(x)^k done");



			}
#endif

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
				});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 theirStartIdx = mTheirInputSize * t / numThreads;
			u64 tempTheirEndIdx = mTheirInputSize * (t + 1) / numThreads;
			u64 theirEndIdx = std::min(tempTheirEndIdx, mTheirInputSize);

			std::vector<u8> recvBuffs;
			chl.recv(recvBuffs); //receive Hash

			if (recvBuffs.size() != theirInputSize * n1n2MaskBytes)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}

			auto theirMasks = recvBuffs.data();
			//std::cout << "r toBlock(recvBuffs): " << t << " - " << toBlock(theirMasks) << std::endl;


			for (u64 i = theirStartIdx; i < tempTheirEndIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, theirEndIdx - i);

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
		//std::cout << "r gkr done\n";

#endif

	}

	bool JL10PsiReceiver::startPsi_malicious_ristretto(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls)
	{
		u64 numSuperBlocks = 2;

		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		//####################### offline #########################
		gTimer.reset();
		gTimer.setTimePoint("r offline start ");

		mSecParam = secParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(seed);
		mIntersection.clear();

		mSetSeedsSize = myInputSize; //compute g^ri without using subset-sum

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize  << "\n";

		mFieldSize = crypto_core_ristretto255_BYTES;

		std::vector<unsigned char*> nSeeds(mSetSeedsSize);
		std::vector<unsigned char*> pG_seeds(mSetSeedsSize);

		//compute seed and g^seed
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(nSeeds[i]);

			pG_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];
			crypto_core_ristretto255_scalar_random(nSeeds[i]);
			crypto_scalarmult_ristretto255_base(pG_seeds[i], (nSeeds[i]));
		}
		//std::cout << "g^seed done" << std::endl;


		u8* onebit = new u8[1]; //return bit
		std::vector<block> hashX(inputs.size());

		//std::cout << "mG_pairs_subsetsum done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		unsigned char* mG_K= new unsigned char[crypto_core_ristretto255_BYTES];
		chls[0].recv(mG_K);
		//std::cout << "r g^k= " << g_k << std::endl;

		//compute seeds (g^k)^ri
		std::vector<unsigned char*> pgK_seeds(mSetSeedsSize);

		////seeds //todo: paralel
		//for (u64 i = 0; i < mSetSeedsSize; i++)
		//{
		//	pgK_seeds[i]= new unsigned char[crypto_core_ristretto255_BYTES];
		//	if (crypto_scalarmult_ristretto255(pgK_seeds[i], nSeeds[i], mG_K) != 0) {

		//		std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
		//		throw std::runtime_error("rt error at " LOCATION);
		//	}
		//}


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = (40 + log2(mTheirInputSize * mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;

#if 1	//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());
		std::vector<block> xik(inputs.size()); //H(x)^k 

		//##################### compute/send yi=H(x)*(g^ri). recv yi^k, comp. H(x)^k  #####################

		auto routine = [&](u64 t)
		{
			RandomOracle inputHasher(sizeof(block));
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			auto& chl = chls[t];
			u8 hashOut[SHA1::HashSize];

			//EllipticCurve curve(p256k1, thrdPrng[t].get<block>());

			unsigned char* point = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* xk = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* gri = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* xab = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point_hash = new unsigned char[crypto_core_ristretto255_HASHBYTES];


			std::vector<unsigned char*> yi; //yi=H(xi)*g^ri
			std::vector<unsigned char*> yik;
			std::vector<unsigned char*> yiv;

			unsigned char* nR = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			unsigned char* nC = new unsigned char[crypto_core_ristretto255_SCALARBYTES];

			for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)  //yi=H(xi)*g^ri
			{

				auto curStepSize = std::min(stepSize, inputEndIdx - i);
				yi.resize(curStepSize);

				yik.resize(curStepSize);
				yiv.resize(curStepSize);
				for (u64 k = 0; k < curStepSize; k++)
				{
					yik[k] = new unsigned char[crypto_core_ristretto255_BYTES];
					yiv[k] = new unsigned char[crypto_core_ristretto255_BYTES];
				}

				std::vector<u8*> challeger_bytes(2); //(yi^k, yi^v)
				block* challenger = new block[numSuperBlocks]; //H(yi^k, yi^v)
				block temp_challenger = ZeroBlock;

				std::vector<u8> sendBuff(crypto_core_ristretto255_BYTES * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;


				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashX[i + k]);
					ristretto255_hash_from_blk(point_hash, hashX[i + k]);
					crypto_core_ristretto255_from_hash(point, point_hash);//H(x)

													   //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yi[k] = new unsigned char[crypto_core_ristretto255_BYTES];
					crypto_core_ristretto255_add(yi[k], point, pG_seeds[i*curStepSize+k]);//H(x) *g^ri


#ifdef PRINT
					if (i + k == 10)
						std::cout << "r yi[" << k << "] " << yi[k] << std::endl;
#endif
					memcpy(sendIter, yi[k], crypto_core_ristretto255_BYTES);
					sendIter += crypto_core_ristretto255_BYTES;
				}

				chl.asyncSend(std::move(sendBuff));  //sending yi=H(xi)*g^ri


													 //compute  (g^K)^ri from seeds
				std::vector<unsigned char*> pgK_sum(curStepSize);

				for (u64 k = 0; k < curStepSize; k++)
				{
					pgK_sum[k]= new unsigned char[crypto_core_ristretto255_BYTES];

					if (crypto_scalarmult_ristretto255(pgK_sum[k], nSeeds[i * curStepSize + k], mG_K) != 0) {

						std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}
				}




				std::vector<u8> recvBuff(crypto_core_ristretto255_BYTES * curStepSize); //receiving yi^k = H(x)^k *g^ri^k
				u8* xk_byte = new u8[crypto_core_ristretto255_BYTES];
				block temp;
#if 1				
				chl.recv(recvBuff); //recv yi^k||yi^v...||r

				if (recvBuff.size() != curStepSize * (2 * crypto_core_ristretto255_BYTES + 1))
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				memcpy(nR, recvIter + curStepSize * (2 * crypto_core_ristretto255_BYTES), crypto_core_ristretto255_BYTES);

				//std::cout << "r nR= " << nR << " idx= "<< i<<"\n";

				for (u64 k = 0; k < curStepSize; ++k) //ZKDL verifier
				{
					memcpy(yik[k], recvIter , crypto_core_ristretto255_BYTES);
					recvIter += crypto_core_ristretto255_BYTES;

					memcpy(yik[k], recvIter, crypto_core_ristretto255_BYTES);
					recvIter += crypto_core_ristretto255_BYTES;

					challeger_bytes[0] = new u8[crypto_core_ristretto255_BYTES]; //todo: optimize
					memcpy(challeger_bytes[0], yik[k], crypto_core_ristretto255_BYTES); //yi^k  

					challeger_bytes[1] = new u8[crypto_core_ristretto255_BYTES];
					memcpy(challeger_bytes[1], yiv[k], crypto_core_ristretto255_BYTES); //yi^k  


					for (int idxChall = 0; idxChall < challeger_bytes.size(); idxChall++)
						for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
						{
							auto minsize = std::min(sizeof(block), crypto_core_ristretto255_BYTES - idxBlock * sizeof(block));
							memcpy((u8*)&temp_challenger, challeger_bytes[idxChall] + idxBlock * minsize, minsize);
							challenger[idxBlock] = challenger[idxBlock] + temp_challenger;
						}
				}


				std::vector<block> cipher_challenger(numSuperBlocks);
				mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data()); //compute H(sum (yi^k+ yi^v))
				
				unsigned char* nC = new unsigned char[crypto_core_ristretto255_BYTES];
				memcpy(nC, cipher_challenger.data(), crypto_core_ristretto255_BYTES);
			//c=H(sum (yi^k+ yi^v))
				//std::cout << "r nC= " << nC << " idx= " << i << "\n";

				for (u64 k = 0; k < curStepSize; ++k) //ZKDL verifier
				{
					unsigned char* yikNR = new unsigned char[crypto_core_ristretto255_BYTES];
					//yi[k] * nR
					if (crypto_scalarmult_ristretto255(yikNR, nR, yi[k]) != 0) {

						std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}

					unsigned char* yiknC = new unsigned char[crypto_core_ristretto255_BYTES];
					//yi[k] * nR
					if (crypto_scalarmult_ristretto255(yiknC, nC ,yik[k]) != 0) {

						std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}

					unsigned char* yiRyiKC = new unsigned char[crypto_core_ristretto255_BYTES];

					//yi^r*(yi^k)^c
					crypto_core_ristretto255_add(yiRyiKC, yiknC, yikNR);

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
					//H(x)^k
					crypto_core_ristretto255_sub(xk, yik[k], pgK_sum[k]);

					u8* temp_yik = new u8[crypto_core_ristretto255_HASHBYTES];

					memcpy(temp_yik, xk, crypto_core_ristretto255_BYTES);

					block blkTemp = ZeroBlock;
					for (int idxBlock = 0; idxBlock < numSuperBlocks; idxBlock++)
					{
						auto minsize = std::min(sizeof(block), crypto_core_ristretto255_HASHBYTES - idxBlock * sizeof(block));
						memcpy((u8*)&blkTemp, temp_yik + minsize, minsize);
						xik[i + k] = xik[i + k] + blkTemp;
					}

					xik[i + k] = xik[i + k] + hashX[i + k];
					inputHasher.Reset();
					//inputHasher.Update(hashX[i + k]);
					inputHasher.Update(xik[i + k]);
					inputHasher.Final(temp);//H(x)^k

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
			u64 tempEndIdx = mTheirInputSize * (t + 1) / numThreads;
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
		//std::cout << "r gkr done\n";

#endif
#endif
		return true;
	}

}