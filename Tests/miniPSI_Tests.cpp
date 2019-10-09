#include "miniPSI_Tests.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include "Poly/polyNTL.h"
#include "Poly/polyFFT.h"
#include "PsiDefines.h"
#include "MiniPSI/MiniReceiver.h"
#include "MiniPSI/MiniSender.h"
#include "Tools/BalancedIndex.h"
#include "Tools/SimpleIndex.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "Common.h"
#include <thread>
#include <vector>
#include "ECDH/EcdhPsiReceiver.h"
#include "ECDH/EcdhPsiSender.h"

#include "ECDH/JL10PsiReceiver.h"
#include "ECDH/JL10PsiSender.h"

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#endif //  _MSC_VER

#include <memory>
//#include <miracl\include\big.h>
//#include <miracl\include\ec2.h>

//#include "Ristretto/test-ristretto.h"
//#include "Ristretto/ed25519-donna.h"

using namespace osuCrypto;

//#define DEBUGGING

namespace tests_libOTe
{
	struct Bin111
	{
		//std::vector<item> values; //index of items
		std::vector<block> blks;
		std::vector<u8> hashIdxs;
		std::vector<u64> Idxs;
	};




	void Simple_Test_Impl()
	{
		setThreadName("Sender");
		u64 setSize = 1 << 16, psiSecParam = 40, numThreads(2);

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


		std::vector<block> set(setSize);
		for (u64 i = 0; i < set.size(); ++i)
			set[i] = prng.get<block>();

		std::vector<Bin111> mBins;

		AES mAesHasher;
		mAesHasher.setKey(prng.get<block>());

		u64 mNumBins = 4;// sqrt(setSize);
		mBins.resize(mNumBins);

		block cipher;
		u64 b1, b2; //2 bins index

					//1st pass
		for (u64 idxItem = 0; idxItem < set.size(); ++idxItem)
		{
			cipher = mAesHasher.ecbEncBlock(set[idxItem]);

			b1 = _mm_extract_epi64(cipher, 0) % mNumBins; //1st 64 bits for finding bin location
			b2 = _mm_extract_epi64(cipher, 1) % mNumBins; //2nd 64 bits for finding alter bin location


			/*mBins[b1].blks.push_back(set[idxItem]);
			mBins[b2].blks.push_back(set[idxItem]);

			mBins[b1].hashIdxs.push_back(0);
			mBins[b2].hashIdxs.push_back(1);*/

			mBins[b1].Idxs.push_back(idxItem);
			//mBins[b2].Idxs.push_back(idxItem);
		}

		int maxbinsize = 0;
		for (u64 i = 0; i < mBins.size(); i++)
		{
			if (mBins[i].Idxs.size() > maxbinsize)
				maxbinsize = mBins[i].Idxs.size();
		}

		std::cout << "setSize= " << setSize  << "\n";
		std::cout << "maxbinsize= " << maxbinsize << "\n";
		std::cout << "mBins.size()= " << mBins.size() << "\n";
		std::cout << "total item= " << mBins.size()*maxbinsize << "\n";
		std::cout << "%= " << double(mBins.size()*maxbinsize/ (double)setSize) << "\n";

	}


	void testNewGroup()
	{
		

	}

#if 0
	void print_32bits(unsigned char uchar[32], string name="")
	{
#ifdef DEBUGGING
		block blk = toBlock((u8*)&uchar[16]);
		std::cout << name << ": " << blk;
		blk = toBlock((u8*)&uchar[0]);
		std::cout << blk << "\n";
#endif
	}

	/* test data */
	typedef struct test_data_t {
		unsigned char sk[32], pk[32], sig[64];
		const char *m;
	} test_data;

	static void
		edassert_die(const unsigned char *a, const unsigned char *b, size_t len, int round, const char *failreason) {
		size_t i;
		if (round > 0)
			printf("round %d, %s\n", round, failreason);
		else
			printf("%s\n", failreason);
		printf("want: "); for (i = 0; i < len; i++) printf("%02x,", a[i]); printf("\n");
		printf("got : "); for (i = 0; i < len; i++) printf("%02x,", b[i]); printf("\n");
		printf("diff: "); for (i = 0; i < len; i++) if (a[i] ^ b[i]) printf("%02x,", a[i] ^ b[i]); else printf("  ,"); printf("\n\n");
		exit(1);
	}

	static void
		edassert_equal_round(const unsigned char *a, const unsigned char *b, size_t len, int round, const char *failreason) {
		if (memcmp(a, b, len) == 0)
			return;
		edassert_die(a, b, len, round, failreason);
	}

	static void
		edassert_equal(const unsigned char *a, const unsigned char *b, size_t len, const char *failreason) {
		if (memcmp(a, b, len) == 0)
			return;
		edassert_die(a, b, len, -1, failreason);
	}


	void Ristretoo_Test_Impl() {
		//test_ristretto();
		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


		{ //test  curved25519_scalarmult_basepoint

			/* result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times */
			const curved25519_key curved25519_expected = {
				0xac,0xce,0x24,0xb1,0xd4,0xa2,0x36,0x21,
				0x15,0xe2,0x3e,0x84,0x3c,0x23,0x2b,0x5f,
				0x95,0x6c,0xc0,0x7b,0x95,0x82,0xd7,0x93,
				0xd5,0x19,0xb6,0xf1,0xfb,0x96,0xd6,0x04
			};

			curved25519_key csk[2] = { { 255 } };

			for (int i = 0; i < 1024; i++)
				curved25519_scalarmult_basepoint(csk[(i & 1) ^ 1], csk[i & 1]);
			edassert_equal(curved25519_expected, csk[0], sizeof(curved25519_key), "curve25519 failed to generate correct value");

		}
		{

	/*		test_data dataset[] = {
			#include "Ristretto\src\regression.h"
			};
			ed25519_public_key pk;

			for (int i = 0; i < 1024; i++) {
				ed25519_publickey(dataset[i].sk, pk);
				edassert_equal_round(dataset[i].pk, pk, sizeof(pk), i, "public key didn't match");
			}*/
		}

		{
			ed25519_secret_key secret_key1,  secret_key2, sk_sum;
			ed25519_public_key public_key1, public_key2,  pk_sum, pk_sum_test;

			prng.get(secret_key1, 32);
			prng.get(secret_key2, 32);

			for (u32 i = 0; i < 32; i++)
			{
				//secret_key1[i] = 0;
				//secret_key2[i] = 0;
			}
			secret_key1[0] = 1;
			secret_key2[0] = 2;

			ed25519_publickey( secret_key1, public_key1); //pk1=g^sk1
			ed25519_publickey(secret_key2, public_key2); //pk2=g^sk2


			hash_512bits extsk;
			bignum256modm a1, a2, sum;
			ed25519_extsk(extsk, secret_key1);
			expand256_modm(a1, extsk, 32);
			
			ed25519_extsk(extsk, secret_key2);
			expand256_modm(a2, extsk, 32);
			add256_modm(sum, a1, a2);
			contract256_modm(sk_sum, sum); //sk_sum=sk1+sk2

			ed25519_publickey( sk_sum, pk_sum); // pk_sum=g^(sk1+sk2)


			ed25519_extsk(extsk, public_key1);
			expand256_modm(a1, extsk, 32);
			ed25519_extsk(extsk, public_key2);
			expand256_modm(a2, extsk, 32);

			mul256_modm(sum, a1, a2);
			contract256_modm(pk_sum_test, sum);  //pk_sum_test=pk1*pk2

			print_32bits(secret_key1, "secret_key1");
			print_32bits(public_key1, "public_key1");
			print_32bits(secret_key2, "secret_key2");
			print_32bits(public_key2, "public_key2");

			print_32bits(pk_sum, "pk_sum     ");
			print_32bits(pk_sum_test, "pk_sum_test");
		}

	
		{
			curved25519_key secret_key1, public_key1, secret_key2, public_key2, sk_sum, pk_sum, pk_sum_test;
			prng.get(secret_key1, 32);
			prng.get(secret_key2, 32);

			for (u32 i = 0; i < 32; i++)
			{
				//secret_key1[i] = 0;
				//secret_key2[i] = 0;
			}
			secret_key1[0] = 1;
			secret_key2[0] = 2;

			curved25519_scalarmult_basepoint(public_key1, secret_key1); //pk1=g^sk1
			curved25519_scalarmult_basepoint(public_key2, secret_key2); //pk2=g^sk2



			bignum25519 a1, a2, sum;
			curve25519_expand(a1, secret_key1);
			curve25519_expand(a2, secret_key2);
			curve25519_add(sum, a1, a2);
			curve25519_contract(sk_sum, sum); //sk_sum=sk1+sk2
			curved25519_scalarmult_basepoint(pk_sum, sk_sum); // pk_sum=g^(sk1+sk2)

			bignum25519 a11, a21, sum1;
			curve25519_expand(a11, public_key1);
			curve25519_expand(a21, public_key2);
			curve25519_mul(sum1, a11, a21);
			curve25519_contract(pk_sum_test, sum1);  //pk_sum_test=pk1*pk2

			print_32bits(secret_key1, "secret_key1");
			print_32bits(public_key1, "public_key1");
			print_32bits(secret_key2, "secret_key2");
			print_32bits(public_key2, "public_key2");

			print_32bits(pk_sum, "pk_sum     ");
			print_32bits(pk_sum_test, "pk_sum_test");

			curve25519_square(sum1, a11); //pk1^2
			curve25519_contract(pk_sum_test, sum1);  //pk_sum_test=pk1^2
			print_32bits(pk_sum_test, "pk1^2");

		}
	}

#endif
	void curveTest()
	{
		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		u64 setSenderSize = 1 << 4;
		EllipticCurve mCurve(Curve25519, OneBlock);

		miracl* mrc = mirsys(32, 2);

	/*	u8* src = new u8[32];
		prng0.get(src, 32);

		big varX=mirvar(mrc, 0);
		std::cout << varX << "\n";
		
		bytes_to_big(mrc, 32, (char*)src, varX);
		std::cout << varX << "\n";


		char* mMem = (char *)ecp_memalloc(mrc, 1);
		epoint* mVal = (epoint *)epoint_init_mem(mrc, mMem, 0);


		uint32_t itmp;*/
		/*big bigtmp;
		EC2* point*/

		//compress to x-point and y-bit and convert to byte array
		//itmp = point->get(bigtmp);

		////first store the y-bit
		//pBufIdx[0] = (uint8_t)(itmp & 0x01);

		////then store the x-coordinate (sec-param/8 byte size)
		//big_to_bytes(field_size_bytes - 1, bigtmp.getbig(), (char*)pBufIdx + 1, true);


		//bytes_to_big(32, (char*)src, varX);
	//	bytes_to_big(mrc, 32, (char*)src, varX);
	//	epoint_set(mrc, varX, varX, 0, mVal);

		/*cotstr(mrc, mVal.mVal, val.mCurve->mMiracl->IOBUFF);
		std::cout << val.mCurve->mMiracl->IOBUFF;*/

		//std::cout << mVal << "\n";

#if 0
		ZZ mPrime = mPrime255_19;



		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		EccNumber nK(mCurve);
		nK.randomize(prng0);
		
		u64 mPolyBytes = mG.sizeBytes();// mCurve.bitCount() / 8;

		std::cout << "r mFieldSize= " << mCurve.bitCount() << " => byte = " <<  mPolyBytes << "\n";


		std::vector<block> inputs(setSenderSize), theirInputs(setSenderSize);
		for (u64 i = 0; i < setSenderSize; ++i)
		{
			inputs[i] = prng0.get<block>();
			theirInputs[i] = prng0.get<block>();

			//if (i < 2)
			//	theirInputs[i] = inputs[i];
		}

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
		std::vector<EccPoint> yi_curve;
		yi_curve.reserve(inputs.size());



		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);

			u8* yri = new u8[mPolyBytes];

			yi_curve.emplace_back(mCurve);
			yi_curve[idx].randomize(prng0);

			//std::cout << "r yi_curve[idx]= " << yi_curve[idx] << " \n";

			u8* yi_byte = new u8[yi_curve[idx].sizeBytes()];
			yi_curve[idx].toBytes(yi_byte);

			block lastblk = ZeroBlock;
			memcpy((u8*)&lastblk, yi_byte + 2 * sizeof(block), mPolyBytes - 2 * sizeof(block));

			std::cout << "y[ " << idx << "] = " << toBlock(yi_byte)
				<< " - " << toBlock(yi_byte + sizeof(block))
				<< " - " << lastblk << std::endl;

			ZZFromBytes(zz, yi_byte, mPolyBytes);
			//std::cout << "r P(x)= " << idx << " - " << toBlock(mG_pairs[idx].second) << std::endl;
			zzY[idx] = to_ZZ_p(zz);
		}


		prepareForInterpolate(zzX, degree, M, a, 1, mPrime);
		iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, 1, mPrime);


		/////////////////////eval
		ZZ_p* zzX_their = new ZZ_p[theirInputs.size()];
		ZZ_p* zzY_their = new ZZ_p[theirInputs.size()];

		for (u64 idx = 0; idx < theirInputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&theirInputs[idx], sizeof(block));
			zzX_their[idx] = to_ZZ_p(zz);
		}

		ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
		ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];

		build_tree(p_tree, zzX_their, degree * 2 + 1, 1, mPrime);
		evaluate(Polynomial, p_tree, reminders, degree * 2 + 1, zzY_their, 1, mPrime);


		for (u64 idx = 0; idx < theirInputs.size(); idx++)
		{

			u8* yi_bytes = new u8[mG.sizeBytes()];
			BytesFromZZ(yi_bytes, rep(zzY_their[idx]), mPolyBytes);

			//if (idx < 4)

			block lastblk = ZeroBlock;
			memcpy((u8*)&lastblk, yi_bytes + 2 * sizeof(block), mPolyBytes - 2 * sizeof(block));

			std::cout << "y[ " << idx << "] = " << toBlock(yi_bytes)
					<< " - " << toBlock(yi_bytes + sizeof(block)) 
					<< " - " << lastblk << std::endl;

			EccPoint point_ri(mCurve);
			point_ri.fromBytes(yi_bytes);
			
			//if (idx < 4)
				std::cout << "point_ri[ " <<idx <<"] = " << point_ri << std::endl;

			std::cout << "\n";
		}
#endif

	}

	void MiniPSI_impl2()
	{
		setThreadName("EchdSender");
		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 7, psiSecParam = 40, numThreads(1);

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

		//sendSet[0] = ZeroBlock;
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
			recv.outputBigPoly(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputBigPoly(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void MiniPSI_hasing_impl()
	{
		setThreadName("EchdSender");
		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 7, psiSecParam = 40, numThreads(2);

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
			recv.outputSimpleHashing(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputSimpleHashing(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void MiniPSI_malicious_impl()
	{
		setThreadName("EchdSender");
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

		//sendSet[0] = ZeroBlock;
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
			recv.outputBigPoly_malicious(recvSet.size(), sendSet.size(), 40, prng1, recvSet, recvChls);

		});

		sender.outputBigPoly_malicious(sendSet.size(), recvSet.size(), 40, prng0, sendSet, sendChls);

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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}



	void DhPSI_impl()
	{
		setThreadName("EchdSender");
		int curveType = 0;

		u64 setSenderSize = 1 << 6, setRecvSize = 1 << 8, psiSecParam = 40, numThreads(2);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < 10; ++i)
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


		EcdhPsiSender sender;
		EcdhPsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.sendInput(setRecvSize, setSenderSize, 40, prng1.get<block>(), recvSet, recvChls, curveType);

		});

		sender.sendInput(setSenderSize, setRecvSize, 40, prng0.get<block>(), sendSet, sendChls, curveType);


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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void JL10PSI_impl()
	{
		setThreadName("EchdSender");
		u64 setSenderSize = 1 << 6, setRecvSize = 1 <<8, psiSecParam = 40, numThreads(2);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < 10; ++i)
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


		JL10PsiSender sender;
		JL10PsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.startPsi(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

		});

		sender.startPsi(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

		thrd.join();

		std::cout << gTimer << std::endl;


		std::cout << "recv.mIntersection.size(): " << recv.mIntersection.size() << std::endl;
		//for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
		//{
		///*	std::cout << "#id: " << recv.mIntersection[i] <<
		//		"\t" << recvSet[recv.mIntersection[i]] << std::endl;*/
		//}

		u64 dataSent = 0, dataRecv(0);
		for (u64 g = 0; g < recvChls.size(); ++g)
		{
			dataSent += recvChls[g].getTotalDataSent();
			dataRecv += recvChls[g].getTotalDataRecv();
			recvChls[g].resetStats();
		}

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}



	void JL10PSI_subsetsum_impl()
	{
		setThreadName("EchdSender");
		u64 setSenderSize = 1 <<7, setRecvSize = 1 <<7, psiSecParam = 40, numThreads(1);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSenderSize), recvSet(setRecvSize);
		for (u64 i = 0; i < setSenderSize; ++i)
			sendSet[i] = prng0.get<block>();

		for (u64 i = 0; i < setRecvSize; ++i)
			recvSet[i] = prng0.get<block>();


		for (u64 i = 0; i < 10; ++i)
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


		JL10PsiSender sender;
		JL10PsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.startPsi_subsetsum_asyn(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

		});

		sender.startPsi_subsetsum_asyn(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}




	void JL10PSI_subsetsum_malicious_impl()
	{
		setThreadName("EchdSender");
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


		JL10PsiSender sender;
		JL10PsiReceiver recv;

		auto thrd = std::thread([&]() {
			gTimer.setTimePoint("r start ");
			recv.startPsi_subsetsum_malicious(recvSet.size(), sendSet.size(), 40, prng1.get<block>(), recvSet, recvChls);

		});

		sender.startPsi_subsetsum_malicious(sendSet.size(), recvSet.size(), 40, prng1.get<block>(), sendSet, sendChls);

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

		//		std::cout << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n";




		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i].close();
			recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();


	}


	void exp_test()
	{
		std::cout << "curveParam = k283\n";
		int n = 10, k = 3;
		PRNG prng(ZeroBlock);

		EllipticCurve curve(p256k1, ZeroBlock);
		curve.getMiracl().IOBASE = 10;

		auto& g = curve.getGenerator();

		std::cout << g << std::endl;

		std::vector<EccNumber> mSeeds;
		std::vector<EccPoint> mGseeds;

		mSeeds.reserve(n);
		mGseeds.reserve(n);

		for (u64 i = 0; i < n; i++)
		{
			// get a random value from Z_p
			mSeeds.emplace_back(curve);
			mSeeds[i].randomize(prng);

			// using brickexp which has the base of g, compute
			//
			//      PK_sigma[i] = g ^ pK[i]
			//
			// where pK[i] is just a random number in Z_p
			mGseeds.emplace_back(curve);
			mGseeds[i] = g * mSeeds[i];
			std::cout << mGseeds[i] << std::endl;

		}

		std::cout << mGseeds[0] << std::endl;
		std::cout << mGseeds[1] << std::endl;

		auto newG = mGseeds[1] + mGseeds[0];

		std::cout << newG << std::endl;


	}


	inline std::string arrU8toString(u8* Z, int size)
	{
		std::string sss;
		for (int j = 0; j < size; j++)
			sss.append(ToString(static_cast<unsigned int>(Z[j])));

		return sss;
	}



	void evalExp()
	{
		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		EllipticCurve mCurve(myEccpParams, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();
		u64 mMyInputSize = 1 << 10;
#if 1
		//////============clasic g^ri==========

		{
			gTimer.reset();
			gTimer.setTimePoint("clasic g^ri starts");
			std::vector<EccPoint> g_r;
			g_r.reserve(mMyInputSize);

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				EccNumber r(mCurve);
				r.randomize(prng);
				g_r.emplace_back(mCurve);
				g_r[i] = mG*r;
			}
			gTimer.setTimePoint("clasic g^ri done");
			std::cout << gTimer << "\n";


			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[g_r[i].sizeBytes()];
				g_r[i].toBytes(temp);

				string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";
		}
#endif
		//////============HSS g^ri==========
		{	gTimer.reset();
		gTimer.setTimePoint("HSS g^ri starts");

		u64 mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs;
		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

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
		gTimer.setTimePoint("HSS g^seed done");

		std::vector<u64> indices(mSetSeedsSize);
		std::vector<EccPoint> g_r;
		g_r.reserve(mMyInputSize);

		for (u64 i = 0; i < mMyInputSize; i++)
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



			if (mBoundCoeffs == 2)
			{
				g_r.emplace_back(pG_seeds[indices[0]]);

				for (u64 j = 1; j < mChoseSeedsSize; j++)
					g_r[i] = g_r[i] + pG_seeds[indices[j]]; //g^sum //h=2   ci=1

			}
			else
			{
				g_r.emplace_back(mCurve);
				for (u64 j = 0; j < mChoseSeedsSize; j++)
				{
					int rnd = 1 + rand() % (mBoundCoeffs - 1);
					EccNumber ci(mCurve, rnd);
					g_r[i] = g_r[i] + pG_seeds[indices[j]] * ci; //g^sum
				}
			}
	}

		gTimer.setTimePoint("HDD g^ri done");
		std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
		int cnt = 0;
		std::vector<string> checkUnique;

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			u8* temp = new u8[g_r[i].sizeBytes()];
			g_r[i].toBytes(temp);

			string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}
		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

#endif // DOUBLE-CHECK


	}

		//////============recursive h=2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h=2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestH1RecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<EccNumber> nSeeds; //level
			std::vector<std::vector<EccPoint>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.reserve(mSeqParams[0].numSeeds);
			pG_seeds[0].reserve(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds.emplace_back(mCurve);
				nSeeds[i].randomize(prng);

				pG_seeds[0].emplace_back(mCurve);
				pG_seeds[0][i] = mG * nSeeds[i];  //g^ri
			}
			gTimer.setTimePoint("Recursive h=2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].reserve(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}

					pG_seeds[idxLvl + 1].emplace_back(pG_seeds[idxLvl][indices[0]]);

					for (u64 j = 1; j < mSeqParams[idxLvl].numChosen; j++)
					{
						pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; //\sum g^ri
					}
				}
			}


			gTimer.setTimePoint("Recursive h=2 HDD g^ri done");
			std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
			int lvlLast = mSeqParams.size();
			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

		//////============recursive h>2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h>2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestRecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<EccNumber> nSeeds; //level
			std::vector<std::vector<EccPoint>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.reserve(mSeqParams[0].numSeeds);
			pG_seeds[0].reserve(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds.emplace_back(mCurve);
				nSeeds[i].randomize(prng);

				pG_seeds[0].emplace_back(mCurve);
				pG_seeds[0][i] = mG * nSeeds[i];  //g^ri
			}
			gTimer.setTimePoint("Recursive h>2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].reserve(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{
					//std::iota(indices.begin(), indices.end(), 0);
					//std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}


					pG_seeds[idxLvl + 1].emplace_back(mCurve);

					if (mSeqParams[idxLvl].boundCoeff == 2)
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; //\sum g^ri
						}
					else if (mSeqParams[idxLvl].boundCoeff == (1 << 2))
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							int ci = 1 + rand() % (mSeqParams[idxLvl].boundCoeff - 1);

							for (u64 idxRep = 0; idxRep < ci; idxRep++) //repeat ci time
							{
								pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; // (g^ri)^ci
							}

						}
					else
					{
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							//need <2^104 but implemnt 2^128
							int rnd = rand() % mSeqParams[idxLvl].boundCoeff;
							EccNumber ci(mCurve, prng);
							pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]] * ci; //\sum g^ri
						}
					}

				}
			}


			gTimer.setTimePoint("Recursive h>2 HDD g^ri done");
			std::cout << gTimer << "\n";

			//#ifdef DOUBLE-CHECK
#if 1
			int lvlLast = mSeqParams.size();

			std::cout << "pG_seeds[lvlLast].size()=" << pG_seeds[lvlLast].size() << "\n";

			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

}


	void subsetSum_test() {

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		EllipticCurve mCurve(myEccpParams, OneBlock);
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

		for (int i = 0; i < checkUnique.size(); i++)
		{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

		}
	}



	void subsetSum(vector<EccPoint>& g_sum) { //fail

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		EllipticCurve mCurve(myEccpParams, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		u64 mMyInputSize = 1 << 6, mSetSeedsSize, mChoseSeedsSize;
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

		g_sum.reserve(mMyInputSize);

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			std::iota(indices.begin(), indices.end(), 0);
			std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

			g_sum.emplace_back(mCurve);

			for (u64 j = 0; j < mChoseSeedsSize; j++)
				g_sum[i] = g_sum[i] + pG_seeds[indices[j]]; //g^sum

			u8* temp = new u8[g_sum[i].sizeBytes()];
			g_sum[i].toBytes(temp);

			string str_sum = arrU8toString(temp, g_sum[i].sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}

		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n";

		for (int i = 0; i < checkUnique.size(); i++)
		{
			//std::cout << "checkUnique. : " << checkUnique[i] << "\n";

		}

	}


	void schnorrZKDL()
	{
		PRNG prng(ZeroBlock);
		EllipticCurve mCurve(myEccpParams, OneBlock);
		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		EccPoint pG(mCurve);
		pG = mCurve.getGenerator();

		EccNumber nK(mCurve);
		nK.randomize(prng);
		auto g_k = pG*nK;  //g^k

		EccNumber nV(mCurve);
		nV.randomize(prng);
		auto g_v = pG*nV;  //g^v

		std::vector<u8*> challeger_bytes(3);

		challeger_bytes[0] = new u8[pG.sizeBytes()];
		pG.toBytes(challeger_bytes[0]);

		challeger_bytes[1] = new u8[g_k.sizeBytes()];
		g_k.toBytes(challeger_bytes[1]);

		challeger_bytes[2] = new u8[g_v.sizeBytes()];
		g_v.toBytes(challeger_bytes[2]);


		block* challenger = new block[numSuperBlocks]; //g + g^k+g^v
		std::vector<block> cipher_challenger(numSuperBlocks);// 

		for (int i = 0; i < numSuperBlocks; i++)
			challenger[i] = ZeroBlock;

		block temp = ZeroBlock;
		for (int i = 0; i < numSuperBlocks; i++)
		{
			memcpy((u8*)&temp, challeger_bytes[i] + i * sizeof(block), sizeof(block));
			challenger[i] = challenger[i] + temp;
		}

		mAesFixedKey.ecbEncBlocks(challenger, numSuperBlocks, cipher_challenger.data());  //c=H(g,g^k, g^v)
		EccNumber nC(mCurve);
		u8* nC_bytes = new u8[nC.sizeBytes()];
		memcpy(nC_bytes, cipher_challenger.data(), nC.sizeBytes());
		nC.fromBytes(nC_bytes);

		EccNumber nR(mCurve);
		nR = nV - nC*nK; //r=v-ck

		std::cout << "t=" << g_v << "\n";
		auto g_r = pG*nR;  //g^r
		auto y_c = g_k*nC;  //g^r

		auto gryc = g_r + y_c;
		std::cout << "g^r*y^c=" << gryc << "\n";




		auto thrd = std::thread([&]() { //prover



		});

		//verifier

		thrd.join();



	}
	
	
	/*void subsetSum_test() {

		vector<EccPoint> points;
		subsetSum(points);
		std::cout << "points: " << points.size() << "\n";

	}*/
}