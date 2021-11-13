// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Snowgem' + blake2s(b'2018-01-01 Snowgem is born.').hexdigest()
 */

static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Snowgem19ac02b7cdc7d9e50c765bbc6146c3dd3adb8e93cf7cbe9bbc7ec290f8950182";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "TENT";
        bip44CoinType = 407; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 8000;
        consensus.nSubsidyHalvingInterval = 60 * 24 * 365 * 4;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitTop = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.nPowAveragingWindow = 17;
        consensus.nMasternodePaymentsStartBlock = 193200;
        consensus.nMasternodePaymentsIncreasePeriod = 43200; // 1 month

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60; // 1 min
        consensus.nTimeshiftPriv = 7 * 24 * 60; // 7 * 1440 blocks in mainnet
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 520000;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 520000;
        consensus.vUpgrades[Consensus::UPGRADE_DIFA].nActivationHeight = 765000;
        consensus.vUpgrades[Consensus::UPGRADE_DIFA].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_ALFHEIMR].nActivationHeight = 850000;
        consensus.vUpgrades[Consensus::UPGRADE_ALFHEIMR].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_KNOWHERE].nActivationHeight = 916000;
        consensus.vUpgrades[Consensus::UPGRADE_KNOWHERE].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_WAKANDA].nActivationHeight = 1545000;
        consensus.vUpgrades[Consensus::UPGRADE_WAKANDA].nProtocolVersion = 170010;
        consensus.vUpgrades[Consensus::UPGRADE_ATLANTIS].nActivationHeight = 1760000; // 2021, May 10th
        consensus.vUpgrades[Consensus::UPGRADE_ATLANTIS].nProtocolVersion = 170010;

        consensus.nZawyLWMA3AveragingWindow = 60;
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000000000e45718e6cb");
        /**
         * The message start string should be awesome! Ⓢ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xc8;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04081b1f4f0d39e4bbb81c3fb654b0777b9ca5db9ef791e3b05c952d7b4cac2330a6e5d1cb5fcdc27124c387910dafa439e98848d3345a473c2390b33ceb234d7e");
        nDefaultPort = 16113;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        newTimeRule = 246600;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        // eh_epoch_1_endblock = 266000;
        // eh_epoch_2_startblock = 265983;
        eh_epoch_1_endtime = 1530187171;
        eh_epoch_2_starttime = 1530187141;

        nMasternodeCountDrift = 0;

        genesis = CreateGenesisBlock(
            1511111234,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000002d30"),
            ParseHex("00833951120ce20e80739287814a9799eb622ff95803e03c9bf389586f89a320860fbefd368df25762c40f21266a0c57cab9fd8aa3a3fd537a0efb659b544a6035d414bd67fdd7621ac708a6f320edcba0708d401e2f1eb75ec9a9d65069f4475bafdf013a9a3aad42413963785c64fe094b1ff57d1d68718d7e2f96985b362d21c211d0aa8ae107e9dbf5e94816793214df8f502eaceecb9a1cf5eace2a7920d49f62a374f7104f09e2e05630e93d79dbb453a218bf83cebbd73b97cd22c42ba3a7dd1a633b66c24714dd3d50f9837904a126aefaffcf0b65758a02792e706bf42e63889c56213eca83a7f21cfb61588d25b2ff635b35ca4cd4db090c32f9398488a2ce533395e3b2b79702dfcab88f751d3e42c3eb47832b3702574fd1e965a1e1bd78a6f9187cea9b36e53947e65bb9f03de9d067352dfb58c54a39d550e4bae343dc8067608770a8ca51f4f8c9bd0148c91097f725e5cb69305b35c7dd21999bd045290d6751d7d4a5e293c74313ea68a0204aca1298e68a04b97576ceadd9f7d85c70df89cc361c78121bbd1107a671c60f5b008fd77882a0e231cabd5f328d9af30501e719438f1461e6afb0804c35437a6a98baf26418cce91c82cf9c11137e5502462cb299f966733c5723a3fa3252180577fc9b628558b9d864b1a9a60cc1621397105db4065db6d197a16ed22db297691a184e01ee18f1e1863a7bc1850846c34e9626abf736de1354dd7ac04ff04bfba7a5a5fdabf0c5419c77df594b0349d23e9d300951a47f79c6f3f1422eace598d3aa56c3c514e0d5f634e5e045fcc92ff1dac796be38640a578d0a27139c8175a782f93eced2c4d52374e0a053bdf3fe1ce06d01ef72e630f74a4219b749554597205bcee765d137c6d692e79afa5a759627c1d200ec28f75deb474af611b0d7157259ea3299df2672a1d7009c4deaff93c06b6be194eeb7a83e45c51830236b050562d9b88cc3e0f2f8b0c33f4c7eff538b7d825512d45c5b4052b2bf4bf7d28261d1e7216f6613eda41f625dc4edebb501c478223b9febe378ffbb6a79ac035ff8b1bbaa0d437993c36e0a38203e96a7de11221e80454d3dcdbbd6cf6b4431d2b1540dab85f6d25e052cee3662d86be5975a41ae8b612aca7ad694e0e713c4bbd8ef089314ecae72f600b8b57504dfde7b15020a6e269ecee4b4b44080596298dfacea335dfb40531f6f6c8a65aef5e12a67abadedf23a326eb2ca580e0c822e005a9e912891b4b980c3c615b2808f6cb30e31c730cc20f4d33ecc262db364610a3f533303330239189350446188326f23ab362f596113f4ba90b803a86954222fe14da26c124e41d13e8cbbbcc7bb8a0cbf27c28dd7e4eb01b9936134e5bf7a256199ed5f1d6ccbc4e98fe96fedf93a270f71bab7178b7c1528025893336f900a5cfc00828f6020eb6d0de0b4520c0826d133d46b2593cf5a31a45274768678077adda80af5a08d25d712dced9f963d456ed949ced4be32710ff8a20486fafd81ee8953fe2cbdaa27a9df5ff2c90d6685cf0dfb641bef3b4712f1db889a299876eda91e0bc7e3fb1710c1c94851e5e7c6585cd762faa58f115e1a536851984bad87c202e0490c9d3342dae5831436cbf31895a0c6da8a76c2e551fffaae32fdfaf9036c4a90b60cca9ac911d3b2aa43938d8a6f5da30f0f7fd6e2d8da2c11b41295a050b27709da7daefc3311289193e164377785fce6d76be7af1ba6eb9fdcb5298bce7c69d172cf7412b5700e7149a97a51bcd2f20616d8856a82814b7fb01582a9fd0e71f0c5b84c7918ae15776b75b2e5b2f4945f682af7faa5051aaf9c12b435d2461ee711a65bc29216c97501f5491b9fd823bdfe181214d6c4d63954d3bb270a9da8ad3fe40c"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00068b35729d9d2b0c294ff1fe9af0094740524311a131de40e7f705e4c29a5b"));
        assert(genesis.hashMerkleRoot == uint256S("0xa524d6679f759fd4ff2938a104d8488bc89858e0b9a19541bc4f1a6438d08f90"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back(CDNSSeedData("dnsseed1.amitabha.xyz", "dnsseed1.amitabha.xyz")); //Amitabha seed node
        vSeeds.push_back(CDNSSeedData("dnsseed2.amitabha.xyz", "dnsseed2.amitabha.xyz")); //Amitabha seed node
        vSeeds.push_back(CDNSSeedData("dnsseed3.amitabha.xyz", "dnsseed3.amitabha.xyz")); //Amitabha seed node
        vSeeds.push_back(CDNSSeedData("dnsseed1.snowgem.org", "dnsseed1.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("dnsseed2.snowgem.org", "dnsseed2.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("dnsseed3.snowgem.org", "dnsseed3.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("dnsseed1.tent.app", "dnsseed1.tent.app")); //Tent seed node
        vSeeds.push_back(CDNSSeedData("dnsseed2.tent.app", "dnsseed2.tent.app")); //Tent seed node
        vSeeds.push_back(CDNSSeedData("dnsseed3.tent.app", "dnsseed3.tent.app")); //Tent seed node

        // guarantees the first 2 characters, when base58 encoded, are "s1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0x28};
        // guarantees the first 2 characters, when base58 encoded, are "s3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0x2D};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
		fHeadersFirstSyncingActive = false;
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (23000, uint256S("0x000000006b366d2c1649a6ebb4787ac2b39c422f451880bc922e3a6fbd723616"))
            (88000, uint256S("0x0000003ef01c0d1f954fdd738dac1b4f7191e6bee66ed8cb882d00d65fccd89b"))
            (770000, uint256S("0x0000033c44f81085a466f72d24104105caee912da72bdccc6d6f3c0d819ddc1a"))
            (874855, uint256S("0x000000cde6ea86e41c60ca32c06e7d1a0847bf533ecf0cd71b445ce81037f8cd"))
            (888888, uint256S("0x000003f40c40c23a58ca7d0255b994e7235e42a51bce730a68ef79e2157612da"))
            (1060000, uint256S("0x0000026612d48d0f47e9d39bfea738c2378e617067bf6b9d4c3031dff31c4e91"))
            (1720000, uint256S("0x000003dca02caa04cf1d1170e99e0ff045da3aa44fdd5f12954d060d9d0fdc2b"))
            (1861381, uint256S("0x00000ff129e63a7f89dc7fc5775020a5c2369a380bd2257dec7f32da9380e82c"))
            (2027480, uint256S("0x00001d39403ca8b6ee925d492654f9416254e0781532262fb1b323c85e970291")),
            1636792673,     // * UNIX timestamp of last checkpoint block
            3967568,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            2341            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (60 * 24))
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "s3d27MhkBRt3ha2UuxhjXaYF4DCnttTMnL1", /* main-index: 0*/
            "s3Wws6Mx3GHJkAe8QkNr4jhW28WU21Fp9gL", /* main-index: 1*/
            "s3QD18CKEA9Cw4kgnssnmk4rbf9Y3rU1uWG", /* main-index: 2*/
            "s3esoTmHdcXdDwCkoGSxC4YkfzBo1ySuher", /* main-index: 3*/
            "s3Q8NwoBv4aq9RRvqjT3LqN9TQnZrS2RdcV", /* main-index: 4*/
            "s3ix12RLstrzFEJKVsbLxCsPuUSjAqs3Bqp", /* main-index: 5*/
            "s3bCvm5zDv9KYFwHxaZjz2eKecEnbdFz98f", /* main-index: 6*/
            "s3UfvUuHahzTmYViL3KrGZeUPug69denBm3", /* main-index: 7*/
            "s3gmzNUmttwDJbUcpmW4gxVqHf3J58fDKpp", /* main-index: 8*/
            "s3YuWMW4Kpij7gW91WHLhjfi5Dwc7dKyPNn", /* main-index: 9*/
            "s3k2MaTdZyFBqyndrHdCDFnET5atCdC4iod", /* main-index: 10*/
            "s3YFHxL9euG89LMgPT5wGka4Ek8XVyw4FWG", /* main-index: 11*/
            "s3TKKkNnvBXphdv4ce84UKePdssWLHGBe1A", /* main-index: 12*/
            "s3PLrY7e7jzzAxnMY7A6GkjhkGc1CVkuEoi", /* main-index: 13*/
            "s3Ug8VAGcUijwD6QMhyFcCYXQEFABaA9VFy", /* main-index: 14*/
            "s3b4DAbbrTb4FPz3mHeyE89fUq6Liqg5vxX", /* main-index: 15*/
            "s3cM379BTJyCe5yJC4jkPn6qJwpZaHK2kXb", /* main-index: 16*/
            "s3TKWLar6bZEHppF4ZR1MbPuBfe33a1bHX9", /* main-index: 17*/
            "s3UpY6Q3T3v3F7MEpNDnV3rTucLEJkkHR4q", /* main-index: 18*/
            "s3eWx3DcwLiusTBfhWu6z7zM4TffaV1Ng9r", /* main-index: 19*/
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        // For our partner
        vFoundersRewardAddress2 = {
            "s3an7UoVwfga6fXsTvE46MenWDu8auRrUqd", /* main-index: 0*/
            "s3Zu8sebtKEteGETPLm69yf38PMyHWAYeQv", /* main-index: 1*/
            "s3Qeesfn1tuWhxKZ35aSZq7oVWq2LtBjBoa", /* main-index: 2*/
            "s3drQ1rpYKvxcEvtDnG3fP8NDLVjnes5SHN", /* main-index: 3*/
            "s3Uio17ZNu7ZcFk3sHmerN4Tt3Pg7uYteTm", /* main-index: 4*/
            "s3RVLe2j459YjtuAaBakMoG6dUzCU6rtfZ8", /* main-index: 5*/
            "s3f16EZXRchBvZW1ESKUkTcLRWCERP7HBkc", /* main-index: 6*/
            "s3PqWHjG4aLgQWBmA2aWUhv6WrH6FDSN6KG", /* main-index: 7*/
            "s3V5NJFiPrqgXXuoWo5h4c8pbhwTupyJmMy", /* main-index: 8*/
            "s3bc2Af4Aktxz8p25YCX63Hk8pZGMKr2r63", /* main-index: 9*/
            "s3UuTKYhbbRK4NPKSNjnAxvJaTAgJBgM92S", /* main-index: 10*/
            "s3MyuAGqcjUHSF7yN8apLSEWPK19CdKT6nV", /* main-index: 11*/
            "s3XVKYBjQ9hv5NKxKrtyjFmGeFrwSsdwscz", /* main-index: 12*/
            "s3Vjj29KCYoBFKFy11QREGGfPePAe42JX3m", /* main-index: 13*/
            "s3YVbu8hBDVh3pJYUX76tejTg6Dgb9uXsR6", /* main-index: 14*/
            "s3cAonYtPtumWp1c5qAhUQtYLWxe94yw6w9", /* main-index: 15*/
            "s3RDMvMZFmVBDWQT6ooAVVd66SL6Hgs1B4G", /* main-index: 16*/
            "s3TB2uqZpSEK7C5M9dhJYfzKoXzqXRztSMq", /* main-index: 17*/
            "s3cZdRCGyxnzkzgkMPGXrS7YHRPNAmEb87p", /* main-index: 18*/
            "s3fKKBm4kk8LtNhziDYET4Bg5ZxYSHE6AkP", /* main-index: 19*/
        };

        //@TODO - txid update wallet list
        // Treasury reward script expects a vector of 2-of-3 multisig addresses
        vTreasuryRewardAddress = {
            "s3STyRjwtffPWcfQzawkHEcDVVeYCCZvKAw", /* main-index: 0*/
            "s3QiJcoCmWewixcVVAnt3LoxY3BSNNx8YhM", /* main-index: 1*/
            "s3b65JSBYsikDESqv1MqgWhn51adyMd2fzY", /* main-index: 2*/
            "s3fRjrKkH6yVj5rPTU2N8X7pMKnuyWS46Qb", /* main-index: 3*/
            "s3XYB7NcXsZWb6MX8jsCwefdAU8BnTQvg7x", /* main-index: 4*/
            "s3dcca3UyRyH56osUEWMRGTS7h9YwXj6Kqq", /* main-index: 5*/
            "s3c5hmNVHNn5Gb4JzqdUH7iDubSjUSfUD9i", /* main-index: 6*/
            "s3b3EPcrRvkcgcTVVqEhz8HtF3KrKGu5m3h", /* main-index: 7*/
            "s3chG3hQjiorgYRACd42S7p4zzWoGaYyVfN", /* main-index: 8*/
            "s3aVCqrd3qt6EASt9KpGnLtKRQkjAPbu5qC", /* main-index: 9*/
            "s3jPRn5CmFGVfKENbjbE3U4NwfXaBN4oH2C", /* main-index: 10*/
            "s3gUK3Vv9gF1hT4XoGfZju1DFmvoGvhEuVH", /* main-index: 11*/
            "s3b2SGjybAV8vhZeKuXz1vFURpP3CVxyrnq", /* main-index: 12*/
            "s3inM3mAzVwseCPJzMDgwmNyXDTRA9Pjn5h", /* main-index: 13*/
            "s3PiBVbSkPeV6VNXJf1HD2hbsyXRGXDN1q5", /* main-index: 14*/
            "s3aejhtm6xYdB5wEdSyJUsJ79CqqGmeC7Y6", /* main-index: 15*/
            "s3TTYpvWazeMSbvMHvmTfxsJakWz7cEhcET", /* main-index: 16*/
            "s3f4F2nsXzgJt1K2drpcGnDiVZedvfMY6H1", /* main-index: 17*/
            "s3ZGMfXNrYRLEy58bGGacyc7CzsXt6C8brn", /* main-index: 18*/
            "s3S7Z17UfNmRkxoNkRaLuyXpckMv9DEr4cz", /* main-index: 19*/
        };
        nPoolMaxTransactions = 3;
        strSporkKey = "045da9271f5d9df405d9e83c7c7e62e9c831cc85c51ffaa6b515c4f9c845dec4bf256460003f26ba9d394a17cb57e6759fe231eca75b801c20bccd19cbe4b7942d";

        strObfuscationPoolDummyAddress = "s1eQnJdoWDhKhxDrX8ev3aFjb1J6ZwXCxUT";
        nStartMasternodePayments = 1523750400; //2018-04-15
        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
        masternodeProtectionBlock = 590000;
        masternodeCollateral = 10000;
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "SNGT";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 8000;
        consensus.nSubsidyHalvingInterval = 60 * 24 * 365 * 4;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nTimeshiftPriv = 1 * 60; // 60 blocks in testnet
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 13000;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 8100;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 8100;
        consensus.vUpgrades[Consensus::UPGRADE_DIFA].nActivationHeight = 8300;
        consensus.vUpgrades[Consensus::UPGRADE_DIFA].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_ALFHEIMR].nActivationHeight = 8500;
        consensus.vUpgrades[Consensus::UPGRADE_ALFHEIMR].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_KNOWHERE].nActivationHeight = 12600;
        consensus.vUpgrades[Consensus::UPGRADE_KNOWHERE].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_WAKANDA].nActivationHeight = 22500;
        consensus.vUpgrades[Consensus::UPGRADE_WAKANDA].nProtocolVersion = 170010;
        consensus.vUpgrades[Consensus::UPGRADE_ATLANTIS].nActivationHeight = 28610;
        consensus.vUpgrades[Consensus::UPGRADE_ATLANTIS].nProtocolVersion = 170010;
        consensus.nMasternodePaymentsStartBlock = 1500;
        consensus.nMasternodePaymentsIncreasePeriod = 200;
        consensus.nZawyLWMA3AveragingWindow = 60;

		// The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000d");
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 26113;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endtime = 1529432082;
        eh_epoch_2_starttime = 1529402266;
        // eh_epoch_1_endblock = 7600;
        // eh_epoch_2_startblock = 7583;

		
    	genesis = CreateGenesisBlock(
            1477774444,
            uint256S("0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("005723faab5aab574962e0b981aa919d6d16fc4d820b208e873738535ddf58b70ef5d2d049c45af6a21923cd95321e4c7dddf83df3fa1e416bb9d2bedfe1923d51adb3a6dbfaf34cac34b9b151ade9e36354489d06448ab4f5fb6987e275a41b3563f88b8d519eedd20df637c11aa600b3fdf24533bc44e1eda9bb90e3890739d3c2c4518409144dc60d9e445eda06b99f2a3b56d9dcf25a6a337d6c8ec66e18475cc638f67fd58b0273d44321c61c4ac0feb2e3a86ddc3590773dfa00171a4bbd51ef1259ad86531151371bd5a2dd313c301a3920f226908ea57a3d025fc3c3ab2cc45f8e43b61e39b3d17468ffbf763875042b5a44ea4de232a83b0d9e5b2258c4a973bbb3b1145139e823299fbfbc1e2294dfde3e0e3a03a3c2d43b893d30991d567ae06240694712d4614ac91637e4c0fb6780e166645f6cf8520667c1dee4d3c350e0762b45d22e5e78743e6b04035365fb6d72e3cbfb14b055fb3d982e88087b196f210669c8d022f8efd451564783e2fd62d07ffb63df22a249faae2046415da5f5078ecf8e56d3217e5cf5277efcd5a78a4733c842a36bdff7c4cd07622b6a8c08ef8666cd865c0b3f17e0a79f1ea8f9991936538d6d151e66da665c65505f4a0c675f730ebd259bd55d22ad79446bd27a02ba7cb5b1a16c85cdb4ec121f542892170a638d140cb97b62ecb0b097f9e9fd2f53010361e4465cf98c9be8fcf2c023545cd73eb21a7ece26227a36b0dc670bbdb6554ba9def0d9601e1b4b1817381ba1f7978b66e2f624deec4239294bdd9d26592462f3a4712fe4d3c6a306602cfb2795d4dcbbf23609d791b8f64f458788af10e5e1b5f9788218e765e42018fd5cacd73f0b5fcf33d766e80f9d75f30f0f4a0be1efbaab779e29c88a24d641a7b2b96c09327d74169434defb29f0c37d15d7b996f84c2b62105e87e2010b9ec6e5c2d68521bde0efd8f0d7a2896e9575b257f9c3c88569fa25fbbe56d1a8fc3909cf217c45ea1ce691c0d52df541aae9158b9e496efe2a8f5d86402650361d3ae455dbb6eec4c0da48bbfae4c31943060e17c650e89178da95436229aed53d6e179bffb7ff2356feec3615ac40b0c5c28dc8abd534c3c1d351512a3f1ae2d719221bc5607451be63ef8db62c0f02743599bd2daa6db83bc6ec3475fc2873bfa2a23dffee01f0821b301a076d9744650abd7b6f81b95cfcd50c03bf2e7f791d70c3239ad490a0dddd21dacd779d0e175e577627eb89918c3be25aa17a8fb99a249e37981847e569758a3cf71c0365a2467eaa76ab5938954d0d1a7feec99c7137a63844430eec95819d51733baf4632d614feddc1ddfa7e249a995b562a33211586e30d38390e726722498dd679f567ee9d97c1437e5f3d2a06d73ed1568968ef4ec35cfaf4be9619233fc2c201ca9c1a359658c8e62c558a4c66c9ce7769f918fb4207236a769a7825eef5663ca27df7170751797917040fdfd865533929f1225188f8b27ca6916bbd6717061fb4fc079e6763413bd240d750da193a1793890e21d4a6ae5ec9ace86e9813451968575107278bdd2f3719ba88f7e6f0bb64ca64d653e99503bf75ff6eef30d6f46cdef56cb7d416b42ec2be3fdd0f9939fb9a476b4e7ff39c1b1782eec59381e4e269946f5d45210202a6ba57cedb8156f9d0c0ee1d0890a90775ec9808cd75d2824da3fed85436409569e05aab3a972fa107c65227588cefd2e2c24211004d33823fcc5b4a3b18a903a0e04a8b9fe856d43322d8b7edbaf351c34f10a7871a024681d50c15e2724fb55abe4c5e372e671eb5e17414dad4fef09e181775dc94de39967c06411654feec10493e768338333af19bdc89defd3f6a252a3d91ba4dde3be3a4d7634caeb77d058cfdb1c86e"),
            0x2007ffff, 4, 0);
			
		consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0739bced3341885cf221cf22b5e91cdb0f5da3cb34da982167c4c900723c725a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("abctoxyz.site", "dnsseed.testnet.abctoxyz.site")); // Snowgem
        vSeeds.push_back(CDNSSeedData("snowgem.org", "testnet.explorer.snowgem.org")); // Snowgem

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

		checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1477774444,  // * UNIX timestamp of last checkpoint block
            0,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Founders reward script expects a vector 900of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi",
            "t27puhwCQgYRenkoNSFrhfeAPyfk1LpZbu9"
        };

        vFoundersRewardAddress2 = {
            "t2DuepruJtHNZpjsaPneoRsGTBLDG5hhUmj",
            "t27uXCcSZd1qSWhFArDbwVBHuuiGscY4DDM"
        };

        vTreasuryRewardAddress = {
            "t2Vck95daFLBrvcgfxCT43uBsicECsn6wqe"
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());

        nStartMasternodePayments = 1520121600; //2018-03-04
        masternodeProtectionBlock = 7900;
        masternodeCollateral = 10;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nTimeshiftPriv = 1 * 60; // 60 blocks
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 26114;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_1_endtime = 1;
        eh_epoch_2_starttime = 1;

    	genesis = CreateGenesisBlock(
            1296688602,
            uint256S("000000000000000000000000000000000000000000000000000000000000000c"),
            ParseHex("0a8ede36c2a99253574258d60b5607d65d6f10bb9b8df93e5e51802620a2b1f503e22195"),
            0x200f0f0f, 4, 0);
			
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x047c30b7734dbad47335383f9997a5d5d8d5e4b46fd0f02f23ec4fca27651b41"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2f9nkUG1Xe2TrQ4StHKcxUgLGuYszo8iS4" };
        vFoundersRewardAddress2 = { "t2f9nkUG1Xe2TrQ4StHKcxUgLGuYszo8iS4" };
        vTreasuryRewardAddress = { "t2f9nkUG1Xe2TrQ4StHKcxUgLGuYszo8iS4" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit)
    {
        consensus.nPowMaxAdjustDown = nPowMaxAdjustDown;
        consensus.nPowMaxAdjustUp = nPowMaxAdjustUp;
        consensus.powLimit = powLimit;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

int32_t MAX_BLOCK_SIZE(int32_t height)
{
    if ( height >= Params().GetConsensus().vUpgrades[Consensus::UPGRADE_DIFA].nActivationHeight )
        return(MAX_BLOCK_SIZE_AFTER_UPGRADE);
    else return(MAX_BLOCK_SIZE_BEFORE_UPGRADE);
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetFoundersRewardRepeatInterval();
    // assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = (nHeight / addressChangeInterval) % vFoundersRewardAddress.size();
    if(!NetworkUpgradeActive(nHeight, Params().GetConsensus(), Consensus::UPGRADE_ATLANTIS))
    {
        return vFoundersRewardAddress[i];
    }
    else
    {
        return nHeight % 2 == 0 ? vFoundersRewardAddress[i] : vFoundersRewardAddress2[i];
    }
    
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

// Block height must be >0
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetTreasuryRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetFoundersRewardRepeatInterval();
    // assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vTreasuryRewardAddress.size()) / vTreasuryRewardAddress.size();
    size_t i = (nHeight / addressChangeInterval) % vTreasuryRewardAddress.size();
    return vTreasuryRewardAddress[i];
}

// Block height must be >0
// The treasury reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetTreasuryRewardScriptAtHeight(int nHeight) const {
    CTxDestination address = DecodeDestination(GetTreasuryRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetTreasuryRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vTreasuryRewardAddress.size());
    return vTreasuryRewardAddress[i];
}

bool CChainParams::GetCoinbaseProtected(int height) const{
    if(!NetworkUpgradeActive(height, Params().GetConsensus(), Consensus::UPGRADE_ATLANTIS))
    {
        return true;
    }
    else
    {
        return false;
    }
}

int validEHparameterList(EHparameters *ehparams, unsigned int blocktime, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blocktime>=params.eh_epoch_2_start() && blocktime>params.eh_epoch_1_end()){
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }
    if(blocktime<params.eh_epoch_2_start()){
        ehparams[0]=params.eh_epoch_1_params();
        return 1;
    }
    ehparams[0]=params.eh_epoch_2_params();
    ehparams[1]=params.eh_epoch_1_params();
    return 2;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit) {
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit);
}
