// Copyright (c) 2016 The Zcash developers
// Copyright (c) 2017-2018 The SnowGem developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "snowgem/JoinSplit.hpp"
#include "snowgem/Note.hpp"
#include "snowgem/NoteEncryption.hpp"

CWalletTx GetValidReceive(ZCJoinSplit& params,
                          const libsnowgem::SpendingKey& sk, CAmount value,
                          bool randomInputs);
libsnowgem::Note GetNote(ZCJoinSplit& params,
                       const libsnowgem::SpendingKey& sk,
                       const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSpend(ZCJoinSplit& params,
                        const libsnowgem::SpendingKey& sk,
                        const libsnowgem::Note& note, CAmount value);
