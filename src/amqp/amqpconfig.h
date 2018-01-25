// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2017-2018 The SnowGem developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SNOWGEM_AMQP_AMQPCONFIG_H
#define SNOWGEM_AMQP_AMQPCONFIG_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <stdarg.h>
#include <string>

#if ENABLE_PROTON
#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/default_container.hpp>
#include <proton/message.hpp>
#include <proton/message_id.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/thread_safe.hpp>
#include <proton/tracker.hpp>
#include <proton/transport.hpp>
#include <proton/types.hpp>
#include <proton/url.hpp>
#endif

#include "primitives/block.h"
#include "primitives/transaction.h"

#endif // SNOWGEM_AMQP_AMQPCONFIG_H
