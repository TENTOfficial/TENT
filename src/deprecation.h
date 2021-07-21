// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2017-2018 The SnowGem developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SNOWGEM_DEPRECATION_H
#define SNOWGEM_DEPRECATION_H

// Deprecation policy:
// * Shut down 100 weeks' worth of blocks after the estimated release block height.
// * A warning is shown during the 2 weeks' worth of blocks prior to shut down.

static const int APPROX_RELEASE_HEIGHT = 1870000;

static const int WEEKS_UNTIL_DEPRECATION = 100;
static const int DEPRECATION_HEIGHT = APPROX_RELEASE_HEIGHT + (WEEKS_UNTIL_DEPRECATION * 7 * 24 * 60);

// Number of blocks before deprecation to warn users
static const int DEPRECATION_WARN_LIMIT = 96 * 24 * 60; // 4 weeks

/**
 * Checks whether the node is deprecated based on the current block height, and
 * shuts down the node with an error if so (and deprecation is not disabled for
 * the current client version). Warning and error messages are sent to the debug
 * log, the metrics UI, and (if configured) -alertnofity.
 *
 * fThread means run -alertnotify in a free-running thread.
 */
void EnforceNodeDeprecation(int nHeight, bool forceLogging=false, bool fThread=true);

#endif // SNOWGEM_DEPRECATION_H
