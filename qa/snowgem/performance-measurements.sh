#!/bin/bash
set -u


DATADIR=./benchmark-datadir
SHA256CMD="$(command -v sha256sum || echo shasum)"
SHA256ARGS="$(command -v sha256sum >/dev/null || echo '-a 256')"

function snowgem_rpc {
    ./src/snowgem-cli -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 "$@"
}

function snowgem_rpc_slow {
    # Timeout of 1 hour
    snowgem_rpc -rpcclienttimeout=3600 "$@"
}

function snowgem_rpc_veryslow {
    # Timeout of 2.5 hours
    snowgem_rpc -rpcclienttimeout=9000 "$@"
}

function snowgem_rpc_wait_for_start {
    snowgem_rpc -rpcwait getinfo > /dev/null
}

function snowgemd_generate {
    snowgem_rpc generate 101 > /dev/null
}

function extract_benchmark_datadir {
    if [ -f "$1.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
$2  $1.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "$1.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        snowgemd_stop
        echo
        echo "Please download it and place it in the base directory of the repository."
        exit 1
    fi
    xzcat "$1.tar.xz" | tar x
}

function use_200k_benchmark {
    rm -rf benchmark-200k-UTXOs
    extract_benchmark_datadir benchmark-200k-UTXOs dc8ab89eaa13730da57d9ac373c1f4e818a37181c1443f61fd11327e49fbcc5e
    DATADIR="./benchmark-200k-UTXOs/node$1"
}

function snowgemd_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to snowgemd_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/snowgem.conf"
    esac
    ./src/snowgemd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    SNOWGEMD_PID=$!
    snowgem_rpc_wait_for_start
}

function snowgemd_stop {
    snowgem_rpc stop > /dev/null
    wait $SNOWGEMD_PID
}

function snowgemd_massif_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to snowgemd_massif_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/snowgem.conf"
    esac
    rm -f massif.out
    valgrind --tool=massif --time-unit=ms --massif-out-file=massif.out ./src/snowgemd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    SNOWGEMD_PID=$!
    snowgem_rpc_wait_for_start
}

function snowgemd_massif_stop {
    snowgem_rpc stop > /dev/null
    wait $SNOWGEMD_PID
    ms_print massif.out
}

function snowgemd_valgrind_start {
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR/regtest"
    touch "$DATADIR/snowgem.conf"
    rm -f valgrind.out
    valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/snowgemd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    SNOWGEMD_PID=$!
    snowgem_rpc_wait_for_start
}

function snowgemd_valgrind_stop {
    snowgem_rpc stop > /dev/null
    wait $SNOWGEMD_PID
    cat valgrind.out
}

function extract_benchmark_data {
    if [ -f "block-107134.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
4bd5ad1149714394e8895fa536725ed5d6c32c99812b962bfa73f03b5ffad4bb  block-107134.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "block-107134.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        snowgemd_stop
        echo
        echo "Please generate it using qa/snowgem/create_benchmark_archive.py"
        echo "and place it in the base directory of the repository."
        echo "Usage details are inside the Python script."
        exit 1
    fi
    xzcat block-107134.tar.xz | tar x -C "$DATADIR/regtest"
}


if [ $# -lt 2 ]
then
    echo "$0 : At least two arguments are required!"
    exit 1
fi

# Precomputation
case "$1" in
    *)
        case "$2" in
            verifyjoinsplit)
                snowgemd_start "${@:2}"
                RAWJOINSPLIT=$(snowgem_rpc zcsamplejoinsplit)
                snowgemd_stop
        esac
esac

case "$1" in
    time)
        snowgemd_start "${@:2}"
        case "$2" in
            sleep)
                snowgem_rpc zcbenchmark sleep 10
                ;;
            parameterloading)
                snowgem_rpc zcbenchmark parameterloading 10
                ;;
            createjoinsplit)
                snowgem_rpc zcbenchmark createjoinsplit 10 "${@:3}"
                ;;
            verifyjoinsplit)
                snowgem_rpc zcbenchmark verifyjoinsplit 1000 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                snowgem_rpc_slow zcbenchmark solveequihash 50 "${@:3}"
                ;;
            verifyequihash)
                snowgem_rpc zcbenchmark verifyequihash 1000
                ;;
            validatelargetx)
                snowgem_rpc zcbenchmark validatelargetx 5
                ;;
            trydecryptnotes)
                snowgem_rpc zcbenchmark trydecryptnotes 1000 "${@:3}"
                ;;
            incnotewitnesses)
                snowgem_rpc zcbenchmark incnotewitnesses 100 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                snowgem_rpc zcbenchmark connectblockslow 10
                ;;
            sendtoaddress)
                snowgem_rpc zcbenchmark sendtoaddress 10 "${@:4}"
                ;;
            loadwallet)
                snowgem_rpc zcbenchmark loadwallet 10 
                ;;
            listunspent)
                snowgem_rpc zcbenchmark listunspent 10
                ;;
            *)
                snowgemd_stop
                echo "Bad arguments to time."
                exit 1
        esac
        snowgemd_stop
        ;;
    memory)
        snowgemd_massif_start "${@:2}"
        case "$2" in
            sleep)
                snowgem_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                snowgem_rpc zcbenchmark parameterloading 1
                ;;
            createjoinsplit)
                snowgem_rpc_slow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                snowgem_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                snowgem_rpc_slow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                snowgem_rpc zcbenchmark verifyequihash 1
                ;;
            validatelargetx)
                snowgem_rpc zcbenchmark validatelargetx 1
                ;;
            trydecryptnotes)
                snowgem_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                snowgem_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                snowgem_rpc zcbenchmark connectblockslow 1
                ;;
            sendtoaddress)
                snowgem_rpc zcbenchmark sendtoaddress 1 "${@:4}"
                ;;
            loadwallet)
                # The initial load is sufficient for measurement
                ;;
            listunspent)
                snowgem_rpc zcbenchmark listunspent 1
                ;;
            *)
                snowgemd_massif_stop
                echo "Bad arguments to memory."
                exit 1
        esac
        snowgemd_massif_stop
        rm -f massif.out
        ;;
    valgrind)
        snowgemd_valgrind_start
        case "$2" in
            sleep)
                snowgem_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                snowgem_rpc zcbenchmark parameterloading 1
                ;;
            createjoinsplit)
                snowgem_rpc_veryslow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                snowgem_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                snowgem_rpc_veryslow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                snowgem_rpc zcbenchmark verifyequihash 1
                ;;
            trydecryptnotes)
                snowgem_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                snowgem_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                snowgem_rpc zcbenchmark connectblockslow 1
                ;;
            *)
                snowgemd_valgrind_stop
                echo "Bad arguments to valgrind."
                exit 1
        esac
        snowgemd_valgrind_stop
        rm -f valgrind.out
        ;;
    valgrind-tests)
        case "$2" in
            gtest)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/snowgem-gtest
                cat valgrind.out
                rm -f valgrind.out
                ;;
            test_bitcoin)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/test/test_bitcoin
                cat valgrind.out
                rm -f valgrind.out
                ;;
            *)
                echo "Bad arguments to valgrind-tests."
                exit 1
        esac
        ;;
    *)
        echo "Invalid benchmark type."
        exit 1
esac

# Cleanup
rm -rf "$DATADIR"
