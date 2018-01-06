Snowgem 1.0.0
=============

What is Snowgem?
--------------

[Snowgem](https://snowgem.org/) is an implementation of the "Zerocash" protocol.
Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. Technical details are available
in our [Protocol Specification](https://github.com/snowgem/zips/raw/master/protocol/protocol.pdf).

This software is the Snowgem client. It downloads and stores the entire history
of Snowgem transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

Security Warnings
-----------------

See important security warnings on the
[Security Information page](https://snowgem.org/support/security/).

**Snowgem is experimental and a work-in-progress.** Use at your own risk.

Deprecation Policy
------------------

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height and can be explicitly disabled.

Building
-----------------

### Install dependencies

On Ubuntu/Debian-based systems:

```
$ sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python python-zmq \
      zlib1g-dev wget bsdmainutils automake curl
```

On Fedora-based systems:

```
$ sudo dnf install \
      git pkgconfig automake autoconf ncurses-devel python \
      python-zmq wget gtest-devel gcc gcc-c++ libtool patch curl
```

### Check GCC version

gcc/g++ 4.9 or later is required. Zcash has been successfully built using gcc/g++ versions 4.9 to 7.x inclusive. Use ```g++ --version``` to check which version you have.

On Ubuntu Trusty, if your version is too old then you can install gcc/g++ 4.9 as follows:

```
$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
$ sudo apt-get update
$ sudo apt-get install g++-4.9
```

### Check binutils version

binutils 2.22 or later is required. Use as ```--version``` to check which version you have, and upgrade if necessary.

### Build

Ensure you have successfully installed all system package dependencies as described above. Then run the build, e.g.:
```
$ git clone https://github.com/snowgem/snowgem.git
$ cd snowgem/
$ chmod +x zcutil/build.sh depends/config.guess depends/config.sub autogen.sh share/genbuild.sh src/leveldb/build_detect_platform
$ ./zcutil/build.sh --disable-rust -j$(nproc)
```

This should compile our dependencies and build zcashd. (Note: if you don't have nproc, then substitute the number of cores on your system. If the build runs out of memory, try again without the ```-j``` argument, i.e. just ```./zcutil/build.sh --disable-rust```. )

### Fetch the software and parameter files

Fetch our repository with git and run ```fetch-params.sh``` like so:

```
$ chmod +x zcutil/fetch-params.sh
$ ./zcutil/fetch-params.sh
```
This will fetch our Sprout proving and verifying keys (the final ones created in the [Parameter Generation Ceremony](https://github.com/zcash/mpc)), and place them into ```~/.snowgem-params/```. These keys are just under 911MB in size, so it may take some time to download them.

The message printed by ```git checkout``` about a "detached head" is normal and does not indicate a problem.

--------
### Need Help?

* See the documentation at the [refer from Zcash Wiki](https://github.com/zcash/zcash/wiki/1.0-User-Guide)
  for help and more information.
* Ask for help on the [Snowgem](https://forum.snowgem.org/) forum or contact us via email support@snowgem.org

Participation in the Snowgem project is subject to a
[Code of Conduct](code_of_conduct.md).

License
-------

For license information see the file [COPYING](COPYING).
