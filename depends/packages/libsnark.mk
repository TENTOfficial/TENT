package=libsnark
$(package)_download_path=https://github.com/Snowgem/$(package)/releases/download/v20180211/
$(package)_file_name=$(package)-$($(package)_git_commit).tar.gz

$(package)_sha256_hash=3ee1b9410a3a3d7682076775f720aa90bc00fdf475f508127b7be21756ba7b0c
$(package)_git_commit=876e8f6f47f3caaa2d8d103b6b32055300d298f1

define $(package)_set_vars
    $(package)_build_env=CC="$($(package)_cc)" CXX="$($(package)_cxx)"
    $(package)_build_env+=CXXFLAGS="$($(package)_cxxflags) -DBINARY_OUTPUT -DSTATICLIB -DNO_PT_COMPRESSION=1 "
endef

$(package)_dependencies=libgmp libsodium

define $(package)_build_cmds
  CXXFLAGS="-fPIC -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1" $(MAKE) lib DEPINST=$(host_prefix) CURVE=ALT_BN128 MULTICORE=1 NO_PROCPS=1 NO_GTEST=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT OPTFLAGS="-O2"
endef

define $(package)_stage_cmds
    $(MAKE) install STATIC=1 DEPINST=$(host_prefix) PREFIX=$($(package)_staging_dir)$(host_prefix) CURVE=ALT_BN128 NO_SUPERCOP=1
endef
