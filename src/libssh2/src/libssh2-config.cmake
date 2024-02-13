# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

include("${CMAKE_CURRENT_LIST_DIR}/libssh2-targets.cmake")

# Alias for either shared or static library
if(NOT TARGET libssh2::libssh2)
  add_library(libssh2::libssh2 ALIAS libssh2::libssh2_shared)
endif()

# Compatibility alias
if(NOT TARGET Libssh2::libssh2)
  add_library(Libssh2::libssh2 ALIAS libssh2::libssh2_shared)
endif()
