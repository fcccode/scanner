# Install script for directory: D:/git/github/windows/tools/scanner/src/lib/libssh2

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/libssh2")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/libssh2" TYPE FILE FILES
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/COPYING"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/NEWS"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/README"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/RELEASE-NOTES"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/docs/AUTHORS"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/docs/BINDINGS.md"
    "D:/git/github/windows/tools/scanner/src/lib/libssh2/docs/HACKING.md"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("D:/git/github/windows/tools/scanner/src/libssh2/src/cmake_install.cmake")
  include("D:/git/github/windows/tools/scanner/src/libssh2/example/cmake_install.cmake")
  include("D:/git/github/windows/tools/scanner/src/libssh2/tests/cmake_install.cmake")
  include("D:/git/github/windows/tools/scanner/src/libssh2/docs/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "D:/git/github/windows/tools/scanner/src/libssh2/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
