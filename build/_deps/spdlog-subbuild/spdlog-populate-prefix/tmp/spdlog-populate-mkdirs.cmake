# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/moon/UPT-Outpost/build/_deps/spdlog-src"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-build"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/tmp"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/src/spdlog-populate-stamp"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/src"
  "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/src/spdlog-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/src/spdlog-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/moon/UPT-Outpost/build/_deps/spdlog-subbuild/spdlog-populate-prefix/src/spdlog-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
