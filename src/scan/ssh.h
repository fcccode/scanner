#pragma once

#include "pch.h"
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <stdio.h>

#pragma comment(lib, "libssh2.lib")

int IsSsh(int argc, char * argv[]);
