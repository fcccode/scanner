#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <yaml.h>
#pragma comment (lib,"yaml.lib")

extern "C" YAML_DECLARE(int) yaml_parser_update_buffer(yaml_parser_t * parser, size_t length);

int get_version(void);
int scanner(int argc, char * argv[]);
int parser(int argc, char * argv[]);
int dumper(int argc, char * argv[]);






