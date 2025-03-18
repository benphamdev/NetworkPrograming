#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include <stdarg.h>
#include <time.h>
#include <stddef.h>  // for size_t

// Function declarations - make consistent with common.h
void debug_log(const char *format, ...);
uint16_t chksum(const unsigned short *buf, size_t buflen);
uint16_t calculate_checksum(const unsigned short *buf, size_t buflen);
char* read_html_file(void);
void print_packet_content(unsigned char *buffer, int size);
void error(const char *msg);

#endif
