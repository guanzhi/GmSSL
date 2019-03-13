/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include <stdint.h>

int aesctr256 (uint8_t *out, const uint8_t *sk, const void *counter, int bytes);

int aesctr256_zeroiv (uint8_t *out, const uint8_t *sk, int bytes);
