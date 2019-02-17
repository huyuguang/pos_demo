#pragma once

#include "public.h"

void Int256ToBytes(mp::uint256_t const& i, uint8_t* output, size_t len);

mp::uint256_t BytesToInt256(uint8_t const* output, size_t len);