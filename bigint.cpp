#include "bigint.h"

void Int256ToBytes(mp::uint256_t const& i, uint8_t* output, size_t len) {
	auto count = i.backend().size();
	auto tsize = sizeof(mp::limb_type);
	auto copy_count = count * tsize;
	if (len < count * tsize)
		throw std::runtime_error("len < count * tsize");
	memcpy(output, i.backend().limbs(), copy_count);
	if (len > copy_count) {
		memset(output + copy_count, 0, len - copy_count);
	}
}

mp::uint256_t BytesToInt256(uint8_t const* output, size_t len) {
	if (len % sizeof(mp::limb_type))
		throw std::runtime_error("len % sizeof(mp::limb_type)");
	mp::uint256_t i;
	uint32_t size = (uint32_t)len / sizeof(mp::limb_type);
	i.backend().resize(size, size);
	memcpy(i.backend().limbs(), output, len);
	i.backend().normalize();
	return i;
}