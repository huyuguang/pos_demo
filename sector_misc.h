#pragma once

#include "public.h"
#include "bigint.h"
#include "sha256_compress.h"
#include <boost/iostreams/detail/ios.hpp> // streamsize.
#include <boost/iostreams/categories.hpp>

struct SectorItem {
	SectorItem() {}

	SectorItem(std::string s) {
		s.resize(32);
		for (size_t i = 0; i < 8; ++i) {
			uint8_t const* p = (uint8_t const*)s.data() + i * 4;
			data[i] = ReadBE32(p);
		}
	}

	SectorItem(uint64_t n) {
		data[0] = (uint32_t)n;
		data[1] = (uint32_t)(n >> 32);
		for (size_t i = 2; i < 8; ++i) {
			data[i] = 0;
		}
	}

	bool operator==(SectorItem const& v) const {
		return memcmp(data, v.data, sizeof(data)) == 0;
	}
	bool operator!=(SectorItem const& v) const {
		return memcmp(data, v.data, sizeof(data)) != 0;
	}
	bool operator<(SectorItem const& v) const {
		return memcmp(data, v.data, sizeof(data)) < 0;
	}
	std::string to_string() const {
		std::ostringstream oss;
		for (size_t i = 0; i < 8; ++i) {
			oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << data[i];
			oss << ", ";
		}
		auto str = oss.str();
		str.pop_back();
		str.pop_back();
		return str;
	}

	uint64_t get_parent_x(uint64_t n) const {
		if (n == 0) return 0;
		return n - 1; // use dn_1 directly
	}

	uint64_t get_parent_y(uint64_t n) const {
		if (n == 0) return 0;
		std::array<uint64_t, 4> var_x;
		for (size_t i = 0; i < 4; ++i) {
			var_x[i] = data[i * 2];
			var_x[i] += (uint64_t)data[i * 2 + 1] << 32;
		}

		// xor to one uint64_x
		for (size_t i = 1; i < 4; ++i) {
			var_x[0] = var_x[0] ^ var_x[i];
		}

		return var_x[0] % n;
	}

	uint32_t data[8];

	static SectorItem CompressTwo(SectorItem const& a, SectorItem const& b) {
		uint32_t data[16];
		for (size_t i = 0; i < 8; ++i) {
			data[i] = a.data[i];
			data[i + 8] = b.data[i];
		}
		SectorItem ret;
		Sha256Compress2(data, ret.data);
		return ret;
	}

	static void CompressTwo(SectorItem const& a, SectorItem const& b,
		SectorItem* ret) {
		uint32_t data[16];
		for (size_t i = 0; i < 8; ++i) {
			data[i] = a.data[i];
			data[i + 8] = b.data[i];
		}
		Sha256Compress2(data, ret->data);
	}

	static SectorItem Xor(SectorItem const& a, SectorItem const& b) {
		SectorItem ret;
		for (size_t i = 0; i < 8; ++i) {
			ret.data[i] = a.data[i] ^ b.data[i];
		}
		return ret;
	}

	static void Xor(SectorItem const& a, SectorItem const& b, SectorItem* ret) {
		for (size_t i = 0; i < 8; ++i) {
			ret->data[i] = a.data[i] ^ b.data[i];
		}
	}
};

struct SectorProof {
	SectorItem node_c;
	SectorItem node_cx;
	SectorItem node_cy;
	SectorItem node_cyx;
	SectorItem node_cyy;
	std::vector<SectorItem> mkl_path_c;

	std::string to_string() const {
		std::string ret;
		ret += "node_c: " + node_c.to_string() + "\n";
		ret += "node_cx: " + node_cx.to_string() + "\n";
		ret += "node_cy: " + node_cy.to_string() + "\n";
		ret += "node_cyx: " + node_cyx.to_string() + "\n";
		ret += "node_cyy: " + node_cyy.to_string() + "\n";

		ret += "\n";
		ret += "mkl_path_c:\n";
		for (auto& i : mkl_path_c) {
			ret += i.to_string() + "\n";
		}

		return ret;
	}

	size_t get_size() const {
		size_t sector_size = sizeof(uint32_t) * 8;
		return (mkl_path_c.size() + 5)*sector_size;
	}
};

static uint64_t const kSectorSizeK = (uint64_t)1 << 10;
static uint64_t const kSectorSizeM = (uint64_t)1 << 20;
static uint64_t const kSectorSizeG = (uint64_t)1 << 30;
static uint64_t const kSectorSizeT = (uint64_t)1 << 40;

typedef std::function<
	void(int percent, std::string desc)> SectorProgressCallback;

#pragma pack(push)
#pragma pack(4)
struct SectorProofHeader {
	uint16_t index_len;
	uint16_t reserved;
};
#pragma pack(pop)
