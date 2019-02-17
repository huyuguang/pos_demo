#include "sector_verifier.h"
#include "tick.h"
#include "bigint.h"
#include "sha256_compress.h"

// throw
SectorVerifier::SectorVerifier(std::string user_id, std::string sector_id,
	uint64_t data_size, SectorItem const& mkl_root)
	: user_id_(std::move(user_id))
	, sector_id_(std::move(sector_id))
	, data_size_(data_size)
	, mkl_root_(mkl_root)
	, data_count_(data_size / SHA256_DIGESTSIZE)
	, prefix_(SectorItem(user_id_ + sector_id_)) {
	if ((data_size & (data_size - 1)) != 0) { // must be 2^x
		throw std::runtime_error("invalid data_size");
	}
	InitD0();
}

void SectorVerifier::InitD0() noexcept {
	SectorItem empty;
	memset(empty.data, 0, sizeof(empty.data));
	CreateItem(0, empty, empty, &d0_);
}

void SectorVerifier::CreateItem(uint64_t n, SectorItem const& dx,
	SectorItem const& dy, SectorItem* dn) noexcept {
	SectorItem left, right;
	SectorItem::Xor(prefix_, dx, &left);
	SectorItem::Xor(SectorItem(n), dy, &right);
	SectorItem::CompressTwo(left, right, dn);
}

bool SectorVerifier::VerifyProofs(std::vector<uint64_t> const& challenges,
	std::vector<SectorProof> const& proofs) noexcept {
	if (challenges.empty()) // let it crash
		SUICIDE("empty challenges");

	if (proofs.size() != challenges.size()) {
		assert(false);
		return false;
	}

	for (size_t i = 0; i < challenges.size(); ++i) {
		auto c = challenges[i] % data_count_;
		auto const& proof = proofs[i];
		if (!VerifyProof(c, proof))
			return false;
	}

	return true;
}

bool SectorVerifier::VerifyProof(uint64_t challenge,
	SectorProof const& proof) noexcept {
	auto c = challenge % data_count_;
	SectorItem node_c;
	if (c > 0) {
		CreateItem(c, proof.node_cx, proof.node_cy, &node_c);
	} else {
		node_c = d0_;
	}
	if (node_c != proof.node_c)
		return false;

	auto x = proof.node_cx.get_parent_x(c);
	auto y = proof.node_cx.get_parent_y(c);
	SectorItem node_y;
	if (y > 0) {
		CreateItem(y, proof.node_cyx, proof.node_cyy, &node_y);
	} else {
		node_y = d0_;
	}
	if (node_y != proof.node_cy)
		return false;

	if (!VerifyMklPath(node_c, c, mkl_root_, proof.mkl_path_c))
		return false;

	if (c % 2) {
		if (proof.node_cx != proof.mkl_path_c[0])
			return false;
	}

	return true;
}

bool SectorVerifier::VerifyMklPath(SectorItem const& leaf, uint64_t pos,
	SectorItem const& root, std::vector<SectorItem> const& path) noexcept {
	SectorItem cacu_root = leaf;
	for (auto const& p : path) {
		if (pos % 2) {
			SectorItem::CompressTwo(p, cacu_root, &cacu_root);
		} else {
			SectorItem::CompressTwo(cacu_root, p, &cacu_root);
		}
		pos /= 2;
	}

	return (cacu_root == root);
}

bool SectorVerifier::VerifyPackedProofs(
	std::vector<uint64_t> const& challenges,
	std::vector<char> const& packed_proofs) noexcept {
	if (challenges.empty()) {
		// let it crash
		assert(false);
		SUICIDE("empty challenges");
	}

	auto proofs = UnpackProof(packed_proofs);
	if (proofs.size() != challenges.size()) {
		assert(false);
		return false;
	}
	return VerifyProofs(challenges, proofs);
}

std::vector<SectorProof> SectorVerifier::UnpackProof(
	std::vector<char> const& packed_proof) noexcept {
	std::vector<SectorProof> ret;
	auto const kItemSize = sizeof(SectorItem::data);

	std::vector<char> raw_proofs;
	try {
		// avoid zip bomb
		size_t limit = std::min<size_t>(packed_proof.size() * 10, 1000000);
		io::filtering_istream is;
		is.push(io::gzip_decompressor());
		is.push(io::array_source(packed_proof.data(),	packed_proof.size()));
		while (is) {
			char buf[4096];
			is.read(buf, sizeof(buf));
			if (raw_proofs.size() + is.gcount() >= limit) {
				return ret;
			}
			raw_proofs.insert(raw_proofs.end(), buf, buf + is.gcount());
		}
	} catch (std::exception&) {
		return ret;
	}

	auto mkl_path_len = (uint64_t)std::log2(data_count_);
	auto proof_len = kItemSize * (mkl_path_len + 5);

	if (raw_proofs.empty() || raw_proofs.size() % proof_len)
		return ret;

	auto proof_count = raw_proofs.size() / proof_len;

	ret.resize(proof_count);

	uint8_t* begin = (uint8_t*)raw_proofs.data();
	for (auto& proof : ret) {		
		memcpy(proof.node_c.data, begin, kItemSize);
		begin += kItemSize;
		memcpy(proof.node_cx.data, begin, kItemSize);
		begin += kItemSize;
		memcpy(proof.node_cy.data, begin, kItemSize);
		begin += kItemSize;
		memcpy(proof.node_cyx.data, begin, kItemSize);
		begin += kItemSize;
		memcpy(proof.node_cyy.data, begin, kItemSize);
		begin += kItemSize;

		proof.mkl_path_c.resize(mkl_path_len);
		for (size_t i = 0; i < mkl_path_len; ++i) {
			memcpy(proof.mkl_path_c[i].data, begin, kItemSize);
			begin += kItemSize;
		}
	}
	return ret;
}