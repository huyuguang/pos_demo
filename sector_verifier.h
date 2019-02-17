#pragma once

#include "public.h"
#include "sector_misc.h"

class SectorVerifier : private boost::noncopyable {
public:
	// throw
	SectorVerifier(std::string user_id, std::string sector_id, uint64_t data_size,
		SectorItem const& mkl_root);

	std::vector<SectorProof> UnpackProof(
		std::vector<char> const& packed_proof) noexcept;

	bool VerifyProofs(std::vector<uint64_t> const& challenges,
		std::vector<SectorProof> const& proofs) noexcept;

	bool VerifyPackedProofs(std::vector<uint64_t> const& challenges,
		std::vector<char> const& packed_proofs) noexcept;

private:
	void InitD0() noexcept;
	void CreateItem(uint64_t n, SectorItem const& dx, SectorItem const& dy,
		SectorItem* dn) noexcept;
	bool VerifyProof(uint64_t challenge, SectorProof const& proof) noexcept;
	bool VerifyMklPath(SectorItem const& leaf, uint64_t pos,
		SectorItem const& root, std::vector<SectorItem> const& path) noexcept;
private:
	std::string const user_id_;
	std::string const sector_id_;
	uint64_t const data_size_;
	uint64_t const data_count_;
	SectorItem const prefix_;
	SectorItem const mkl_root_;
private:
	SectorItem d0_;
};