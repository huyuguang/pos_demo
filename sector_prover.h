#pragma once

#include "public.h"
#include "sector_misc.h"

class SectorProver : private boost::noncopyable {
public:
	// throw
	SectorProver(std::string user_id, std::string sector_id, uint64_t data_size,
		std::string path);

	// long time
	bool Create(SectorProgressCallback const& progress) noexcept;

	enum OpenFlag {
		NoneIntegrityCheck,
		FullIntegrityCheck,
		FastIntegrityCheck,
	};
	bool Open(OpenFlag flag) noexcept;

	std::vector<SectorProof> GenerateProofs(
		std::vector<uint64_t> const& challenges,
		SectorProgressCallback const& progress) noexcept;

	std::vector<char> GeneratePackedProofs(
		std::vector<uint64_t> const& challenges,
		SectorProgressCallback const& progress) noexcept;

	std::vector<char> PackProofs(
		std::vector<SectorProof> const& proofs) noexcept;

	SectorItem const& mkl_root() noexcept;

	SectorItem const& prefix() noexcept;

	SectorItem const& d0() noexcept;
private:
	void InitData(SectorProgressCallback const& progress); // throw, sync, long time
	void InitMeta(SectorProgressCallback const& progress); // throw, sync, long time
	void OpenData(); // throw
	void OpenMeta(); // throw
	void InitD0() noexcept;
	void CreateItem(uint64_t n, SectorItem const& dx, SectorItem const& dy,
		SectorItem* dn) noexcept;
	void CaculateMklRoot(SectorItem const* begin, uint64_t count,
		SectorItem* root) noexcept;
	void GetMklPaths(std::vector<uint64_t> const& leafs,
		std::vector<std::vector<SectorItem>>& paths) noexcept;
	void GetMklPaths(SectorItem const* begin, uint64_t count,
		std::vector<uint64_t> leafs, SectorItem const* root,
		std::vector<std::vector<SectorItem>>& paths) noexcept;
	// long time
	bool FullCheckIntegrity() noexcept;
	bool FastCheckIntegrity() noexcept;
private:
	std::string const user_id_;
	std::string const sector_id_;
	uint64_t const data_size_;
	uint64_t const data_count_;
	uint64_t const block_size_;
	uint64_t const meta_size_;
	uint64_t const meta_count_;
	std::string const path_;
	std::string const data_pathname_;
	std::string const meta_pathname_;
	SectorItem const prefix_;
private:
	SectorItem d0_;
	std::unique_ptr<io::mapped_file_source> data_view_;
	std::unique_ptr<io::mapped_file_source> meta_view_;
};