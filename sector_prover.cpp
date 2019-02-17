#include "sector_prover.h"
#include "sector_verifier.h"
#include "tick.h"
#include "bigint.h"

SectorProver::SectorProver(std::string user_id, std::string sector_id,
	uint64_t data_size, std::string path)
	: user_id_(std::move(user_id))
	, sector_id_(std::move(sector_id))
	, data_size_(data_size)
	, data_count_(data_size / SHA256_DIGESTSIZE)
	, block_size_(1ULL << ((uint64_t)(std::log2(data_count_)/2)))
	, meta_size_(data_size / block_size_ + SHA256_DIGESTSIZE)
	, meta_count_(meta_size_ / SHA256_DIGESTSIZE)
	, path_(std::move(path))
	, data_pathname_(path_ + "/" + sector_id_ + ".dat")
	, meta_pathname_(path_ + "/" + sector_id_ + ".mta")
	, prefix_(SectorItem(user_id_ + sector_id_)) {

	if ((data_size & (data_size - 1)) != 0) { // must be 2^x
		throw std::runtime_error("invalid data_size");
	}

	if (meta_count_ <= 1) {
		throw std::runtime_error("data_size too small");
	}

	if (path_.empty()) {
		throw std::runtime_error("invalid pathname");
	}

	std::error_code error_code;
	if (!fs::exists(path_, error_code) || error_code) {
		throw std::runtime_error("path not exist");
	}

	if (!fs::is_directory(path_, error_code) || error_code) {
		throw std::runtime_error("path not directory");
	}
	
	InitD0();
}

bool SectorProver::Create(SectorProgressCallback const& progress) noexcept {
	if (data_view_ || meta_view_)
		return false;	

	std::error_code error_code;

	fs::space_info space = fs::space(path_, error_code);
	if (error_code)
		return false;

	uint64_t const kUselessSize = 1024 * 1024;
	uint64_t want_space = data_size_ + meta_size_ + kUselessSize;
	if (space.available < want_space)
		return false;

	try {
		InitData(progress);
		OpenData();
		InitMeta(progress);
		OpenMeta();
		return true;
	} catch (std::exception&) {
		fs::remove(data_pathname_, error_code);
		fs::remove(meta_pathname_, error_code);
		return false;
	}
}

bool SectorProver::Open(SectorProver::OpenFlag flag) noexcept {
	if (data_view_ || meta_view_)
		return false;

	try {
		OpenData();
		OpenMeta();
	} catch (std::exception&) {
		return false;
	}

	if (flag == OpenFlag::FastIntegrityCheck)
		return FastCheckIntegrity();
	if (flag == OpenFlag::FullIntegrityCheck)
		return FullCheckIntegrity();

	return true;
}

SectorItem const& SectorProver::mkl_root() noexcept {
	if (!data_view_ || !meta_view_) {
		SUICIDE("not opened");
	}

	SectorItem* meta_items = (SectorItem*)meta_view_->data();
	auto& meta_root = meta_items[meta_count_ - 1];
	return meta_root;
}

SectorItem const& SectorProver::prefix() noexcept {
	return prefix_;
}

SectorItem const& SectorProver::d0() noexcept {
	return d0_;
}

void SectorProver::InitD0() noexcept {
	SectorItem empty;
	memset(empty.data, 0, sizeof(empty.data));
	CreateItem(0, empty, empty, &d0_);
}

// dn = hash(prefix ^ dx, n ^ dy)
void SectorProver::CreateItem(uint64_t n, SectorItem const& dx,
	SectorItem const& dy, SectorItem* dn) noexcept {
	SectorItem left, right;
	SectorItem::Xor(prefix_, dx, &left);
	SectorItem::Xor(SectorItem(n), dy, &right);
	SectorItem::CompressTwo(left, right, dn);
}

// throw
void SectorProver::InitData(SectorProgressCallback const& progress) {
	Tick tick(__FUNCTION__);
	io::mapped_file_params params;
	params.path = data_pathname_;
	params.flags = io::mapped_file_base::readwrite;
	params.new_file_size = data_size_;
	io::mapped_file view(params);
	SectorItem* items = (SectorItem*)view.data();
	if (!items)
		throw std::runtime_error("init data_view failed");

	items[0] = d0_;
	
	for (uint64_t n = 1; n < data_count_; ++n) {
		SectorItem* dn = &items[n];
		SectorItem* dn_1 = &items[n - 1];
		uint64_t x = dn_1->get_parent_x(n);
		uint64_t y = dn_1->get_parent_y(n);
		SectorItem* dx = &items[x];
		SectorItem* dy = &items[y];
		CreateItem(n, *dx, *dy, dn);

		if (n % 1000000 == 0) {
			progress((int)(n * 100 / data_count_),
				"init data: " + std::to_string(n));
		}
	}
}

// throw
void SectorProver::OpenData() {
	io::mapped_file_params params;
	params.path = data_pathname_;
	data_view_.reset(new io::mapped_file_source(params));
	if (data_view_->size() != data_size_)
		throw std::runtime_error("data size");
	if (!data_view_->data())
		throw std::runtime_error("data open");
}

// throw
void SectorProver::InitMeta(SectorProgressCallback const& progress) {
	Tick tick(__FUNCTION__);
	io::mapped_file_params params;
	params.path = meta_pathname_;
	params.flags = io::mapped_file_base::readwrite;
	params.new_file_size = meta_size_;
	io::mapped_file view(params);
	SectorItem* meta_items = (SectorItem*)view.data();
	if (!meta_items)
		throw std::runtime_error("init meta_view failed");

	SectorItem* data_items = (SectorItem*)data_view_->data();

	// calculate all block root
	for (uint64_t i = 0; i < data_count_ / block_size_; ++i) {
		auto begin = data_items + i * block_size_;
		CaculateMklRoot(begin, block_size_, &meta_items[i]);

		if (i % 1000 == 0) {
			progress((int)(i * 100 / (data_count_ / block_size_)),
				"calculate block root: " + std::to_string(i));
		}
	}

	assert(data_count_ / block_size_ == meta_count_ - 1);

	// mkl tree root
	SectorItem* begin = meta_items;
	uint64_t count = data_count_ / block_size_;
	CaculateMklRoot(begin, count, &meta_items[meta_count_ - 1]);
	
	auto& meta_root = meta_items[meta_count_ - 1];
	std::cout << "root: " << meta_root.to_string() << "\n";
}

// throw
void SectorProver::OpenMeta() {
	io::mapped_file_params params;
	params.path = meta_pathname_;
	meta_view_.reset(new io::mapped_file_source(params));
	if (meta_view_->size() != meta_size_)
		throw std::runtime_error("meta size");
	if (!meta_view_->data())
		throw std::runtime_error("meta open");
}

// memory usage: O(lgN)
void SectorProver::CaculateMklRoot(SectorItem const* begin, uint64_t count,
	SectorItem* root) noexcept {
	assert((count & (count - 1)) == 0);
	typedef std::pair<SectorItem, int> H; // pair<item, height>
	std::vector<H> s;
	s.reserve(256);

	uint64_t offset = 0;
	for (;;) {
		if (s.size() >= 2) {
			auto& right = s[s.size() - 1];
			auto& left = s[s.size() - 2];
			if (right.second == left.second) {
				SectorItem::CompressTwo(left.first, right.first, &left.first);
				++left.second;
				s.pop_back();
				continue;
			}
		}

		if (offset == count) {
			if (s.size() != 1) {
				SUICIDE(std::to_string(s.size()) + " != 1");
			}

			if (((uint64_t)1 << s[0].second) != count) {
				SUICIDE(std::to_string(s[0].second) + " !=" +
					std::to_string(count));
			}

			break;
		}

		s.resize(s.size() + 1);

		// push new leaf
		s[s.size() - 1].first = begin[offset++];
		s[s.size() - 1].second = 0;
	}

	*root = s[0].first;
}

void SectorProver::GetMklPaths(SectorItem const* begin, uint64_t count,
	std::vector<uint64_t> leafs, SectorItem const* root,
	std::vector<std::vector<SectorItem>>& paths) noexcept {
	for (auto leaf : leafs) {
		assert(leaf < count);
	}
	paths.resize(leafs.size());

	struct H {
		uint64_t pos;
		SectorItem item;
		int height;
		std::vector<bool> flags;
	};
	std::vector<H> s;
	s.reserve(256);
	uint64_t offset;

	offset = 0;
	for (;;) {
		if (s.size() >= 2) {
			auto& right = s[s.size() - 1];
			auto& left = s[s.size() - 2];
			if (right.height == left.height) {
				std::vector<bool> flags;
				flags.resize(leafs.size());
				for (size_t i = 0; i < flags.size(); ++i) {
					if (right.flags[i]) {
						paths[i].push_back(left.item);
						flags[i] = true;
					} else if (left.flags[i]) {
						paths[i].push_back(right.item);
						flags[i] = true;
					} else {
						flags[i] = false;
					}
				}
				SectorItem::CompressTwo(left.item, right.item, &left.item);
				left.height += 1;
				left.flags = std::move(flags);
				s.pop_back();
				continue;
			}
		}

		if (offset == count) {
			if (s.size() != 1) {
				SUICIDE(std::to_string(s.size()) + " != 1");
			}
			break;
		}

		s.resize(s.size() + 1);

		// push new leaf
		auto& last_s = s[s.size() - 1];
		last_s.flags.resize(leafs.size());
		last_s.pos = offset;
		for (size_t i = 0; i < leafs.size(); ++i) {
			auto leaf = leafs[i];
			last_s.flags[i] = (offset == leaf);
		}
		last_s.item = begin[offset++];
		last_s.height = 0;
	}

	SectorItem const& cacu_root = s[0].item;
	assert(cacu_root == *root);
}

void SectorProver::GetMklPaths(std::vector<uint64_t> const& leafs,
	std::vector<std::vector<SectorItem>>& paths) noexcept {
	SectorItem* data_items = (SectorItem*)data_view_->data();
	SectorItem* meta_items = (SectorItem*)meta_view_->data();
	paths.resize(leafs.size());
	for (auto& leaf : leafs) {
		assert(leaf < data_count_);
	}
	// leaf to meta
	struct GroupLeaf {
		std::vector<uint64_t> leafs;
		std::vector<uint64_t> poss;
		std::vector<std::vector<SectorItem>> proofs;
	};
	std::unordered_map<uint64_t, GroupLeaf> block_leafs;
	for (auto leaf : leafs) {
		uint64_t block_index = leaf / block_size_;
		auto& group_leaf = block_leafs[block_index];
		group_leaf.leafs.push_back(leaf);
		group_leaf.poss.push_back(leaf % block_size_);
	}

	// maybe some leafs exist in same block
	for (auto block_leaf : block_leafs) {
		uint64_t block_index = block_leaf.first;
		SectorItem* begin = data_items + block_index * block_size_;
		auto block_root = &meta_items[block_index];
		auto& group_leaf = block_leaf.second;

		GetMklPaths(begin, block_size_, group_leaf.poss, block_root,
			group_leaf.proofs);

		for (size_t i = 0; i < group_leaf.leafs.size(); ++i) {
			auto leaf = group_leaf.leafs[i];
			auto& proof = group_leaf.proofs[i];
			for (size_t j = 0; j < leafs.size(); ++j) {
				if (leafs[j] == leaf) {
					if (paths[j].empty()) {
						// maybe the leaf duplicate
						paths[j] = std::move(proof);
					}
				}
			}
		}
	}

	// meta to root
	std::vector<uint64_t> meta_poss;
	for (auto leaf : leafs) {
		uint64_t block_index = leaf / block_size_;
		meta_poss.push_back(block_index);
	}

	SectorItem* begin = meta_items;
	auto meta_root = &meta_items[meta_count_ - 1];
	GetMklPaths(begin, meta_count_ - 1, meta_poss, meta_root, paths);
}

std::vector<SectorProof> SectorProver::GenerateProofs(
	std::vector<uint64_t> const& challenges,
	SectorProgressCallback const& progress) noexcept {
	Tick tick(__FUNCTION__);

	if (challenges.empty()) {
		SUICIDE("empty challenges");
	}

	if (!data_view_ || !meta_view_) {
		SUICIDE("not opened");
	}

	std::vector<SectorProof> proofs;
	proofs.resize(challenges.size());
	SectorItem* data_items = (SectorItem*)data_view_->data();

	std::vector<uint64_t> mkl_leafs;
	for (size_t i = 0; i < challenges.size(); ++i) {
		auto c = challenges[i] % data_count_;
		auto& proof = proofs[i];
		// Dc, Dx, Dy, Dyx, Dyy
		proof.node_c = data_items[c];
		SectorItem const& node_c_1 = (c > 0) ? data_items[c - 1] : data_items[0];		
		auto cx = node_c_1.get_parent_x(c);
		auto cy = node_c_1.get_parent_y(c);
		proof.node_cx = data_items[cx];
		proof.node_cy = data_items[cy];
		SectorItem const& node_y_1 = (cy > 0) ? data_items[cy - 1] : data_items[0];
		auto yx = node_y_1.get_parent_x(cy);
		auto yy = node_y_1.get_parent_y(cy);
		proof.node_cyx = data_items[yx];
		proof.node_cyy = data_items[yy];
		mkl_leafs.push_back(c);
	}

	std::vector<std::vector<SectorItem>> mkl_paths;
	GetMklPaths(mkl_leafs, mkl_paths);

	auto mkl_path_len = (uint64_t)std::log2(data_count_);
	for (size_t i = 0; i < challenges.size(); ++i) {
		auto& proof = proofs[i];
		proof.mkl_path_c = std::move(mkl_paths[i]);
		assert(proof.mkl_path_c.size() == mkl_path_len);
	}

	return proofs;
}

std::vector<char> SectorProver::PackProofs(
	std::vector<SectorProof> const& proofs) noexcept {
	std::vector<char> ret;

	io::filtering_ostream os;
	os.push(io::gzip_compressor());
	os.push(io::back_inserter(ret));

	auto const kItemSize = sizeof(SectorItem::data);
	for (auto& proof : proofs) {
		os.write((char*)proof.node_c.data, kItemSize);
		os.write((char*)proof.node_cx.data, kItemSize);
		os.write((char*)proof.node_cy.data, kItemSize);
		os.write((char*)proof.node_cyx.data, kItemSize);
		os.write((char*)proof.node_cyy.data, kItemSize);
		for (auto& i : proof.mkl_path_c) {
			os.write((char*)i.data, kItemSize);
		}
	}

	os.reset();

	size_t raw_size = sizeof(SectorItem::data) * proofs.size() *
		(5 + 2 * proofs[0].mkl_path_c.size());

	std::cout << __FUNCTION__ << ": " << std::to_string(raw_size) << " -> " <<
		ret.size() << std::endl;

	return ret;
}

std::vector<char> SectorProver::GeneratePackedProofs(
	std::vector<uint64_t> const& challenges,
	SectorProgressCallback const& progress) noexcept {
	if (challenges.empty()) {
		SUICIDE("empty challenges");
	}
	auto proofs = GenerateProofs(challenges, progress);
	return PackProofs(proofs);
}

bool SectorProver::FullCheckIntegrity() noexcept {
	Tick tick(__FUNCTION__);
	SectorItem* data_items = (SectorItem*)data_view_->data();
	SectorItem* meta_items = (SectorItem*)meta_view_->data();
	auto & root = mkl_root();
	SectorItem temp_root;

	for (uint64_t i = 0; i < meta_count_ - 1; ++i) {
		auto begin = data_items + i * block_size_;
		CaculateMklRoot(begin, block_size_, &temp_root);
		if (temp_root != meta_items[i]) {
			assert(false);
			return false;
		}
	}

	CaculateMklRoot(meta_items, meta_count_ - 1, &temp_root);
	if (temp_root != root) {		
		assert(false);
		return false;
	}

#if 0 // do not need it
	CaculateMklRoot(data_items, data_count_, &temp_root);
	if (temp_root != root) {
		assert(false);
		return false;
	}
#endif

	return true;
}

bool SectorProver::FastCheckIntegrity() noexcept {
	Tick tick(__FUNCTION__);
	std::vector<uint64_t> c{ 0, data_count_ - 1 };
	std::random_device rd;
	std::uniform_int_distribution<uint64_t> dist;
	for (uint64_t i = 0; i < 8; ++i) {
		c.push_back(dist(rd));
	}

	auto proofs = GenerateProofs(c, [](int percent, std::string desc) {});
	if (proofs.size() != c.size())
		return false;

	SectorVerifier verifier(user_id_, sector_id_, data_size_, mkl_root());
	return verifier.VerifyProofs(c, proofs);
}
