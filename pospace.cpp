// pospace.cpp : Defines the entry point for the console application.
//

#include "public.h"
#include "sector_prover.h"
#include "sector_verifier.h"
#include "sha256_compress.h"
#include <iostream>

bool test_random_write(std::string const& pathname, uint64_t count) {
	try {
		io::mapped_file_params params;
		params.path = pathname;
		params.flags = io::mapped_file_base::readwrite;
		io::mapped_file db(params);
		uint8_t* p = (uint8_t*)db.data();
		if (!p) {
			std::cout << "init db failed\n";
			return false;
		}
		uint64_t size = db.size();

		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0, size);

		for (uint64_t i = 0; i < count; ++i) {
			uint64_t x = dist(rd);
			p[x] = 0;
		}
	} catch (std::exception&) {
		return false;
	}
	return true;
}

void save_proofs(std::string const& pathname, std::string const& user_id,
	std::string const& sector_id, SectorItem const& root, 
	std::vector<uint64_t> const& c, std::vector<SectorProof> const& proofs) {

	assert(c.size() == proofs.size());
	
	auto s = user_id + sector_id;
	s.resize(32);

	size_t filesize = s.size() + sizeof(root.data) +
		c.size() * (sizeof(uint64_t) + proofs[0].get_size());

	io::mapped_file_params params;
	params.path = pathname;
	params.flags = io::mapped_file_base::readwrite;
	params.new_file_size = filesize;
	io::mapped_file view(params);
	uint8_t* p = (uint8_t*)view.data();
	if (!p)
		throw std::runtime_error("init save file failed");

	memcpy(p, s.data(), 32);
	p += 32;

	memcpy(p, root.data, sizeof(SectorItem::data));
	p += sizeof(SectorItem::data);

	for (size_t i = 0; i < c.size(); ++i) {
		auto& proof = proofs[i];
		*(uint64_t*)p = c[i];
		p += sizeof(uint64_t);

		memcpy(p, proof.node_c.data, sizeof(SectorItem::data));
		p += sizeof(SectorItem::data);

		memcpy(p, proof.node_cx.data, sizeof(SectorItem::data));
		p += sizeof(SectorItem::data);

		memcpy(p, proof.node_cy.data, sizeof(SectorItem::data));
		p += sizeof(SectorItem::data);

		memcpy(p, proof.node_cyx.data, sizeof(SectorItem::data));
		p += sizeof(SectorItem::data);

		memcpy(p, proof.node_cyy.data, sizeof(SectorItem::data));
		p += sizeof(SectorItem::data);

		for (auto& path : proof.mkl_path_c) {
			memcpy(p, path.data, sizeof(SectorItem::data));
			p += sizeof(SectorItem::data);
		}
	}
}

void test_sha256_compress();


int main(int argc, char** argv) {
	//test_sha256_compress(); return 1;
	//test(); return 1;
	std::string user_id = "abcd";
	std::string sector_id = "1234";
	std::string path = "i:/tmp";
	std::string proof_pathname = path + "/pos_proof.bin";

	uint64_t data_size = kSectorSizeG;
	uint64_t data_count = data_size / SHA256_DIGESTSIZE;

	// test_random_write(pathname, 100);

	SectorProver prover(user_id, sector_id, data_size, path);

#if 0
	prover.Create([](int percent, std::string desc) {
		std::cout << percent << "%, " << desc << std::endl;
	});
#else
	if (!prover.Open(SectorProver::OpenFlag::FastIntegrityCheck)) {
		std::cout << "open failed\n";
		return -1;
	}
#endif

	std::random_device rd;
	std::uniform_int_distribution<uint64_t> dist;
	std::vector<uint64_t> c;

#if 0
	std::vector<uint64_t> c{ 0, 1, 2, data_count + 1, data_count, data_count - 1 };		
	for (uint64_t i = 0; i < 4; ++i) {
		c.push_back(dist(rd));
	}
#else
	c.push_back(dist(rd)% data_count);
	c.push_back(dist(rd)% data_count);
#endif

	auto proofs = prover.GenerateProofs(c,
		[](int percent, std::string desc) {
		std::cout << percent << "%, " << desc << std::endl;
	});

	save_proofs(proof_pathname, user_id, sector_id, prover.mkl_root(), c, proofs);

	std::cout << "\n";

	std::cout << "data_count: " << data_count << std::endl;		

	std::cout << "root: " << prover.mkl_root().to_string() << std::endl;

	std::cout << "prefix: " << prover.prefix().to_string() << std::endl;

	std::cout << "d0: " << prover.d0().to_string() << std::endl;

	for (size_t i = 0; i < c.size(); ++i) {
		std::cout << "\n\n";
		std::cout << "challenge: " << c[i] % data_count << std::endl;
		auto const& proof = proofs[i];
		std::cout << proof.to_string() << std::endl;
		std::cout << "\n\n";
	}
	

	auto packed_proofs = prover.PackProofs(proofs);

	SectorVerifier verifier(user_id, sector_id, data_size, prover.mkl_root());
		
	if (!verifier.VerifyPackedProofs(c, packed_proofs)) {
		std::cout << "verify failed\n";
		assert(false);
	}

	std::cout << "verify success\n";

  return 0;
}

