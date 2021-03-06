
#pragma once

#define BOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE
#define BOOST_IOSTREAMS_NO_LIB

#ifdef _MSC_VER
#include <SDKDDKVer.h>
#endif

#include <stdio.h>
#include <tchar.h>

#include <stdint.h>
#include <limits>
#include <cmath>
#include <typeinfo>
#include <algorithm>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <iostream>
#include <memory>
#include <random>
#include <chrono>
#include <stack>
#include <experimental/filesystem>

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>

#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4244 4267 4242 4996)
#endif

#include <boost/iostreams/device/mapped_file.hpp>
//#include <boost/multiprecision/gmp.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_int/serialize.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#if defined(_MSC_VER)
#pragma warning( pop )
#endif

namespace mp = boost::multiprecision;
namespace fs = std::experimental::filesystem;
namespace io = boost::iostreams;

#define SUICIDE(desc) {	\
	std::cout << __FILE__ << " " << __LINE__ << " " << desc << std::endl; \
	assert(false); \
	abort(); \
}