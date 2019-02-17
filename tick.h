#pragma once

#include "public.h"

struct Tick {
	Tick(std::string desc)
		: desc_(std::move(desc))
		, start_(std::chrono::steady_clock::now()) {		
	}
	~Tick() {
		auto now = std::chrono::steady_clock::now();
		auto period = now - start_;
		auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			period).count();
		if (ms > 10 * 60 * 1000) {
			std::cout << desc_ << " tick: " << ms / (1000 * 60) << "m";
		} else if (ms > 10 * 1000) {
			std::cout << desc_ << " tick: " << ms / 1000 << "s";
		} else {
			std::cout << desc_ << " tick: " << ms << "ms";
		}
		std::cout << std::endl;		
	}
	std::string desc_;
	std::chrono::steady_clock::time_point start_;
};
