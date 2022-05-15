#include <iostream>
#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"
#include "conv-string-bin/convert.cpp"

class Cle {

uint8_t* private_key_;
size_t private_key_size_;
uint8_t* public_key_;
size_t public_key_size_;

public:
	void initialize(const char* x) {
		auto curve = uECC_secp256k1();
		private_key_size_ = uECC_curve_private_key_size(curve);
		public_key_size_ = uECC_curve_public_key_size(curve);

		private_key_ = new uint8_t[private_key_size_]();

		hexStringToBin(private_key_, x);

		public_key_ = new uint8_t[public_key_size_]();
		uECC_compute_public_key(private_key_, public_key_, curve);
	}

	char* get_private_key() {
		char* out = new char[private_key_size_]();
		binToHexString(out, private_key_, private_key_size_);
		return out;
	}

	size_t get_private_key_size() {
		return private_key_size_;
	}

	char* get_public_key() {
		char* out = new char[public_key_size_]();
		binToHexString(out, public_key_, public_key_size_);
		return out;
	}

	size_t get_public_key_size() {
		return public_key_size_;
	}

};

namespace py = pybind11;

PYBIND11_MODULE(cle_component, cle) {
	cle.doc() = "Cle component 1.0";
	
	py::class_<Cle>(cle, "Cle")
		.def(py::init<>())
		.def("initialize", &Cle::initialize)
		.def("get_private_key", &Cle::get_private_key)
		.def("get_public_key", &Cle::get_public_key)
		.def("get_private_key_size", &Cle::get_private_key_size)
		.def("get_public_key_size", &Cle::get_public_key_size);
}
