#include <iostream>
#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"

#include <stddef.h>
#include <iostream>
#include <dlfcn.h>

unsigned char hexchr2bin(const char hex)
{
        unsigned char result;

        if (hex >= '0' && hex <= '9') {
                result = hex - '0';
        } else if (hex >= 'A' && hex <= 'F') {
                result = hex - 'A' + 10;
        } else if (hex >= 'a' && hex <= 'f') {
                result = hex - 'a' + 10;
        } else {
                return 0;
        }
        return result;
}



void hexStringToBin(unsigned char *out,const char * hexPrivate) {
    for (int i=0; i<32; i++){
        out[i] = hexchr2bin(hexPrivate[2*i])<<4 | hexchr2bin(hexPrivate[2*i+1]);
    }
}


void binToHexString(char *out,const unsigned char *bin, size_t len)
{
    size_t  i;

    if (bin == NULL || len == 0)
        return;

    for (i=0; i<len; i++) {
        out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
        out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';

}

char version[]="1.0";

char const* getVersion() {
        return version;
}

// la classe cle que nous souhaitons importer
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

PYBIND11_MODULE(composant_cle, cle) {
	cle.doc() = "Cle component 1.0";
	
	py::class_<Cle>(cle, "Cle")
		.def(py::init<>())
		.def("initialize", &Cle::initialize)
		.def("get_private_key", &Cle::get_private_key)
		.def("get_public_key", &Cle::get_public_key)
		.def("get_private_key_size", &Cle::get_private_key_size)
		.def("get_public_key_size", &Cle::get_public_key_size);
}
