//============================================================================
// Name        : crypto.cpp
// Author      : CthulhuDen
// Version     :
// Copyright   : 
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <fstream>
#include <iostream>
#include <cstring>
#include <memory>
#include "Encryptor.h"
#include "Decryptor.h"
#include <cryptopp/rsa.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>

enum Mode {
	RSA_OAEP_SHA_GCM_AES_128 = 0,
};

Encryptor getStandardEncryptor(Mode mode, const char *pkFile)
{
	Encryptor enc(pkFile);
	switch (mode) {
	case RSA_OAEP_SHA_GCM_AES_128:
		enc.setPkEncryptor(std::make_unique<CryptoPP::RSAES_OAEP_SHA_Encryptor>());
		enc.setSymmetricCipher(std::make_unique<CryptoPP::GCM<CryptoPP::AES>::Encryption>(), 16, 12);
		return enc;
	}
	throw std::logic_error("unknown encryption mode");
}

Decryptor getStandardDecryptor(Mode mode, const char *pkFile)
{
	Decryptor dec(pkFile);
	switch (mode) {
	case RSA_OAEP_SHA_GCM_AES_128:
		dec.setPkDecryptor(std::make_unique<CryptoPP::RSAES_OAEP_SHA_Decryptor>());
		dec.setSymmetricCipher(std::make_unique<CryptoPP::GCM<CryptoPP::AES>::Decryption>(), 16, 12);
		return dec;
	}
	throw std::logic_error("unknown decryption mode");
}

void encryptInput(const char *pkFile, unsigned blockSize = 4096, Mode mode = RSA_OAEP_SHA_GCM_AES_128)
{
	byte b_mode = mode;
	std::cout.put(b_mode);

	Encryptor enc = getStandardEncryptor(mode, pkFile);
	std::vector<byte> input(blockSize);

	while (!std::cin.eof()) {
		std::cin.read((char*) input.data(), blockSize);
		std::vector<byte> output = enc.update(std::vector<byte>(input.begin(), input.begin() + std::cin.gcount()));
		std::cout.write((char*) output.data(), output.size());
	}

	std::vector<byte> output = enc.finalize();
	std::cout.write((char*) output.data(), output.size());

	std::vector<byte> aad = enc.aad();
	std::cout.write((char*) aad.data(), aad.size());
}

void decryptInput(const char *pkFile, unsigned blockSize = 4096)
{
	byte b_mode;
	std::cin.get((char&) b_mode);

	Decryptor dec = getStandardDecryptor(static_cast<Mode>(b_mode), pkFile);
	std::vector<byte> input(blockSize);

	while (!std::cin.eof()) {
		std::cin.read((char*) input.data(), blockSize);
		std::vector<byte> output = dec.update(std::vector<byte>(input.begin(), input.begin() + std::cin.gcount()));
		std::cout.write((char*) output.data(), output.size());
	}

	std::vector<byte> output = dec.finalize();
	std::cout.write((char*) output.data(), output.size());
}

int main(int argn, char **argv) {
	std::ios_base::sync_with_stdio(false);
	if (argn >= 3 && strcmp(argv[1], "encrypt") == 0) {
		encryptInput(argv[2], argn >= 4 ? strtoul(argv[3], nullptr, 10) : 32768);
	} else if (argn >= 3 && strcmp(argv[1], "decrypt") == 0) {
		decryptInput(argv[2], argn >= 4 ? strtoul(argv[3], nullptr, 10) : 32768);
	} else {
		std::cout<<"Usage: <command> <keyfile> [buffer], where\n"
					"\tcommand - encrypt or decrypt,\n"
					"\tkeyfile - path to public/private key\n"
					"\tbuffer - buffer size in bytes (defaults to 32768)\n";
	}
	return 0;
}
