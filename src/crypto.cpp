//============================================================================
// Name        : crypto.cpp
// Author      : CthulhuDen
// Version     :
// Copyright   : 
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include "Encryptor.h"

using namespace std;
using namespace CryptoPP;

int main() {
	Encryptor enc("/etc/ssl/backup.pub");
	std::vector<byte> input(1024);

	while (!std::cin.eof()) {
		std::cin.read((char*) input.data(), 1024);
		std::vector<byte> output = enc.update(vector<byte>(input.begin(), input.begin() + cin.gcount()));
		std::cout.write((char*) output.data(), output.size());
	}

	std::vector<byte> output = enc.finalize();
	std::cout.write((char*) output.data(), output.size());

	std::vector<byte> aad = enc.aad();
	std::cout.write((char*) aad.data(), aad.size());

	return 0;
}
