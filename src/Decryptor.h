/*
 * Decryptor.h
 *
 *  Created on: Aug 14, 2015
 *      Author: cthulhu
 */

#ifndef DECRYPTOR_H_
#define DECRYPTOR_H_

#include <vector>
#include <memory>
#include <string>

namespace CryptoPP {
	class StreamTransformation;
	class SymmetricCipher;
	class AuthenticatedSymmetricCipher;
	class PK_Decryptor;
	class AutoSeededRandomPool;
	class FilterWithBufferedInput;
}

typedef unsigned char byte;

class Decryptor {
public:
	Decryptor(const char *pkFilename);
	virtual ~Decryptor();

	void setSymmetricCipher(std::unique_ptr<CryptoPP::SymmetricCipher> symmetricCipher
								, unsigned keySize = 0, unsigned ivSize = 0);
	void setSymmetricCipher(std::unique_ptr<CryptoPP::AuthenticatedSymmetricCipher> symmetricCipher
								, unsigned keySize = 0, unsigned ivSize = 0);
	void setPkDecryptor(std::unique_ptr<CryptoPP::PK_Decryptor> pkDecryptor);

	std::vector<byte> update(std::vector<byte> input);
	std::vector<byte> finalize();

private:
	virtual void setDefaultSymmetricCipher();
	virtual void setDefaultPkDecryptor();

	void initializeSymmetricCipher(unsigned keySize = 0, unsigned ivSize = 0);
	bool setKeyAndIV();

	bool m_isInitialized = false;
	bool m_isFinalized = false;
	bool m_isCipherAuthenticated = false;

	const char *m_pkFilename;

	std::unique_ptr<CryptoPP::StreamTransformation> m_symmetricCypher;
	std::unique_ptr<CryptoPP::PK_Decryptor> m_pkDecryptor;
	std::unique_ptr<CryptoPP::FilterWithBufferedInput> m_streamFilter;
	std::unique_ptr<CryptoPP::AutoSeededRandomPool> m_randomPool;

	std::vector<byte> m_input;

	unsigned m_keySize = 0;
	unsigned m_ivSize = 0;
};

#endif /* DECRYPTOR_H_ */
