/*
 * Encryptor.h
 *
 *  Created on: Aug 9, 2015
 *      Author: cthulhu
 */

#ifndef ENCRYPTOR_H_
#define ENCRYPTOR_H_

#include <vector>
#include <memory>
#include <string>

namespace CryptoPP {
	class StreamTransformation;
	class SymmetricCipher;
	class AuthenticatedSymmetricCipher;
	class PK_Encryptor;
	class StreamTransformationFilter;
	class AutoSeededRandomPool;
	template <class T>
	class StringSinkTemplate;
	class TransparentFilter;
}

typedef unsigned char byte;

class Encryptor {
public:
	Encryptor(const char *pkFilename);
	virtual ~Encryptor();

	void setSymmetricCipher(std::unique_ptr<CryptoPP::SymmetricCipher> symmetricCipher
								, unsigned keySize = 0, unsigned ivSize = 0);
	void setSymmetricCipher(std::unique_ptr<CryptoPP::AuthenticatedSymmetricCipher> symmetricCipher
								, unsigned keySize = 0, unsigned ivSize = 0);
	void setPkEncryptor(std::unique_ptr<CryptoPP::PK_Encryptor> pkEncryptor);

	std::vector<byte> aad();

	std::vector<byte> initialize();
	std::vector<byte> update(std::vector<byte> input);
	std::vector<byte> finalize();

private:
	virtual void setDefaultSymmetricCipher();
	virtual void setDefaultPkEncryptor();

	void initializeSymmetricCipher(unsigned keySize = 0, unsigned ivSize = 0);

	bool m_isInitialized = false;
	bool m_isFinalized = false;
	bool m_isCipherAuthenticated = false;

	const char *m_pkFilename;

	std::unique_ptr<CryptoPP::StreamTransformation> m_symmetricCypher;
	std::unique_ptr<CryptoPP::PK_Encryptor> m_pkEncryptor;
	std::unique_ptr<CryptoPP::StreamTransformationFilter> m_streamFilter;
	std::unique_ptr<CryptoPP::AutoSeededRandomPool> m_randomPool;
	std::unique_ptr<CryptoPP::TransparentFilter> m_outputFilter;

	std::string m_aad;
	std::unique_ptr<CryptoPP::StringSinkTemplate<std::string> > m_aadSink;


	std::vector<byte> m_iv;
	unsigned m_keySize = 0;
};

#endif /* ENCRYPTOR_H_ */
