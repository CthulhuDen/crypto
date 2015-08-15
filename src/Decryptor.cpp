/*
 * Decryptor.cpp
 *
 *  Created on: Aug 9, 2015
 *	  Author: cthulhu
 */

#include <stdexcept>

#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "Decryptor.h"
#include "PEMStripper.h"

using CryptoPP::SymmetricCipher;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::GCM;
using CryptoPP::AES;

using CryptoPP::PK_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Base64Decoder;
using CryptoPP::FileSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::StringSink;
using CryptoPP::SimpleKeyingInterface;
using CryptoPP::StreamTransformation;
using CryptoPP::SecByteBlock;

using std::vector;
using std::unique_ptr;
using std::make_unique;
using std::logic_error;
using std::string;

Decryptor::Decryptor(const char *pkFilename)
	: m_pkFilename(pkFilename), m_randomPool(new AutoSeededRandomPool())
{
}

Decryptor::~Decryptor()
{
}

void Decryptor::setDefaultSymmetricCipher()
{
	setSymmetricCipher(make_unique<GCM<AES>::Decryption>());
}

void Decryptor::setDefaultPkDecryptor()
{
	setPkDecryptor(make_unique<RSAES_OAEP_SHA_Decryptor>());
}

void Decryptor::setSymmetricCipher(unique_ptr<SymmetricCipher> symmetricCipher, unsigned keySize, unsigned ivSize)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");
	m_symmetricCypher = std::move(symmetricCipher);
	initializeSymmetricCipher(keySize, ivSize);
	m_isCipherAuthenticated = false;
}

void Decryptor::setSymmetricCipher(unique_ptr<AuthenticatedSymmetricCipher> symmetricCipher, unsigned keySize, unsigned ivSize)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");
	m_symmetricCypher = std::move(symmetricCipher);
	initializeSymmetricCipher(keySize, ivSize);
	m_isCipherAuthenticated = true;
}

void Decryptor::initializeSymmetricCipher(unsigned keySize, unsigned ivSize)
{
	auto *cipher = dynamic_cast<CryptoPP::SimpleKeyingInterface*>(m_symmetricCypher.get());

	if (ivSize || (cipher->IVRequirement() != SimpleKeyingInterface::NOT_RESYNCHRONIZABLE
			&& cipher->IVRequirement() != SimpleKeyingInterface::INTERNALLY_GENERATED_IV)) {
		m_ivSize = ivSize ? ivSize : cipher->DefaultIVLength();
	} else {
		m_ivSize = 0;
	}

	m_keySize = keySize ? keySize : cipher->DefaultKeyLength();
}

void Decryptor::setPkDecryptor(unique_ptr<PK_Decryptor> pkEncrytor)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");

	m_pkDecryptor = std::move(pkEncrytor);

	FileSource file(m_pkFilename, true, new PEMStripper(new Base64Decoder()));
	m_pkDecryptor->AccessPrivateKey().Load(file);
	m_pkDecryptor->AccessPrivateKey().ThrowIfInvalid(*m_randomPool, 2);
}

bool Decryptor::setKeyAndIV()
{
	if (!m_symmetricCypher) setDefaultSymmetricCipher();
	if (!m_pkDecryptor) setDefaultPkDecryptor();

	unsigned encryptedKeySize = m_pkDecryptor->CiphertextLength(m_keySize);

	if (m_input.size() < encryptedKeySize + m_ivSize) {
		return false;
	}

	if (m_isCipherAuthenticated) {
		auto *cipher = dynamic_cast<AuthenticatedSymmetricCipher*>(m_symmetricCypher.get());
		m_streamFilter = make_unique<AuthenticatedDecryptionFilter>(*cipher);
	} else {
		m_streamFilter = make_unique<StreamTransformationFilter>(*m_symmetricCypher);
	}

	// decrypt symmetric key with public
	SecByteBlock key(m_keySize);
	m_pkDecryptor->Decrypt(*m_randomPool, m_input.data(), encryptedKeySize, key.data());

	auto *cipher = dynamic_cast<SimpleKeyingInterface*>(m_symmetricCypher.get());

	if (m_ivSize) {
		cipher->SetKeyWithIV(key.data(), m_keySize, m_input.data() + encryptedKeySize, m_ivSize);
	} else {
		cipher->SetKey(key.data(), m_keySize);
	}

	if (m_isCipherAuthenticated) {
		m_streamFilter->ChannelPut(CryptoPP::AAD_CHANNEL, m_input.data(), encryptedKeySize + m_ivSize);
	}
	m_input.erase(m_input.begin(), m_input.begin() + encryptedKeySize + m_ivSize);

	return m_isInitialized = true;
}

vector<byte> Decryptor::update(vector<byte> input)
{
	if (m_isFinalized) throw logic_error("Already finalized");

	vector<byte> res;
	if (!m_isInitialized) {
		m_input.insert(m_input.end(), input.begin(), input.end());
		if (setKeyAndIV()) {
			input = m_input;
			m_input.resize(0);
		} else {
			return {};
		}
	}

	string cipherText;
	StringSink sink(cipherText);
	m_streamFilter->ChannelPut(CryptoPP::DEFAULT_CHANNEL, input.data(), input.size());
	m_streamFilter->TransferTo(sink);

	res.insert(res.end(), cipherText.begin(), cipherText.end());

	return res;
}

vector<byte> Decryptor::finalize()
{
	if (m_isFinalized) throw logic_error("Already finalized");
	if (!m_isInitialized) throw logic_error("Initialization not completed");

	string res;
	StringSink sink(res);
	m_streamFilter->MessageEnd();
	m_streamFilter->TransferTo(sink);

	m_isFinalized = true;

	if (m_isCipherAuthenticated) {
		auto *cipher = dynamic_cast<AuthenticatedDecryptionFilter*>(m_streamFilter.get());
		if (!cipher->GetLastResult()) {
			throw logic_error("Input corrupted of authenticity violated!");
		}
	}

	return vector<byte>(res.begin(), res.end());
}
