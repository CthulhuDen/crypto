/*
 * Encryptor.cpp
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
#include <cryptopp/channels.h>

#include "Encryptor.h"
#include "PEMStripper.h"

using CryptoPP::SymmetricCipher;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::GCM;
using CryptoPP::AES;

using CryptoPP::PK_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Base64Decoder;
using CryptoPP::FileSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::StringSink;
using CryptoPP::SimpleKeyingInterface;
using CryptoPP::StreamTransformation;
using CryptoPP::SecByteBlock;
using CryptoPP::ChannelSwitch;
using CryptoPP::Redirector;
using CryptoPP::TransparentFilter;

using std::vector;
using std::unique_ptr;
using std::make_unique;
using std::logic_error;
using std::string;

Encryptor::Encryptor(const char *pkFilename)
	: m_pkFilename(pkFilename), m_randomPool(new AutoSeededRandomPool()), m_outputFilter(new TransparentFilter())
{
	m_aadSink = make_unique<StringSink>(m_aad);
}

Encryptor::~Encryptor()
{
}

void Encryptor::setDefaultSymmetricCipher()
{
	setSymmetricCipher(make_unique<GCM<AES>::Encryption>());
}

void Encryptor::setDefaultPkEncryptor()
{
	setPkEncryptor(make_unique<RSAES_OAEP_SHA_Encryptor>());
}

void Encryptor::setSymmetricCipher(unique_ptr<SymmetricCipher> symmetricCipher, unsigned keySize, unsigned ivSize)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");
	m_symmetricCypher = std::move(symmetricCipher);
	initializeSymmetricCipher(keySize, ivSize);
	m_isCipherAuthenticated = false;
}

void Encryptor::setSymmetricCipher(unique_ptr<AuthenticatedSymmetricCipher> symmetricCipher, unsigned keySize, unsigned ivSize)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");
	m_symmetricCypher = std::move(symmetricCipher);
	initializeSymmetricCipher(keySize, ivSize);
	m_isCipherAuthenticated = true;
}

vector<byte> Encryptor::aad()
{
	if (!m_isFinalized) throw logic_error("Not finalized yet");
	if (!m_isCipherAuthenticated) throw logic_error("Encryption is not authenticated!");

	return vector<byte>(m_aad.begin(), m_aad.end());
}

void Encryptor::initializeSymmetricCipher(unsigned keySize, unsigned ivSize)
{
	auto *cipher = dynamic_cast<CryptoPP::SimpleKeyingInterface*>(m_symmetricCypher.get());

	if (ivSize || (cipher->IVRequirement() != SimpleKeyingInterface::NOT_RESYNCHRONIZABLE
			&& cipher->IVRequirement() != SimpleKeyingInterface::INTERNALLY_GENERATED_IV)) {
		if (!ivSize) ivSize = cipher->DefaultIVLength();
		m_iv.resize(ivSize);
		m_randomPool->GenerateBlock(m_iv.data(), ivSize);
	} else {
		m_iv.resize(0);
	}

	m_keySize = keySize ? keySize : cipher->DefaultKeyLength();
}

void Encryptor::setPkEncryptor(unique_ptr<PK_Encryptor> pkEncrytor)
{
	if (m_isInitialized) throw logic_error("Initialization already complete");

	m_pkEncryptor = std::move(pkEncrytor);

	FileSource file(m_pkFilename, true, new PEMStripper(new Base64Decoder()));
	m_pkEncryptor->AccessPublicKey().Load(file);
	m_pkEncryptor->AccessPublicKey().ThrowIfInvalid(*m_randomPool, 2);
}

vector<byte> Encryptor::initialize()
{
	if (m_isInitialized) throw logic_error("Initialization already complete");

	if (!m_symmetricCypher) setDefaultSymmetricCipher();
	if (!m_pkEncryptor) setDefaultPkEncryptor();

	if (m_isCipherAuthenticated) {
		auto *cipher = dynamic_cast<AuthenticatedSymmetricCipher*>(m_symmetricCypher.get());
		auto *channelSwitch = new ChannelSwitch(*m_outputFilter);
		m_streamFilter = make_unique<AuthenticatedEncryptionFilter>(*cipher, channelSwitch, false, -1, "ATAG");
		channelSwitch->AddRoute("ATAG", *m_aadSink, CryptoPP::DEFAULT_CHANNEL);
	} else {
		m_streamFilter = make_unique<StreamTransformationFilter>(*m_symmetricCypher, new Redirector(*m_outputFilter));
	}

	// initialize symmetric cipher
	SecByteBlock key(m_keySize);
	m_randomPool->GenerateBlock(key.data(), m_keySize);

	// encrypt symmetric key with public
	vector<byte> res(m_pkEncryptor->CiphertextLength(key.size()));
	m_pkEncryptor->Encrypt(*m_randomPool, key.data(), key.size(), res.data());

	auto *cipher = dynamic_cast<SimpleKeyingInterface*>(m_symmetricCypher.get());

	if (m_iv.size()) {
		cipher->SetKeyWithIV(key.data(), m_keySize, m_iv.data(), m_iv.size());
		res.insert(res.end(), m_iv.begin(), m_iv.end());
	} else {
		cipher->SetKey(key.data(), m_keySize);
	}

	if (m_isCipherAuthenticated) {
		m_streamFilter->ChannelPutMessageEnd(CryptoPP::AAD_CHANNEL, res.data(), res.size());
	}

	m_isInitialized = true;
	return res;
}

vector<byte> Encryptor::update(vector<byte> input)
{
	if (m_isFinalized) throw logic_error("Already finalized");

	vector<byte> res;
	if (!m_isInitialized) res = initialize();

	string cipherText;
	StringSink sink(cipherText);
	m_streamFilter->Put(input.data(), input.size());
	m_outputFilter->TransferTo(sink);

	res.insert(res.end(), cipherText.begin(), cipherText.end());

	return res;
}

vector<byte> Encryptor::finalize()
{
	if (m_isFinalized) throw logic_error("Already finalized");
	if (!m_isInitialized) throw logic_error("Initialization not completed");

	string res;
	StringSink sink(res);
	m_streamFilter->MessageEnd();
	m_outputFilter->TransferTo(sink);

	m_isFinalized = true;

	return vector<byte>(res.begin(), res.end());
}
