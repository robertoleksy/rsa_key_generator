#include <iostream>
#include <chrono>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/eccrypto.h>
#include <crypto++/oids.h>

using namespace CryptoPP;

void GenKeyPair(unsigned int keySize) {
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, keySize);
 
	// Create Keys
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);
	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	/*Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();*/
	 
	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	//RSAFunction pubkey(privkey);
	
	/*Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();*/
 
}

void test(unsigned int keySize) {
	const int numberOfTests = 5;
	std::cout << "generate " << numberOfTests << " keys, size = " << keySize << std::endl;
    std::chrono::time_point<std::chrono::steady_clock> start_time = std::chrono::steady_clock::now();
	for (int i = 0; i < numberOfTests; ++i) {
		GenKeyPair(keySize);
	}
	std::chrono::time_point<std::chrono::steady_clock> stop_time = std::chrono::steady_clock::now();
	std::chrono::steady_clock::duration diff = stop_time - start_time;
	std::cout << "time: " << std::chrono::duration_cast<std::chrono::milliseconds>(diff).count() << "ms" << std::endl;
}

////////////////ECDSA////////////////

void ECDSAGenKeyPair(unsigned int keySize) {
	AutoSeededRandomPool rng;
	DL_GroupParameters_EC<ECP> params(ASN1::secp160r1());

	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	ECDSA<ECP, SHA1>::PublicKey publicKey;

	privateKey.Initialize(rng, params);
	privateKey.MakePublicKey(publicKey);
}


int main(int argc, char **argv) {
	
	test(2048);
	test(4096);
	test(8192);
	
    return 0;
}
