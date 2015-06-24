#include <iostream>
#include <chrono>
#include <string>

#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/eccrypto.h>
#include <crypto++/oids.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>

using namespace CryptoPP;
void ECDSAGenKeyPair(unsigned int keySize);

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

////////////////ECDSA////////////////

//http://tools.ietf.org/html/rfc4492
//                     Symmetric  |   ECC   |  DH/DSA/RSA
//                    ------------+---------+-------------
//                         80     |   163   |     1024
//                        112     |   233   |     2048
//                        128     |   283   |     3072
//                        192     |   409   |     7680
//                        256     |   571   |    15360
// 
//                   Table 1: Comparable Key Sizes (in bits)
// 
void ECDSAGenKeyPair(unsigned int keySize = 0) {
	AutoSeededRandomPool rng;
	DL_GroupParameters_EC<ECP> params(ASN1::secp521r1());

	ECDSA<ECP, SHA512>::PrivateKey privateKey;
	ECDSA<ECP, SHA512>::PublicKey publicKey;
	privateKey.Initialize(rng, params);
	privateKey.MakePublicKey(publicKey);
	
	// save keys to files
	/*Base64Encoder pubkeysink(new FileSink("key_1.pub"));
	publicKey.DEREncodePublicKey(pubkeysink);
	pukeysink.MessageEnd();*/
	ByteQueue pubKeyBytes;
	publicKey.Save(pubKeyBytes);
	Base64Encoder publicKeyEncoder(new FileSink("key_1.pub"));
	pubKeyBytes.CopyTo(publicKeyEncoder);
	publicKeyEncoder.MessageEnd();
	
	
	ByteQueue prvKeyBytes;
	privateKey.Save(prvKeyBytes);
	Base64Encoder prvKeyEncoder(new FileSink("key_1.prv"));
	prvKeyBytes.CopyTo(prvKeyEncoder);
	prvKeyEncoder.MessageEnd();
	
	/*FileSink fs( "key_1.prv", false);
	privateKey.Save(fs);*/
}


void ECDSASignFile(const std::string &filename) {
	AutoSeededRandomPool rng;
	// load private key
	ECDSA<ECP, SHA512>::PrivateKey privateKey;
	ByteQueue bytes;
	std::cout << "start load prv key" << std::endl;
	FileSource prvKeyFile("key_1.prv", true, new Base64Decoder);
	prvKeyFile.TransferTo(bytes);
	bytes.MessageEnd();
 	std::cout << "load bytes" << std::endl;
	privateKey.Load(bytes);
	
	//bytes.CopyTo(decoder);
	std::cout << "end of load prv key" << std::endl;
	std::cout << "validate prv key " << std::endl;
	if (privateKey.Validate(rng, 3) == false) {
		std::cout << "prv key validate error";
		return;
	}
	std::cout << "prv key validate OK" << std::endl;

	std::cout << "start load clear file" << std::endl;
	std::string strContents;
	FileSource(filename.c_str(), true, new StringSink(strContents));
	
	ECDSA<ECP, SHA512>::Signer signer(privateKey);
	SecByteBlock sbbSignature(signer.SignatureLength());
	std::cout << "sign message" << std::endl;
	signer.SignMessage(rng,
		(byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);
	
	std::cout << "Save result" << std::endl;
	FileSink sinksig(std::string(filename + ".sig").c_str());
	sinksig.Put(sbbSignature, sbbSignature.size());
	sinksig.MessageSeriesEnd();
}

void ECDSAVerifyFile(const std::string &filename, const std::string &signatureFileName) {
	AutoSeededRandomPool rng;
	// load pub key from file
	std::string pubKeyFilename("key_1.pub");
	std::cout << "load pub key form " << pubKeyFilename << std::endl;
	CryptoPP::ByteQueue bytes;
	ECDSA<ECP, SHA512>::PublicKey publicKey;
	FileSource file(pubKeyFilename.c_str(), true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	publicKey.Load(bytes);
	if (publicKey.Validate(rng, 3) == false) {
		std::cout << "pub key validate error";
		return;
	}
	std::cout << "pub key validate OK" << std::endl;

	std::string signature, clearData;
	ECDSA<ECP, SHA512>::Verifier verifier(publicKey);
	std::cout << "load clear text file " << filename << std::endl;
	FileSource(filename.c_str(), true, new StringSink(clearData));
	std::cout << "load signature from file " << signatureFileName << std::endl;
	FileSource(signatureFileName.c_str(), true, new StringSink(signature));
	std::string combined(clearData);
	combined.append(signature);
	std::cout << "start verify" << std::endl;
	try {
		StringSource(combined, true,
			new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION));
		std::cout << "verify OK" << std::endl;
	}
	catch (SignatureVerificationFilter::SignatureVerificationFailed &err) {
		std::cout << "verify error " << err.what() << std::endl;
	}
}

void test(unsigned int keySize, void (*f)(unsigned int)) {
	const int numberOfTests = 5;
	std::cout << "generate " << numberOfTests << " keys, size = " << keySize << std::endl;
    std::chrono::time_point<std::chrono::steady_clock> start_time = std::chrono::steady_clock::now();
	for (int i = 0; i < numberOfTests; ++i) {
		//GenKeyPair(keySize);
		//ECDSAGenKeyPair(keySize);
		f(keySize);
	}
	std::chrono::time_point<std::chrono::steady_clock> stop_time = std::chrono::steady_clock::now();
	std::chrono::steady_clock::duration diff = stop_time - start_time;
	std::cout << "time: " << std::chrono::duration_cast<std::chrono::milliseconds>(diff).count() << "ms" << std::endl;
}

int main(int argc, char **argv) {
	
	//test(2048, GenKeyPair);
	//test(4096, ECDSAGenKeyPair);
	ECDSAGenKeyPair();
	std::cout << "sign test.txt" << std::endl;
	ECDSASignFile("test.txt");
	ECDSAVerifyFile("test.txt", "test.txt.sig");
    return 0;
}
