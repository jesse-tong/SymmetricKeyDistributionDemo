#pragma once
#include <iostream>
#include <tuple>
#include <string>
#include <memory>
#include "cryptlib.h"
#include "modes.h"
#include "files.h"
#include "rsa.h"
#include "RSAClass.h"
#include "AESClass.h"

using namespace std;
using namespace CryptoPP;


//A struct mimics the structure of a possible message in a key distribution scheme
struct Message{
	//These two is for key and inititial vector used to encrypt/decrypt using DES 
	//(or the key used for communication after key distribution scheme)
	//Public key of sender
	RSA::PublicKey sentPubKey;
	string message; //Main message or other information (like identifiers)
	string message2; //Secondary message (like second nonce N2)
	string signature; //Signature used in second distribution approach
};

class Sender;
class Receiver;


class IClient {
public:

	RSA::PublicKey receiverPubkey;
	RSAClass keyPair;
	AESClass symmetricKeyFuncs; //This is used to encrypt and decrypt message using the secret key
	string secretKey;
	string firstNonce;
	string secondNonce;
public:

	IClient() { }
	virtual void response(Message m, int step) = 0;
	virtual void responseWithAuthentication(Message m, int step) = 0;
};

class Sender : public IClient {
public:
	Receiver *recvClient;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step);
};

class Receiver : public IClient {
public:
	Sender *sendClient;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step);
};

class MaliciousActor : virtual public Sender, virtual public Receiver {
public:
	RSAClass keyPair;
	AESClass symmetricKeyFuncs;
	string secretKey;
	RSA::PublicKey senderPubKey;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step) {} 
};

