// SymmetricKeyDistribution.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include "AESClass.h"
#include "RSAClass.h"
#include "Agent.h"


int main()
{
	cout << "Scenario of A and B using simple key distribution scheme.\n";
	
	Sender* s =  new Sender(); Receiver *r = new Receiver();
	s->recvClient = r; r->sendClient = s;
	Message m;
	s->response(m, 0);

	cout << "\n\n-------------------------------------------------------------------------------\n\n";
	cout << "Scenario of malicious actor intercepting A and B using simple key distribution scheme.\n";

	MaliciousActor* a = new MaliciousActor();
	s->recvClient = a; a->recvClient = r; //Intercept between A -> B: A -> M -> B
	r->sendClient = a; a->sendClient = s; //Intercept between B -> A: B -> M -> A
	s->response(m, 0);

	cout << "\n\n-------------------------------------------------------------------------------\n\n";
	cout << "Scenario of malicious actor intercepting A and B using key distribution scheme with authentication.\n";
	s->recvClient = r; r->sendClient = s;
	s->responseWithAuthentication(m, 0);

	delete s; delete r; delete a;

	return 0;
}

