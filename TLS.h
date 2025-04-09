#pragma once

#undef UNICODE

//#define WIN32_LEAN_AND_MEAN
//#define _CRT_SECURE_NO_WARNINGS

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <cstdlib>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

class TLSApplikation;

enum Method
{
	selectServer = 1,
	selectClient = 2
};

enum Version
{
	TLSv1_2 = TLS1_2_VERSION,
	TLSv1_3 = TLS1_3_VERSION
};

class TLS_Config 
{
public:
	explicit TLS_Config(Method method);
	~TLS_Config();

	void Reset();

	SSL_CTX* m_pCtx;
	SSL* m_pSSL;
};

class TLS
{
public:
	TLS(TLSApplikation& app, Method method);
	~TLS() = default;

	int SetVersion(const Version MinVersion, const Version MaxVersion);
	int CreateSSL();
	int EncryptedConnect();
	int SetEncryptedSocket(const SOCKET& nSocket);
	int AcceptEncryptedClient();
	int UseCertificate(const std::string file);
	int UsePrivateKey(const std::string file);
	int UseAlgorithm();

private:
	TLSApplikation* m_pApp;
	std::unique_ptr<TLS_Config> m_pParam;
};
