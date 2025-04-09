#include "TLS.h"
#include "TLSApplikation.h"


TLS_Config::TLS_Config(Method method):
	m_pCtx(NULL),
	m_pSSL(NULL)
{
	if (method == Method::selectServer)
	{
		m_pCtx = SSL_CTX_new(TLS_server_method());
	}
	else if (method == Method::selectClient)
	{
		m_pCtx = SSL_CTX_new(TLS_client_method());
	}
	else
	{
		m_pCtx = nullptr;
	}
}

TLS_Config::~TLS_Config()
{
	Reset();
}

void TLS_Config::Reset()
{
	if (m_pSSL)
	{
		SSL_free(m_pSSL);
		m_pSSL = nullptr;
	}

	if (m_pCtx)
	{
		SSL_CTX_free(m_pCtx);
		m_pCtx = nullptr;
	}
}

TLS::TLS(TLSApplikation& app, Method method)
	: m_pApp(&app)
{
	m_pParam = std::make_unique<TLS_Config>(method);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}

int TLS::SetVersion(const Version MinVersion, const Version MaxVersion)
{
	try 
	{
		int nResult = SSL_CTX_set_min_proto_version(m_pParam.get()->m_pCtx, MinVersion);
		if (nResult <= 0)
			return nResult;

		nResult = SSL_CTX_set_max_proto_version(m_pParam.get()->m_pCtx, MaxVersion);
		if (nResult <= 0)
			return nResult;

		return nResult;
	}
	catch (std::exception& error)
	{
		std::cout << "Error occured: " << error.what() << std::endl;
	}

}

int TLS::CreateSSL()
{
	try
	{
		if ((m_pParam.get()->m_pCtx))
		{
			m_pParam.get()->m_pSSL = SSL_new(m_pParam.get()->m_pCtx);

			if (m_pParam.get()->m_pSSL != NULL)
				return 1;
		}
		else
			return 2;
	}
	catch (std::exception& error)
	{
		std::cout << "Error occured: " << error.what() << std::endl;
	}
}

int TLS::EncryptedConnect()
{
	try
	{
		int nRes = SSL_connect(m_pParam.get()->m_pSSL);

		return nRes;
	}
	catch (std::exception& error)
	{
		std::cout << "Error occured: " << error.what() << std::endl;
	}
}

int TLS::SetEncryptedSocket(const SOCKET& nSocket)
{
	try
	{
		int nRes = SSL_set_fd(m_pParam.get()->m_pSSL, nSocket);
		return nRes;
	}
	catch (std::exception& error)
	{
		std::cout << "Error occured: " << error.what() << std::endl;
	}
}

int TLS::AcceptEncryptedClient()
{
	try
	{
		int nRes = SSL_accept(m_pParam.get()->m_pSSL);

		if (nRes <= 0)
		{
			int nErr = SSL_get_error(m_pParam.get()->m_pSSL, nRes);

			std::string strError;
			if (nErr == SSL_ERROR_SSL)
			{
				unsigned long errCode;
				while ((errCode = ERR_get_error()) != 0)
				{
					char buf[256];
					ERR_error_string_n(errCode, buf, sizeof(buf));
					strError += "OpenSSL error: " + std::string(buf) + "\n";
				}
			}
			else
			{
				// Anderer Fehler bei SSL_accept
				switch (nErr)
				{
				case SSL_ERROR_ZERO_RETURN:
					strError = "SSL connection closed.";
					break;
				case SSL_ERROR_WANT_READ:
					strError = "SSL_accept needs to read more data.";
					break;
				case SSL_ERROR_WANT_WRITE:
					strError = "SSL_accept needs to write more data.";
					break;
				case SSL_ERROR_SYSCALL:
					strError = "I/O error during SSL_accept.";
					break;
				default:
					strError = "Unknown SSL error.";
					break;
				}
			}

			m_pApp->SetStatus("Fehler bei SSL_accept: " + strError + "\n");
		}

		return nRes;
	}
	catch (std::exception& error)
	{
		std::string strError = "Error occured: " + std::string(error.what()) + "\n";
	}

	return 1;
}

int TLS::UseCertificate(const std::string file)
{
	try
	{
		int nResult = SSL_CTX_use_certificate_file(m_pParam.get()->m_pCtx, file.c_str(), SSL_FILETYPE_PEM);
		return nResult;
	}
	catch (std::exception& error)
	{
		std::string strError = "Error occured: " + std::string(error.what()) + "\n";
	}

	return 3;
}

int TLS::UsePrivateKey(const std::string file)
{
	try
	{
		int nResult = SSL_CTX_use_PrivateKey_file(m_pParam.get()->m_pCtx, file.c_str(), SSL_FILETYPE_PEM);
		return nResult;
	}
	catch (std::exception& error)
	{
		std::string strError = "Error occured: " + std::string(error.what()) + "\n";
	}

	return 4;
}

int TLS::UseAlgorithm()
{
	try
	{
		int nResult = SSL_CTX_set_cipher_list(m_pParam.get()->m_pCtx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
		return nResult;
	}
	catch (std::exception& error)
	{
		std::string strError = "Error occured: " + std::string(error.what()) + "\n";
	}

	return 6;
}
