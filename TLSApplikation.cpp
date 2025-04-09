#include "TLSApplikation.h"

TLSApplikation::TLSApplikation(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::TLSApplikationClass())
{
    ui->setupUi(this);

    m_pTLS = std::make_unique<TLS>(*this, Method::selectClient);
    ui->CurrentStatus->setText("--> Current Status: No connection...");

    connect(    ui->ExitAppButton   ,   &QPushButton::clicked, this , &TLSApplikation::OnExitAppButtonClicked    );
    connect(    ui->Connect         ,   &QPushButton::clicked, this , &TLSApplikation::OnConnectButtonClicked    );
    connect(    ui->EncryptionParam ,   &QPushButton::clicked, this , &TLSApplikation::OnEncryptionParamClicked  );
    connect(    ui->IsServer        ,   &QCheckBox  ::clicked, this , &TLSApplikation::OnIsServerCheckBoxClicked );
    connect(    ui->IsClient        ,   &QCheckBox  ::clicked, this , &TLSApplikation::OnIsClientCheckBoxClicked );
}


TLSApplikation::~TLSApplikation()
{
    delete ui;
}


Ui::TLSApplikationClass* TLSApplikation::GetUI()
{
    return ui;
}


void TLSApplikation::SetStatus(std::string status_text)
{
    ui->CurrentStatus->setText(status_text.c_str());
}


void TLSApplikation::InitSocket()
{
    if (!ui->IsEncrypted->isChecked()) {
        return;
    }

    if (ui->IsClient->isChecked()) {
        InitClientSocket();
    }
    else {
        InitServerSocket();
    }
}


void TLSApplikation::InitClientSocket()
{
    if (ui->Port->text().isEmpty() || ui->IPv4->text().isEmpty()) {
        return;
    }

    ui->CurrentStatus->setText("Setting up Client Socket");

    std::string strPort = ui->Port->text().toStdString();
    std::string strIP = ui->IPv4->text().toStdString();

    ClientSocket clientSocket(*this, strIP, strPort);

    ui->CurrentStatus->setText("Conneting to Server using Encryption!");

    SetUpEncryption(clientSocket.GetSocket());
}


void TLSApplikation::InitServerSocket()
{
    if (ui->Port->text().isEmpty())
    {
        return;
    }

    std::string strPort = ui->Port->text().toStdString();

    ServerSocket serverSocket(*this, strPort);

    SOCKET sock = serverSocket.GetSocket();
    SetUpServer(sock);
}


void TLSApplikation::SetUpEncryption(const SOCKET& nSocket)
{
    int nResult = m_pTLS->SetVersion(Version::TLSv1_2, Version::TLSv1_2);
    if (nResult != 1) { return; }

    nResult = m_pTLS->CreateSSL();
    if (nResult != 1) { return; }

    nResult = m_pTLS->SetEncryptedSocket(nSocket);
    if (nResult != 1) { return; }

    nResult = m_pTLS->EncryptedConnect();
    if (nResult != 1) { return; }

    ui->CurrentStatus->setText("Successfully connected!");
}

void TLSApplikation::SetUpServer(const SOCKET& nSocket)
{
    int nResult = m_pTLS->SetVersion(Version::TLSv1_2, Version::TLSv1_2);
    if (nResult != 1) { return; }

    nResult = m_pTLS->UseCertificate("C:/Users/lahas/Documents/OpenSSL Zertifikate & Schlüssel/certificate.pem");
    if (nResult != 1) { return; }

    nResult = m_pTLS->UsePrivateKey("C:/Users/lahas/Documents/OpenSSL Zertifikate & Schlüssel/private.pem");
    if (nResult != 1) { return; }

    nResult = m_pTLS->UseAlgorithm();
    if (nResult != 1) { return; }

    nResult = m_pTLS->CreateSSL();
    if (nResult != 1) { return; }

    nResult = m_pTLS->SetEncryptedSocket(nSocket);
    if (nResult != 1) { return; }

    nResult = m_pTLS->AcceptEncryptedClient();
    if (nResult != 1) { return; }

    ui->CurrentStatus->setText("Successfully accepted Client!");
}


void TLSApplikation::OnConnectButtonClicked()
{
    if (ui)
    {
        InitSocket();
    }
}

void TLSApplikation::OnEncryptionParamClicked()
{
    if (ui)
    {
        return; // TO DO
    }
}

void TLSApplikation::OnIsServerCheckBoxClicked()
{
    if (ui->IsServer->isChecked())
    {
        if (m_pTLS.get() != NULL)
        {
            m_pTLS = std::make_unique<TLS>(*this, Method::selectServer);

            ui->IsClient->setChecked(FALSE);
        }
        else
        {
            m_pTLS = std::make_unique<TLS>(*this, Method::selectServer);
        }
    }
}

void TLSApplikation::OnIsClientCheckBoxClicked()
{
    if (ui->IsClient->isChecked())
    {
        if (m_pTLS.get() != NULL)
        {
            m_pTLS = std::make_unique<TLS>(*this, Method::selectClient);

            ui->IsServer->setChecked(FALSE);
        }
        else
        {
            m_pTLS = std::make_unique<TLS>(*this, Method::selectClient);
        }
    }
}


void TLSApplikation::OnExitAppButtonClicked()
{
    if (ui)
    {
        QCoreApplication::quit();
    }
}