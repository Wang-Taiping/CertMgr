/**
* @brief Windows证书管理库
* @author acgnFun
* @date 2023/12/25
* @detail 提供简便的管理Windows证书存储的API，相对的功能受限
*/

// Windows原生证书管理API对于证书只支持DER_X509类型，即二进制类型
// 所以PEM_X509类型(base64编码)需先转化为DER_X509类型(base64解码)再安装

#include "CertMgr.h"
#include "base64.h"
#include <Windows.h>
#include <wincrypt.h>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <regex>
#include <iostream>

#pragma comment(lib, "Crypt32.lib")

typedef std::string _CertData;
typedef std::vector<_CertData> _CertFile;

CertMgr::CertStore CertMgr::OpenStore(CertStoreName Name)
{
	switch (Name)
	{
	case CertMgr::Certification_Authority:
		return (CertStore)CertOpenSystemStoreW(0, L"CA");
		break;
	case CertMgr::My_Certificate:
		return (CertStore)CertOpenSystemStoreW(0, L"MY");
		break;
	case CertMgr::Root_Certificate:
		return (CertStore)CertOpenSystemStoreW(0, L"ROOT");
		break;
	case CertMgr::Software_Publisher_Certificate:
		return (CertStore)CertOpenSystemStoreW(0, L"SPC");
		break;
	}
	return nullptr;
}

void CertMgr::CloseStore(CertStore Store)
{
	CertCloseStore(HCERTSTORE(Store), 0);
}

CertMgr::CertFile CertMgr::LoadCertificate(const char* Path, CertEncoding Encoding)
{
	std::fstream file(Path, std::ios::in | std::ios::binary);
	if (!file.is_open()) return nullptr;
	char* buffer = new char[1024];
	std::string cert_data;
	size_t gsize;
	while (!file.eof())
	{
		gsize = file.read(buffer, 1024).gcount();
		cert_data.append(buffer, gsize);
	}
	file.close();
	delete[] buffer;
	return LoadCertificate(cert_data.c_str(), cert_data.size(), Encoding);
}

CertMgr::CertFile CertMgr::LoadCertificate(const wchar_t* Path, CertEncoding Encoding)
{
	std::fstream file(Path, std::ios::in | std::ios::binary);
	char* buffer = new char[1024];
	std::string cert_data;
	size_t gsize;
	while (!file.eof())
	{
		gsize = file.read(buffer, 1024).gcount();
		cert_data.append(buffer, gsize);
	}
	file.close();
	delete[] buffer;
	return LoadCertificate(cert_data.c_str(), cert_data.size(), Encoding);
}

CertMgr::CertFile CertMgr::LoadCertificate(const void* Address, size_t Size, CertEncoding Encoding)
{
	_CertFile* pCertFile = nullptr;
	// TODO: 判断Encoding，读取证书链，DER只能读取到单个证书并直接载入，PEM可以读取为证书链（一组证书）但PEM需要转码为DER后再载入
	std::string temp;
	temp.append((char*)Address, Size);
	if (Encoding == DER_X509)
	{
		pCertFile = new _CertFile;
		pCertFile->push_back(temp);
		return CertFile(pCertFile);
	}
	else if (Encoding != PEM_X509) return nullptr;
	pCertFile = new _CertFile;
	std::stringstream Stream;
	Stream.str(temp);
	temp.clear();
	Stream.seekg(std::ios::beg);
	bool CertTag = false;
	std::regex begin("-+BEGIN.*-+");
	std::regex end("-+END.*-+");
	std::string buffer;
	char* cbuffer = nullptr;
	size_t bufsize = 0, lastbufsize = 0, decodesize = 0;
	while (!Stream.eof())
	{
		std::getline(Stream, temp);
		if (temp.empty()) continue;
		while (!temp.empty() && temp.back() == '\r') temp.pop_back();
		if (std::regex_match(temp, begin))
		{
			CertTag = true;
			buffer.clear();
			continue;
		}
		else if (std::regex_match(temp, end))
		{
			CertTag = false;
			bufsize = base64_decode_calc_buffer(buffer.size());
			if (bufsize == size_t(-1)) continue;
			if (bufsize > lastbufsize || cbuffer == nullptr)
			{
				lastbufsize = bufsize;
				if (cbuffer) delete[] cbuffer;
				cbuffer = new char[bufsize];
			}
			if ((decodesize = base64_decode(buffer.c_str(), buffer.size(), cbuffer, bufsize)) == size_t(-1))
				continue;
			buffer.clear();
			buffer.append(cbuffer, decodesize);
			pCertFile->push_back(buffer);
			continue;
		}
		else buffer += temp;
	}
	if (cbuffer) delete[] cbuffer;
	return CertFile(pCertFile);
}

size_t CertMgr::GetMaxCertificateIndex(CertFile Certificate)
{
	if (Certificate == nullptr) return 0;
	return ((_CertFile*)Certificate)->size() - 1;
}

void CertMgr::ReleaseCertificate(CertFile Certificate)
{
	if (Certificate == nullptr) return;
	delete (_CertFile*)Certificate;
}

CertMgr::CertData CertMgr::GetCertificateData(CertFile Certificate, size_t Index)
{
	if (Certificate == nullptr) return nullptr;
	if (Index > GetMaxCertificateIndex(Certificate)) return nullptr;
	return CertData(&(((_CertFile*)Certificate)->at(Index)));
}

CertMgr::CertContext CertMgr::LoadCertContext(CertData CertificateData)
{
	if (CertificateData == nullptr) return nullptr;
	_CertData* hCertData = (_CertData*)CertificateData;
	return CertContext(CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE*)hCertData->c_str(), hCertData->size()));
}

void CertMgr::ReleaseCertContext(CertContext Context)
{
	if (Context == nullptr) return;
	CertFreeCertificateContext(PCCERT_CONTEXT(Context));
}

bool CertMgr::AddCertificateToStore(CertStore Store, CertData CertificateData, bool Update)
{
	if (Store == nullptr || CertificateData == nullptr) return false;
	HCERTSTORE hCertStore = HCERTSTORE(Store);
	_CertData* hCertData = (_CertData*)CertificateData;
	return CertAddEncodedCertificateToStore(hCertStore, X509_ASN_ENCODING, (const BYTE*)hCertData->c_str(), hCertData->size(), Update ? CERT_STORE_ADD_REPLACE_EXISTING : CERT_STORE_ADD_NEW, nullptr);
}

bool CertMgr::DelCertificateFromStore(CertStore Store, CertContext Context)
{
	if (Store == nullptr || Context == nullptr) return false;
	HCERTSTORE hCertStore = HCERTSTORE(Store);
	PCCERT_CONTEXT pCertContext = PCCERT_CONTEXT(Context);
	PCCERT_CONTEXT pPrevCertContext = nullptr;
	bool Finded = false, t1, t2, t3;
	WCHAR szCertName[256] = { 0 };
	memset(szCertName, 0, sizeof(WCHAR) * 256);
	CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, szCertName, 256);
	std::wcout << szCertName << std::endl;
	while (pPrevCertContext = CertEnumCertificatesInStore(hCertStore, pPrevCertContext))
	{
		memset(szCertName, 0, sizeof(WCHAR) * 256);
		CertGetNameStringW(pPrevCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, szCertName, 256);
		std::wcout << szCertName << std::endl;
		t1 = CertCompareCertificateName(X509_ASN_ENCODING, &(pCertContext->pCertInfo->Subject), &(pPrevCertContext->pCertInfo->Subject));
		t2 = CertComparePublicKeyInfo(X509_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), &(pPrevCertContext->pCertInfo->SubjectPublicKeyInfo));
		t3 = CertCompareCertificate(X509_ASN_ENCODING, pCertContext->pCertInfo, pPrevCertContext->pCertInfo);
		if (t1 && t2 && t3)
		{
			CertDeleteCertificateFromStore(pPrevCertContext);
			Finded = true;
			break;
		}
	}
	return Finded;
}
