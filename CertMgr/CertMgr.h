/**
* @brief Windows证书管理库
* @author acgnFun
* @date 2023/12/25
* @detail 提供简便的管理Windows证书存储的API，相对的功能受限
*/

#pragma once

#ifndef CERTMGR_H
#define CERTMGR_H

#include <stdint.h>

#define DEFINE_HANDLE(name)	struct __##name { int unused; }; typedef __##name *name

#ifdef __cplusplus

namespace CertMgr
{
	DEFINE_HANDLE(CertStore);
	DEFINE_HANDLE(CertFile);
	DEFINE_HANDLE(CertData);
	DEFINE_HANDLE(CertContext);

	enum CertStoreName
	{
		Certification_Authority,
		My_Certificate,
		Root_Certificate,
		Software_Publisher_Certificate
	};

	enum CertEncoding
	{
		PEM_X509, // Base64 encoding
		DER_X509 // Binary (no encoding)
	};

	CertStore OpenStore(CertStoreName Name);
	void CloseStore(CertStore Store);

	CertFile LoadCertificate(const char* Path, CertEncoding Encoding);
	CertFile LoadCertificate(const wchar_t* Path, CertEncoding Encoding);
	CertFile LoadCertificate(const void* Address, size_t Size, CertEncoding Encoding);
	size_t GetMaxCertificateIndex(CertFile Certificate);
	void ReleaseCertificate(CertFile Certificate);

	CertData GetCertificateData(CertFile Certificate, size_t Index = 0);

	CertContext LoadCertContext(CertData CertificateData);
	void ReleaseCertContext(CertContext Context);

	bool AddCertificateToStore(CertStore Store, CertData CertificateData, bool Update = false);
	bool DelCertificateFromStore(CertStore Store, CertContext Context);
}

#endif // __cplusplus

#endif // !CERTMGR_H
