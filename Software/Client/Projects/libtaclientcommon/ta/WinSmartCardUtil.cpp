#include "WinSmartCardUtil.h"
#ifdef _WIN32

#include "ta/logger.h"
#include "ta/certutils.h"
#include "ta/encodingutils.h"
#include "ta/scopedresource.hpp"
#include <windows.h>


// For CreateCSV
//#include "Tpmvscmgr.h"
//#include "StrSafe.h"


namespace ta
{
    namespace WinSmartCardUtil
    {
        using std::string;
        using std::vector;
        using std::auto_ptr;

        struct ScopedCryptProvider
        {
            HCRYPTPROV myCryptProv;
            ScopedCryptProvider(HCRYPTPROV aCryptProv)
            {
                myCryptProv = aCryptProv;
            }
            ~ScopedCryptProvider()
            {
                CryptReleaseContext(myCryptProv, 0);
            }
        };

        bool hasSmartCard()
        {
            SCARDCONTEXT	hSC = NULL;
            LPTSTR          pmszReaders = NULL;
            LPTSTR          pReader;
            DWORD     cch = SCARD_AUTOALLOCATE;
            int				scardCount = 0;

            const LONG lReturn = SCardListReaders(hSC, NULL, (LPTSTR)&pmszReaders, &cch);

            if (lReturn == SCARD_S_SUCCESS)
            {
                pReader = pmszReaders;
                while ('\0' != *pReader)
                {
                    scardCount++;
                    pReader = pReader + wcslen((wchar_t *)pReader) + 1;
                }

                const LONG lReturnFree = SCardFreeMemory(hSC, pmszReaders);
                if (SCARD_S_SUCCESS != lReturnFree)
                {
                    TA_THROW_MSG(std::runtime_error, boost::format("Failed to free smart card memory. SCardFreeMemory failed with code %d") % lReturnFree);
                }

                return scardCount > 0;
            }
            else if (lReturn == SCARD_E_NO_READERS_AVAILABLE)
            {
                return false;
            }
            TA_THROW_MSG(std::runtime_error, boost::format("An unknown error occurred in hasSmartCard with error code %d") % lReturn);
        }

        vector<unsigned char> doCryptEncodeObject(const CERT_NAME_INFO& aCertNameInfo)
        {
            DWORD myNameEncodedLength;
            if (!CryptEncodeObject(
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),     //i  Encoding type
                        X509_NAME,            //i  Structure type
                        &aCertNameInfo,                //i  Address of CERT_NAME_INFO structure
                        NULL,                 //o  pbEncoded
                        &myNameEncodedLength))      //io pbEncoded size
            {
                TA_THROW_MSG(std::runtime_error, boost::format("The first call to CryptEncodeObject failed. A public/private key pair may not exist in the container. Errorcode: %d") % GetLastError());
            }

            vector<unsigned char> myNameEncoded(myNameEncodedLength);

            if (!CryptEncodeObject(
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),    //i  Encoding type
                        X509_NAME,           //i  Structure type
                        &aCertNameInfo,               //i  Address of CERT_NAME_INFO structure
                        &myNameEncoded[0],       //o  pbEncoded
                        &myNameEncodedLength))     //io pbEncoded size
            {
                TA_THROW_MSG(std::runtime_error, boost::format("The second call to CryptEncodeObject failed. Errorcode: %d") % GetLastError());
            }
            return myNameEncoded;
        }

        auto_ptr<CERT_PUBLIC_KEY_INFO> doCryptExportPublicKeyInfo(const HCRYPTPROV& aCryptProv)
        {
            DWORD myPublicKeyInfoLength;
            if (!CryptExportPublicKeyInfo(
                        aCryptProv,            //i  Provider handle
                        AT_SIGNATURE,          //i  Key spec
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),      //i  Encoding type
                        NULL,                  //o  pbPublicKeyInfo
                        &myPublicKeyInfoLength))     //io Size of PublicKeyInfo
            {
                TA_THROW_MSG(std::runtime_error, boost::format("The first call to CryptExportPublickKeyInfo failed."
                             " The probable cause is that there is no key pair in the key container."
                             " Errorcode: %d") % GetLastError());
            }

            auto_ptr<CERT_PUBLIC_KEY_INFO> myPublicKeyInfo(static_cast<CERT_PUBLIC_KEY_INFO*>(::operator new(myPublicKeyInfoLength)));

            if (!CryptExportPublicKeyInfo(
                        aCryptProv,            //i  Provider handle
                        AT_SIGNATURE,          //i  Key spec
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),      //i  Encoding type
                        myPublicKeyInfo.get(),       //o  pbPublicKeyInfo
                        &myPublicKeyInfoLength))     //io Size of PublicKeyInfo
            {
                TA_THROW_MSG(std::runtime_error, boost::format("The second call to CryptExportPublicKeyInfo failed. Errorcode: %d") % GetLastError());
            }
            return myPublicKeyInfo;
        }

        string doCryptSignAndEncodeCertificate(const HCRYPTPROV& aCryptProv, const CERT_REQUEST_INFO& aCertReqInfo, CRYPT_ALGORITHM_IDENTIFIER& aSigAlg)
        {
            DWORD myEncodedCertReqSize;
            if (!CryptSignAndEncodeCertificate(
                        aCryptProv,                      //i  Crypto provider
                        AT_SIGNATURE,                    //i  Key spec
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),                //i  Encoding type
                        X509_CERT_REQUEST_TO_BE_SIGNED,  //i  Structure type
                        &aCertReqInfo,                    //i  Structure information
                        &aSigAlg,                         //i  Signature algorithm
                        NULL,                            //i  Not used
                        NULL,                            //o  pbSignedEncodedCertReq
                        &myEncodedCertReqSize))          //io Size of certificate
            {
                TA_THROW_MSG(std::runtime_error, boost::format("First call to CryptSignAndEncodeCertificate failed. Errorcode: %d") % GetLastError());
            }

            vector<unsigned char> mySignedEncodedCertReq(myEncodedCertReqSize);

            if (!CryptSignAndEncodeCertificate(
                        aCryptProv,                     //i  Crypto provider
                        AT_SIGNATURE,                   //i  Key spec
                        (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),               //i  Encoding type
                        X509_CERT_REQUEST_TO_BE_SIGNED, //i  Struct type
                        &aCertReqInfo,                   //i  Struct info
                        &aSigAlg,                        //i  Signature algorithm
                        NULL,                           //i  Not used
                        &mySignedEncodedCertReq[0],   //o  Pointer
                        &myEncodedCertReqSize))         //io Length of the message
            {
                TA_THROW_MSG(std::runtime_error, boost::format("The second call to CryptSignAndEncodeCertificate failed. Errorcode: %d") % GetLastError());
            }
            return "-----BEGIN CERTIFICATE REQUEST-----\n" + ta::EncodingUtils::toBase64(mySignedEncodedCertReq) + "\n-----END CERTIFICATE REQUEST-----\n";
        }

        string requestCsr(const resept::CsrRequirements& aCsrRequirements)
        {
            return requestCsr(
                       aCsrRequirements.subject.cn,
                       aCsrRequirements.subject.c,
                       aCsrRequirements.subject.st,
                       aCsrRequirements.subject.l,
                       aCsrRequirements.subject.o,
                       aCsrRequirements.subject.ou,
                       aCsrRequirements.subject.e,
                       aCsrRequirements.key_size,
                       aCsrRequirements.signing_algo
                   );
        }

        string requestCsr(const string& aCn,
                          const string& aC,
                          const string& aSt,
                          const string& anL,
                          const string& anO,
                          const string& anOu,
                          const string& anE,
                          const unsigned int aKeySize,
                          const ta::SignUtils::Digest aSigningAlg)
        {
            vector<unsigned char> myCnVec(ta::str2Vec<unsigned char>(aCn));
            vector<unsigned char> myCVec(ta::str2Vec<unsigned char>(aC));
            vector<unsigned char> myStVec(ta::str2Vec<unsigned char>(aSt));
            vector<unsigned char> myLVec(ta::str2Vec<unsigned char>(anL));
            vector<unsigned char> myOVec(ta::str2Vec<unsigned char>(anO));
            vector<unsigned char> myOuVec(ta::str2Vec<unsigned char>(anOu));
            vector<unsigned char> myEVec(ta::str2Vec<unsigned char>(anE));

            const CERT_RDN_ATTR rgCnAttr = {
                szOID_COMMON_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myCnVec.size(),
                &myCnVec[0]
            };
            const CERT_RDN_ATTR rgCAttr = {
                szOID_COUNTRY_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myCVec.size(),
                &myCVec[0]
            };
            const CERT_RDN_ATTR rgStAttr = {
                szOID_STATE_OR_PROVINCE_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myStVec.size(),
                &myStVec[0]
            };
            const CERT_RDN_ATTR rgLAttr = {
                szOID_LOCALITY_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myLVec.size(),
                &myLVec[0]
            };
            const CERT_RDN_ATTR rgOAttr = {
                szOID_ORGANIZATION_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myOVec.size(),
                &myOVec[0]
            };
            const CERT_RDN_ATTR rgOuAttr = {
                szOID_ORGANIZATIONAL_UNIT_NAME,
                CERT_RDN_PRINTABLE_STRING,
                myOuVec.size(),
                &myOuVec[0]
            };
            const CERT_RDN_ATTR rgEAttr = {
                szOID_RSA_emailAddr,
                CERT_RDN_PRINTABLE_STRING,
                myEVec.size(),
                &myEVec[0]
            };

            CERT_RDN_ATTR rgAttrArray[] = { rgCnAttr, rgCAttr, rgStAttr, rgLAttr, rgOAttr, rgOuAttr, rgEAttr };
            CERT_RDN rgRDN[] = { sizeof(rgAttrArray) / sizeof(rgAttrArray[0]), rgAttrArray };
            const CERT_NAME_INFO myCertNameInfo = { 1, rgRDN };

            vector<unsigned char> myNameEncoded = doCryptEncodeObject(myCertNameInfo);
            CERT_NAME_BLOB SubjNameBlob = { myNameEncoded.size(), &myNameEncoded[0] };

            CERT_REQUEST_INFO myCertReqInfo;
            myCertReqInfo.Subject = SubjNameBlob;
            myCertReqInfo.cAttribute = 0;
            myCertReqInfo.rgAttribute = NULL;
            myCertReqInfo.dwVersion = CERT_REQUEST_V1;

            HCRYPTPROV myCryptProv;
            if (!CryptAcquireContext(
                        &myCryptProv,        //o Address for handle to be returned.
                        NULL,               //i Use the current user's logon name.
                        MS_SCARD_PROV,      //i Use Smart Card provider.
                        PROV_RSA_FULL,      //i Need to both encrypt and sign.
                        CRYPT_MACHINE_KEYSET))              //i No flags needed.
            {
                TA_THROW_MSG(std::runtime_error, boost::format("CryptAcquireContext failed. Errorcode: %d") % GetLastError());
            }
            ScopedCryptProvider myCryptProvScoped(myCryptProv);

            auto_ptr<CERT_PUBLIC_KEY_INFO> myPublicKeyInfo = doCryptExportPublicKeyInfo(myCryptProv);
            myCertReqInfo.SubjectPublicKeyInfo = *myPublicKeyInfo.get();

            const unsigned int myKeySizeBits = myPublicKeyInfo->PublicKey.cbData * 8 - myPublicKeyInfo->PublicKey.cUnusedBits;
            if (aKeySize != myKeySizeBits)
            {
                TA_THROW_MSG(std::runtime_error, boost::format("Invalid KeySize for public key. Expected keySize %d, got %d") % aKeySize % myKeySizeBits);
            }

            CRYPT_ALGORITHM_IDENTIFIER mySigAlg;
            switch (aSigningAlg)
            {
            case ta::SignUtils::digestSha1:
                mySigAlg.pszObjId = szOID_RSA_SHA1RSA;
                break;
            case ta::SignUtils::digestSha256:
                mySigAlg.pszObjId = szOID_RSA_SHA256RSA;
                break;
            default:
                TA_THROW_MSG(std::invalid_argument, boost::format("Signature algorithm not supported for signature algorithm: %s") % str(aSigningAlg));
                break;
            }
            CRYPT_OBJID_BLOB Parameters = {};
            mySigAlg.Parameters = Parameters;

            const string myCsr = doCryptSignAndEncodeCertificate(myCryptProv, myCertReqInfo, mySigAlg);
            if (!ta::CertUtils::isValidCsr(myCsr))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("Invalid CSR generated with CSR: %s") % myCsr);
            }
            if (ta::CertUtils::parseSignedCSR(myCsr).pubKeyBits != aKeySize)
            {
                TA_THROW_MSG(std::runtime_error, boost::format("Invalid KeySize for CSR. Expected keySize %d, got %d") % aKeySize % ta::CertUtils::parseSignedCSR(myCsr).pubKeyBits);
            }
            return myCsr;
        } // End of requestCsr

#if 0
        // Used for createVsc
        void getGUID2String(const REFCLSID rclsid, WCHAR** wszCLSID)
        {
            HRESULT hr = StringFromCLSID(rclsid, wszCLSID);
            if (FAILED(hr))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("StringFromGUID2 failed with code: %s") % hr);
            }
        }

        // Used for createVsc
        void getMonikerName(const WCHAR* wszCLSID, WCHAR** wszMonikerName)
        {
            // @Andrei, cannot figure out how to get the array size from the pointer-to-pointer -- TODO (tim)
            HRESULT hr = StringCchPrintfW(*wszMonikerName, 300 / sizeof(WCHAR), L"Elevation:Administrator!new:%s", wszCLSID);
            if (FAILED(hr))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("StringCchPrintfW failed with code 0x%X") % hr);
            }
        }

        // Used for createVsc
        HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void ** ppv)
        {
            BIND_OPTS3 bo;
            WCHAR  wszCLSID[50] = {};
            WCHAR  wszMonikerName[300] = {};
            WCHAR *wszCLSIDPtr = &wszCLSID[0];
            WCHAR *wszMonikerNamePtr = &wszMonikerName[0];

            getGUID2String(rclsid, &wszCLSIDPtr);
            getMonikerName(wszCLSID, &wszMonikerNamePtr);

            memset(&bo, 0, sizeof(bo));
            bo.cbStruct = sizeof(bo);
            bo.hwnd = hwnd;
            bo.dwClassContext = CLSCTX_LOCAL_SERVER;
            return CoGetObject(wszMonikerNamePtr, &bo, riid, ppv);
        }

        void createVsc()
        {
            HRESULT hr = S_OK;
            HWND hwnd = NULL; // Initialized with the parent window handle of UAC prompt.
            ITpmVirtualSmartCardManager *pObj;

            hr = CoInitialize(NULL);
            if (FAILED(hr))
                TA_THROW_MSG(std::runtime_error, "FAILED TO COINITIALIZE");

            hr = CoCreateInstanceAsAdmin(
                     hwnd,
                     CLSID_TpmVirtualSmartCardManager,
                     IID_ITpmVirtualSmartCardManager,
                     (void**)&pObj);

            if (FAILED(hr))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("CoGetObject failed with code 0x%X") % hr);
            }

            LPWSTR mySmartCardName = L"TestVirtualSmartCard";
            BYTE adminAlgId = 0x82;
            const BYTE adminKey[24] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            DWORD adminKeySize = 24;
            BYTE pin[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            DWORD pinSize = 8;

            LPWSTR outInstanceId = NULL;
            BOOL outNeedReboot = false;

            BOOL shouldGenerate = true; // Generate file system in VSC, needed to use certificates. Therefore must be true
            hr = pObj->CreateVirtualSmartCard(mySmartCardName, TPMVSC_DEFAULT_ADMIN_ALGORITHM_ID, adminKey, adminKeySize, NULL, 0, NULL, 0, pin, pinSize, shouldGenerate, NULL, &outInstanceId, &outNeedReboot);
            if (FAILED(hr))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("CreateVirtualSmartCard failed with code 0x%X") % hr);
            }

            WARNLOG(boost::format("OUT INSTANCE ID: %s") % outInstanceId);
        }
        // End of commented code
#endif

    } // end WinSmartCardUtil namespace
} // end ta namespace

#else
//no
#endif