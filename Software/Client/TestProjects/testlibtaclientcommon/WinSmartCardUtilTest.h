#ifndef _WIN32
#error "This file is meant for Windows only"
#endif
#include "ta/WinSmartCardUtil.h"
#include "ta/certutils.h"
#include "ta/osinfoutils.h"
#include "ta/version.h"
#include "cxxtest/TestSuite.h"


class WinSmartCardUtilTest : public CxxTest::TestSuite
{
public:
#ifdef _WIN32
	const std::string enterPinPath = "TpmVscEnterPin.au3";

	void setUp()
	{
		const std::string enterPinCmd = "Sleep(5000)\nSend(\"12345678\")\nSend(\"{ENTER}\")";
		ta::writeData(enterPinPath, enterPinCmd);
	}

	void tearDown()
	{
		// Nothing right now
	}

	int getOsVersion() const
	{
		return ta::version::parse(ta::OsInfoUtils::getVersion().ver).major();
	}

	void test_tpm_vsc_has_smartcard()
	{
		if (getOsVersion() == 10)
		{
			TS_TRACE("Testing has Smart card");
			TS_ASSERT(ta::WinSmartCardUtil::hasSmartCard());
		}
		else
		{
			TS_SKIP("This will only be performed on Windows 10");
		}
	}

	void test_request_csr()
	{
		if (getOsVersion() == 10)
		{
			unsigned int unusedExitCode = 0; // Ignore exit code
			ta::Process::shellExecAsync(enterPinPath, unusedExitCode);

			std::string result = ta::WinSmartCardUtil::requestCsr("DemoUser", "NL", "NB", "Eindhoven", "KeyTalk", "KeyTalk", "test@keytalk.com", 2048);
			TS_ASSERT(ta::CertUtils::isValidCsr(result));
		}
		else
		{
			TS_SKIP("This will only be performed on Windows 10");
		}
	}

	void test_request_csr_with_incorrect_key_size()
	{
		if (getOsVersion() == 10)
		{
			TS_ASSERT_THROWS(ta::WinSmartCardUtil::requestCsr("DemoUser", "NL", "NB", "Eindhoven", "KeyTalk", "KeyTalk", "test@keytalk.com", 1024), std::exception);
		}
		else
		{
			TS_SKIP("This will only be performed on Windows 10");
		}
	}
#endif
};


