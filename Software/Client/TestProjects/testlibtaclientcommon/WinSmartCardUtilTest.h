#include "ta/WinSmartCardUtil.h"
#include "ta/certutils.h"
#include "cxxtest/TestSuite.h"


class WinSmartCardUtilTest : public CxxTest::TestSuite
{
public:
#ifdef _WIN32
	const std::string enterPinPath = "TpmVscEnterPin.au3";
#endif

	void setUp()
	{
#ifdef _WIN32
		const std::string enterPinCmd = "Sleep(5000)\nSend(\"12345678\")\nSend(\"{ENTER}\")";
		ta::writeData(enterPinPath, enterPinCmd);
#endif
	}

	void tearDown()
	{
		// Nothing right now
	}

	void test_tpm_vsc_has_smartcard()
	{
#ifdef _WIN32
		TS_WARN("This test temporarily disabled because the build server does not have a VSC installed");
		TS_SKIP("This test temporarily disabled because the build server does not have a VSC installed");
		TS_TRACE("Testing has Smart card");
		TS_ASSERT(ta::WinSmartCardUtil::hasSmartCard());
#else
		TS_SKIP("This test is for Windows only");
#endif
	}

	void test_request_csr()
	{
#ifdef _WIN32
		TS_WARN("This test temporarily disabled because the build server does not have a VSC installed");
		TS_SKIP("This test temporarily disabled because the build server does not have a VSC installed");
		unsigned int unusedExitCode = 0; // Ignore exit code
		ta::Process::shellExecAsync(enterPinPath, unusedExitCode);

		std::string result = ta::WinSmartCardUtil::requestCsr("DemoUser", "NL", "NB", "Eindhoven", "KeyTalk", "KeyTalk", "test@keytalk.com", 2048);
		TS_ASSERT(ta::CertUtils::isValidCsr(result));
#else
		TS_SKIP("This test is for Windows only");
#endif
	}

	void test_request_csr_with_incorrect_key_size()
	{
#ifdef _WIN32
		TS_WARN("This test temporarily disabled because the build server does not have a VSC installed");
		TS_SKIP("This test temporarily disabled because the build server does not have a VSC installed");
		TS_ASSERT_THROWS(ta::WinSmartCardUtil::requestCsr("DemoUser", "NL", "NB", "Eindhoven", "KeyTalk", "KeyTalk", "test@keytalk.com", 1024), std::exception);
#else
		TS_SKIP("This test is for Windows only");
#endif
	}
};


