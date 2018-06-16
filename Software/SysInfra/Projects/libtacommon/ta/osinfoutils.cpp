#include "osinfoutils.h"
#include "process.h"
#include "utils.h"
#include "common.h"

#include <stdexcept>
#include "boost/format.hpp"
#include "boost/algorithm/string.hpp"

#ifdef _WIN32
#include <windows.h>

#pragma warning (disable: 4996) // suppress deprecation warning for GetVersionEx()

namespace
{
    const string WUNKNOWN = "unknown Windows version";

    const string W95 = "Windows 95";
    const string W95SP1 = "Windows 95 SP1";
    const string W95OSR2 = "Windows 95 OSR2";
    const string W98 = "Windows 98";
    const string W98SP1 = "Windows 98 SP1";
    const string W98SE = "Windows 98 SE";
    const string WME = "Windows ME";

    const string WNT351 = "Windows NT 3.51";
    const string WNT4 = "Windows NT 4";
    const string W2K = "Windows 2000";
    const string WXP = "Windows XP";
    const string W2003SVR = "Windows Server 2003 or XP 64-bit";

    const string WVISTA = "Windows Vista";
    const string W2008SVR = "Windows Server 2008";

    const string W7 = "Windows 7";
    const string W2008SVRR2 = "Windows Server 2008 R2";

    const string W8 = "Windows 8";
    const string W81 = "Windows 8.1";
    const string W2012SVR = "Windows Server 2012";
    const string W2012SVRR2 = "Windows Server 2012 R2";

    const string W10 = "Windows 10";
    const string W2016SVRTECHPREVIEW = "Windows Server 2016 Technical Preview";
}

#elif defined(__linux__)
# include "process.h"
# include<sys/utsname.h>
#else
# error "Unsupported platform"
#endif

using std::string;

namespace ta
{
    namespace OsInfoUtils
    {
        //
        // Private API
        //
        namespace
        {
#ifdef _WIN32
            string parseWin32VersionName(const OSVERSIONINFOEX& aVersion)
            {
                const DWORD myBuildNum = aVersion.dwBuildNumber & 0xFFFF;

                switch (aVersion.dwPlatformId)
                {
                case VER_PLATFORM_WIN32_WINDOWS:
                {
                    if (aVersion.dwMajorVersion != 4)
                        break;
                    else if(aVersion.dwMinorVersion < 10 && myBuildNum == 950)
                        return W95;
                    else if(aVersion.dwMinorVersion < 10 && (myBuildNum > 950 && myBuildNum <= 1080))
                        return W95SP1;
                    else if(aVersion.dwMinorVersion < 10 && myBuildNum > 1080)
                        return W95OSR2;
                    else if(aVersion.dwMinorVersion == 10 && myBuildNum == 1998)
                        return W98;
                    else if(aVersion.dwMinorVersion == 10 && (myBuildNum > 1998 && myBuildNum < 2183))
                        return W98SP1;
                    else if(aVersion.dwMinorVersion == 10 && myBuildNum >= 2183)
                        return W98SE;
                    else if(aVersion.dwMinorVersion == 90)
                        return WME;
                    break;
                }
                case VER_PLATFORM_WIN32_NT:
                {
                    if (aVersion.dwMajorVersion == 3 && aVersion.dwMinorVersion == 51)
                        return WNT351;
                    else if (aVersion.dwMajorVersion == 4 && aVersion.dwMinorVersion == 0)
                        return WNT4;
                    else if (aVersion.dwMajorVersion == 5 && aVersion.dwMinorVersion == 0)
                        return W2K;
                    else if (aVersion.dwMajorVersion == 5 && aVersion.dwMinorVersion == 1)
                        return WXP;
                    else if(aVersion.dwMajorVersion == 5 && aVersion.dwMinorVersion == 2)
                        return W2003SVR;
                    else if(aVersion.dwMajorVersion == 6)
                    {
                        if (aVersion.dwMinorVersion == 0)
                        {
                            if (aVersion.wProductType == VER_NT_WORKSTATION)
                                return WVISTA;
                            else
                                return W2008SVR;
                        }
                        if (aVersion.dwMinorVersion == 1)
                        {
                            if (aVersion.wProductType == VER_NT_WORKSTATION)
                                return W7;
                            else
                                return W2008SVRR2;
                        }
                        if (aVersion.dwMinorVersion == 2)
                        {
                            if (aVersion.wProductType == VER_NT_WORKSTATION)
                                return W8;
                            else
                                return W2012SVR;
                        }
                        if (aVersion.dwMinorVersion == 3)
                        {
                            if (aVersion.wProductType == VER_NT_WORKSTATION)
                                return W81;
                            else
                                return W2012SVRR2;
                        }
                    }
                    else if (aVersion.dwMajorVersion == 10)
                    {
                        if (aVersion.dwMinorVersion == 0)
                        {
                            if (aVersion.wProductType == VER_NT_WORKSTATION)
                                return W10;
                            else
                                return W2016SVRTECHPREVIEW;
                        }
                    }
                    break;
                }
                default:
                {
                    break;
                }
                }// end-of-switch

                return WUNKNOWN;
            }
#endif
        }

        //
        // Public API
        //
        OsVersion getVersion()
        {
            OsVersion myRetVal;
#ifdef _WIN32
            OSVERSIONINFOEX osinfoex = {0};
            osinfoex.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

            if (!::GetVersionEx((OSVERSIONINFO*)&osinfoex))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("GetVersionEx failed. LastError %d") % ::GetLastError());
            }

            myRetVal.ver = str(boost::format("%u.%u.%u") % osinfoex.dwMajorVersion % osinfoex.dwMinorVersion % (osinfoex.dwBuildNumber & 0xFFFF));
            myRetVal.name = parseWin32VersionName(osinfoex);
#elif defined(__linux__)
            try
            {
                myRetVal.name = boost::trim_copy(Process::checkedShellExecSync("lsb_release --id --short"));
                myRetVal.ver = boost::trim_copy(Process::checkedShellExecSync("lsb_release --release --short"));
            }
            catch (...)
            {
                if (ta::isFileExist("/etc/debian_version"))
                {
                    myRetVal.name = "Debian";
                    myRetVal.ver = boost::trim_copy((string)ta::readData("/etc/debian_version"));
                }
                else if (ta::isFileExist("/etc/centos-release"))
                {
                    myRetVal.name = "CentOS";
                    myRetVal.ver = boost::trim_copy((string)ta::readData("/etc/centos-release"));
                }
                else if (ta::isFileExist("/etc/redhat-release"))
                {
                    myRetVal.name = "RHEL";
                    myRetVal.ver = boost::trim_copy((string)ta::readData("/etc/redhat-release"));
                }
            }

            if (myRetVal.name.empty())
            {
                // fallback, show generic Linux kernel version
                myRetVal.name = boost::trim_copy(Process::checkedShellExecSync("uname -s"));
                myRetVal.ver = boost::trim_copy(Process::checkedShellExecSync("uname -r"));
            }
            if (isRaspberryPi())
            {
                myRetVal.name += " (Raspberry Pi)";
            }
#else
#error "Unsupported platform"
#endif
            return myRetVal;
        }

        string getPlatformShortName()
        {
#ifdef _WIN32
            return "Windows";
#elif defined(__linux__)
            struct utsname buf = {};
            if (uname(&buf) == 0)
            {
                return buf.sysname;
            }
            else
            {
                return "Linux";
            }
#else
#error "Unsupported platform"
#endif
        }

#ifdef __linux__
        bool isRaspberryPi()
        {
            try {
                // If matched, we have Broadcom BCM2835 SoC, so with a high degree of probability we run Raspberry Pi
                return boost::trim_copy(Process::checkedShellExecSync("grep -m 1 '^Hardware' /proc/cpuinfo | cut -d ':' -f 2")) == "BCM2708";
            } catch (...) {
                return false;
            }
        }

        bool isLinuxDebian()
        {
            return ta::isFileExist("/etc/debian_version");
        }

        bool isLinuxCentOS()
        {
            return ta::isFileExist("/etc/centos-release");
        }

        bool isLinuxRHEL()
        {
            return ta::isFileExist("/etc/redhat-release");
        }
#endif // __linux__

    } //OsInfoUtils
} // ta


