#ifdef _WIN32
#include "osuserinfo.h"
#include "ta/common.h"
#include "ta/sysinfo.h"
#include "ta/scopedresource.hpp"

#include <vector>
#include <stdexcept>
#include <windows.h>

namespace ta
{
    namespace OsUserInfo
    {

        using std::string;
        using std::vector;

        //
        // Internal API
        //
        namespace
        {
            vector<unsigned char> getTokenInfo(HANDLE aTokenHandle, TOKEN_INFORMATION_CLASS aTokenInfoClass)
            {
                DWORD myLen = 0;
                ::GetTokenInformation(aTokenHandle, aTokenInfoClass, NULL, 0, &myLen);
                if (myLen == 0)
                {
                    TA_THROW_MSG(std::runtime_error, "GetTokenInformation returned zero token length");
                }
                vector<unsigned char> myTokenInfo(myLen);
                if (!::GetTokenInformation(aTokenHandle, aTokenInfoClass, ta::getSafeBuf(myTokenInfo), myLen, &myLen))
                {
                    TA_THROW_MSG(std::runtime_error, boost::format("GetTokenInformation second pass failed with error: %s") % ta::SysInfo::getLastErrorStr());
                }
                return myTokenInfo;
            }

            string getSid(vector<unsigned char>& aTokenInfo)
            {
                if (aTokenInfo.empty())
                    TA_THROW_MSG(std::runtime_error, "aTokenInfo is empty");
                PSID mySidPtr = ((TOKEN_USER*)&aTokenInfo[0])->User.Sid;
                if (!mySidPtr )
                    TA_THROW_MSG(std::runtime_error, "SID is NULL");
                const int mySubAuthCount = *::GetSidSubAuthorityCount(mySidPtr) ;
                string mySid = str(boost::format("S-1-%u") % (unsigned int)(::GetSidIdentifierAuthority(mySidPtr)->Value[5]));
                for (int i = 0; i < mySubAuthCount; ++i )
                    mySid += str(boost::format("-%u") % (*::GetSidSubAuthority(mySidPtr, i)));
                return mySid;
            }
        }

        //
        // Public API
        //

        string getCurrentUserSID()
        {
            HANDLE myTokenHandle;
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &myTokenHandle))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("OpenProcessToken failed with error: %s") % ta::SysInfo::getLastErrorStr());
            }
            ta::ScopedResource<HANDLE> myTokenHandleScoped(myTokenHandle, ::CloseHandle);
            vector<unsigned char> myTokenInfo = getTokenInfo(myTokenHandle, TokenUser);
            const string mySid = getSid(myTokenInfo);
            return mySid;
        }

        UserLogonId getCurrentUserLogonId()
        {
            HANDLE myTokenHandle;
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &myTokenHandle))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("OpenProcessToken failed with error: %s") % ta::SysInfo::getLastErrorStr());
            }
            ta::ScopedResource<HANDLE> myTokenHandleScoped(myTokenHandle, ::CloseHandle);

            const std::vector<unsigned char> myTokenInfo = getTokenInfo(myTokenHandle, TokenStatistics);
            const TOKEN_STATISTICS* myTokenStat = (TOKEN_STATISTICS*)&myTokenInfo[0];

            const LUID myLogonUid = myTokenStat->AuthenticationId;
            return UserLogonId(myLogonUid.HighPart, myLogonUid.LowPart);
        }
    }
}
#endif
