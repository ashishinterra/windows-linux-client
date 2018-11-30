#include "utils.h"
#include "strings.h"
#include "url.h"
#include "scopedresource.hpp"

#include "boost/format.hpp"
#include "boost/regex.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/range/algorithm_ext/erase.hpp"
#include "boost/algorithm/string.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include <locale>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <Lmcons.h>
#else
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#endif

using std::string;

namespace ta
{
    // Private API
    namespace
    {

#if defined(__linux__)
        void chownDirContentsRecursively(const string& aDir, const uid_t anOwner)
        {
            if (!isDirExist(aDir))
            {
                return;
            }

            ta::ScopedResource<DIR*> dir(opendir(aDir.c_str()), closedir);
            if (dir)
            {
                // chown all files and subdirectories in dir recursively diving inside subdirectories
                struct dirent* dp;
                while ((dp = readdir(dir)) != NULL)
                {
                    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
                    {
                        continue;
                    }
                    const string subpath = aDir + "/" + dp->d_name;
                    if (!isDirExist(subpath) && !isFileExist(subpath))
                    {
                        continue;
                    }
                    if (chown(subpath.c_str(), anOwner, -1) < 0)
                    {
                        TA_THROW_MSG(std::runtime_error, boost::format("Failed to set owner of %s to %d. %s") % subpath % anOwner % strerror(errno));
                    }

                    if (isDirExist(subpath))
                    {
                        chownDirContentsRecursively(subpath, anOwner);
                    }
                }
            }
        }
#endif

    } // unnamed ns


    //
    // Public API
    //

    bool isValidEmail(const string& aEmail)
    {
        // This validation covers 99.99% cases from RFC 5322
        // Leave the remaining 0.01% of invalid emails to be tackled by mail servers.

        const string myEmail = boost::trim_copy(aEmail);

        if (myEmail.empty())
        {
            return false;
        }

        try
        {
            static const string myEmailPartRegexStr = str(boost::format("[a-zA-Z0-9%1%]+(\\.[a-zA-Z0-9%1%]+)*") % regexEscapeStr("!#$%&'*+/=?^_`{|}~-"));
            static const string myDomainPartRegexStr = "((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})";
            const boost::regex myRegEx(myEmailPartRegexStr + "@" + myDomainPartRegexStr);
            return regex_match(myEmail, myRegEx);
        }
        catch (std::exception&)
        {
            return false;
        }
    }

    bool isValidPhoneNumber(const string& aPhone)
    {
        string myPhone = aPhone;
        boost::remove_erase_if(myPhone, boost::is_any_of(" \t-"));

        if (myPhone.empty())
        {
            return false;
        }

        try
        {
            const boost::regex myRegEx("\\+(\\d){8,15}");
            return regex_match(myPhone, myRegEx);
        }
        catch (std::exception&)
        {
            return false;
        }
    }

    bool isFileExist(const string& aFileName)
    {
        try
        {
            namespace fs = boost::filesystem;
            fs::path myPath(aFileName);
            if (!fs::exists(myPath))
                return false;
            if (!fs::is_regular_file(myPath))
                return false;
        }
        catch (std::exception&)
        {
            return false;
        }
        return true;
    }

    bool isDirExist(const string& aDirName)
    {
        try
        {
            namespace fs = boost::filesystem;
            fs::path myPath(aDirName);
            if (!fs::exists(myPath))
                return false;
            if (!fs::is_directory(myPath))
                return false;
        }
        catch (std::exception&)
        {
            return false;
        }
        return true;
    }

    void createParentDir(const string& aFilePath)
    {
        namespace fs = boost::filesystem;

        const fs::path myPath(aFilePath);
        if (myPath.has_parent_path())
        {
            const fs::path myParentDir = myPath.parent_path();
            if (!fs::exists(myParentDir))
            {
                fs::create_directories(myParentDir);
            }
        }
    }

    string getParentDir(const string& aFilePath)
    {
        namespace fs = boost::filesystem;

        const fs::path myPath(aFilePath);
        if (myPath.has_parent_path())
        {
            return myPath.parent_path().string();
        }
        else
        {
            return ".";
        }
    }

    string getDirSep()
    {
#ifdef _WIN32
        return "\\";
#else
        return "/";
#endif
    }

    void copyDir(const string& aSrcDir, const string& aDestDir)
    {
        namespace fs = boost::filesystem;

        if(!fs::exists(aSrcDir) || !fs::is_directory(aSrcDir))
            TA_THROW_MSG(std::invalid_argument, "Source directory " + aSrcDir + " does not exist or is not a directory.");

        fs::create_directories(aDestDir);

        const fs::path mySourceDirPath(aSrcDir);
        for( fs::directory_iterator it(mySourceDirPath); it != fs::directory_iterator(); ++it)
        {
            fs::path current(it->path());
            if(fs::is_directory(current))
                copyDir(current.string(), aDestDir + getDirSep() + current.filename().string());
            else // file
                fs::copy_file(current.string(), aDestDir + getDirSep() + current.filename().string());
        }
    }

    string regexEscapeStr(const string& anStr)
    {
        static const std::locale& loc = std::locale::classic();
        string myEscapedStr;
        foreach (char c, anStr)
        {
            if (std::isalnum(c, loc))
                myEscapedStr += c;
            else
                myEscapedStr += str(boost::format("\\%c") % c);
        }
        return myEscapedStr;
    }

    string shellEscapeStr(const string& anStr)
    {
        return "'" + boost::replace_all_copy(anStr, "'", "'\\''") + "'";
    }

    string genUuid()
    {
        const std::vector<unsigned char> myRawUuid = genRawUuid();
        return Strings::toHex(getSafeBuf(myRawUuid), myRawUuid.size(), Strings::caseLower);
    }

    std::vector<unsigned char> genRawUuid()
    {
        static boost::uuids::random_generator gen; // seeding entropy might be expensive, so do it once only
        boost::uuids::uuid myUuid = gen();
        return std::vector<unsigned char>(myUuid.begin(), myUuid.end());
    }

    boost::uint32_t genRand(boost::uint32_t anUpperBound)
    {
        if (anUpperBound == 0)
            TA_THROW_MSG(std::invalid_argument, "Upper bound cannot be zero");

#ifdef _WIN32
        HCRYPTPROV myProv = NULL;
        if (!::CryptAcquireContext(&myProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT|CRYPT_SILENT))
            TA_THROW_MSG(std::runtime_error, boost::format("Failed to acquire CryptoAPI provider. Last error: %d") % ::GetLastError());

        // avoiding "modulo bias"; stolen from arc4random_uniform() of OpenBSD-4.6
        boost::uint32_t myMin;
# if (ULONG_MAX > 0xffffffffUL)
        myMin = 0x100000000UL % anUpperBound;
# else
        if (anUpperBound > 0x80000000)
            myMin = 1 + ~anUpperBound;
        else
            myMin = ((0xffffffff - (anUpperBound * 2)) + 1) % anUpperBound;
# endif

        boost::uint32_t myRandom = 0;
        while (true)
        {
            if (!::CryptGenRandom(myProv, sizeof(myRandom), (BYTE*)&myRandom))
            {
                ::CryptReleaseContext(myProv, 0);
                TA_THROW_MSG(std::runtime_error, boost::format("::CryptGenRandom failed. Last error: %d") % ::GetLastError());
            }
            if (myRandom >= myMin)
                break;
        }
        ::CryptReleaseContext(myProv, 0);

        return myRandom % anUpperBound;
#else
        static bool entropySeeded = false;
        if (!entropySeeded)
        {
            srandom((unsigned int)time(NULL));
            entropySeeded = true;
        }
        return random() % anUpperBound;
#endif
    }


    std::vector<unsigned char> genRandBuf(size_t aBufSize)
    {
        if (aBufSize == 0)
        {
            TA_THROW_MSG(std::invalid_argument, "Size of random buffer cannot be zero");
        }

        std::vector<unsigned char> randomDataBuffer(aBufSize, 0);

#ifdef _WIN32
        HCRYPTPROV myProv = NULL;
        if (!::CryptAcquireContext(&myProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT|CRYPT_SILENT))
            TA_THROW_MSG(std::runtime_error, boost::format("Failed to acquire CryptoAPI provider. Last error: %d") % ::GetLastError());

        if (!::CryptGenRandom(myProv, (DWORD)aBufSize, (BYTE*)getSafeBuf(randomDataBuffer)))
        {
            ::CryptReleaseContext(myProv, 0);
            TA_THROW_MSG(std::runtime_error, boost::format("::CryptGenRandom failed. Last error: %d") % ::GetLastError());
        }

        ::CryptReleaseContext(myProv, 0);

#else
        foreach (unsigned char& ch, randomDataBuffer)
        {
            ch = genRand(UCHAR_MAX);
        }
#endif
        return randomDataBuffer;
    }

    string getUserName()
    {
#ifdef _WIN32
        char myUserName[UNLEN+1] = {};
        DWORD myBufLen = sizeof(myUserName)+1;
        if (!GetUserName(myUserName, &myBufLen))
            return "<unknown>";
        return myUserName;
#else
        struct passwd pwd;
        struct passwd* result;
        char myBuf[16384];
        if (getpwuid_r(getuid(), &pwd, myBuf, sizeof(myBuf), &result) != 0 || !result || !pwd.pw_name)
            return "<unknown>";
        return pwd.pw_name;
#endif
    }

#if defined(__linux__)
    bool isUserRoot()
    {
        return getuid() == 0;
    }

    bool isRebootRequired()
    {
        return isFileExist("/var/run/reboot-required");
    }

    void chownDir(const string& aDir, Recursive aRecursive)
    {
        const uid_t owner = getuid();

        if (!isDirExist(aDir))
        {
            return;
        }
        if (chown(aDir.c_str(), owner, -1) < 0)
        {
            TA_THROW_MSG(std::runtime_error, boost::format("Failed to set owner of %s to %d. %s") % aDir % owner % strerror(errno));
        }
        if (aRecursive == recursiveYes)
        {
            chownDirContentsRecursively(aDir, owner);
        }
    }
#endif

}// namespace ta
