#include "ReseptPrGenerator.h"
#include "LogInitializer.h"
#include "rclient/Settings.h"
#ifdef _WIN32
#include "rclient/TaskSettings.h"
#endif
#include "rclient/CommonUtils.h"
#include "rclient/NativeCertStore.h"
#include "rclient/Common.h"
#include "ta/ExceptionDumper.h"
#include "ta/Zip.h"
#include "ta/osinfoutils.h"
#include "ta/process.h"
#include "ta/certutils.h"
#include "ta/utils.h"

#include <vector>

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/convenience.hpp"
#include "boost/assign/list_of.hpp"

using std::string;
using std::vector;
namespace fs = boost::filesystem;
using boost::assign::list_of;

namespace PrGenerator
{
    //
    // Private API
    //
    namespace
    {
        void copyFile(const string& anSrcPath, const string& aDestPath)
        {
            fs::copy_file(anSrcPath, aDestPath, fs::copy_option::overwrite_if_exists);
        }

        ta::StringArray tryCopyKeyTalkClientLogs(const string& aDir)
        {
            ta::StringArray myRetVal;
            try
            {
                const string mySrcPath = rclient::getLogDir() + ta::getDirSep() + rclient::LogName;
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::LogName;
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s log file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            try
            {
                const string mySrcPath = rclient::getLogDir() + ta::getDirSep() + rclient::LogName + ".old";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::LogName + ".old";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s old log file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }

        ta::StringArray tryCopyKeyTalkConfigManagerLog(const string& aDir)
        {
            ta::StringArray myRetVal;
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::ConfigManagerLogFileName;
                const string myDestPath = aDir + ta::getDirSep() + rclient::ConfigManagerLogFileName;
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Config manager log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::ConfigManagerLogFileName + ".old";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::ConfigManagerLogFileName + ".old";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Config manager old log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            return myRetVal;
        }


#ifdef _WIN32
        ta::StringArray tryCopyKeyTalkScheduledTasksFiles(const string& aDir)
        {
            ta::StringArray myRetVal;

            // copy task logs
            try
            {
                foreach(const std::string& task, rclient::Settings::getTaskNames(rclient::Settings::IISTask))
                {
                    string myDefaultScriptFileName;
                    rclient::Settings::IISTaskParameters::getDefaultScriptLogFileName(task, myDefaultScriptFileName);
                    const string myDestPath = aDir + ta::getDirSep() + myDefaultScriptFileName;
                    std::string myFallbackTaskLogFilePath;
                    rclient::Settings::IISTaskParameters::getFallbackScriptLogFilePath(task, myFallbackTaskLogFilePath);
                    std::string myTaskLogFilePath;
                    // Determine primary log source
                    try
                    {
                        myTaskLogFilePath = rclient::Settings::IISTaskParameters::getScriptLogFilePath(task);
                    }
                    catch (std::exception&)
                    {
                        // Task not configured properly, use fallback location as primary log source
                        myTaskLogFilePath = myFallbackTaskLogFilePath;
                    }

                    try
                    {
                        copyFile(myTaskLogFilePath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                    catch (std::exception&)
                    {
                        // Could not copy from primary location, try to copy log from fallback location
                        try
                        {
                            copyFile(myFallbackTaskLogFilePath, myDestPath);
                            myRetVal.push_back(myDestPath);
                        }
                        catch (std::exception& e)
                        {
                            WARNLOG(boost::format("Failed to copy task log '%s' for task %s to %s. %s. Skipping...") % myTaskLogFilePath % task % aDir % e.what());
                        }
                    }
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy task log files. %s. Skipping...") % e.what());
            }

            // copy task configs
            try
            {
                const string mySrcPath = rclient::Settings::getTaskConfigPath();
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + fs::path(mySrcPath).filename().string();
                    copyFile(mySrcPath, myDestPath);

                    rclient::Settings::setTaskConfigPath(myDestPath);

                    foreach(const std::string& task, rclient::Settings::getTaskNames(rclient::Settings::IISTask))
                    {
                        string myPassword;
                        try
                        {
                            myPassword = rclient::Settings::IISTaskParameters::getKeyTalkPassword(task);
                            if (!myPassword.empty())
                            {
                                myPassword = "<erased>"; // password successfully read, but excluded from the PR for privacy reasons
                            }
                            else
                            {
                                myPassword = ""; // anonymous login
                            }
                        }
                        catch (...)
                        {
                            WARNLOG(boost::format("Password unretrievable for task %s.") % task);
                            myPassword = "<unretrievable>"; // indicates error in task configuration or task configuration module
                        }
                        rclient::Settings::IISTaskParameters::setKeyTalkPassword(task, myPassword);
                    }

                    // File is included in PR only when all passwords were masked
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy RESEPT Tasks Config to %s. %s. Skipping...") % aDir % e.what());
            }
            return myRetVal;
        }

        ta::StringArray tryCopyKeyTalkBrokerServiceLog(const string& aDir)
        {
            ta::StringArray myRetVal;
            try
            {
                const string mySrcPath = ta::Process::getCommonAppDataDir() + "\\" + resept::CompanyName + "\\" + rclient::BrokerServiceLogName;
                const string myDestPath = aDir + ta::getDirSep() + rclient::BrokerServiceLogName;
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Broker Service log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            try
            {
                const string mySrcPath = ta::Process::getCommonAppDataDir() + "\\" + resept::CompanyName + "\\" + rclient::BrokerServiceLogName + ".old";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::BrokerServiceLogName + string(".old");
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Broker Service old log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }

        ta::StringArray tryCopyMiniDump(const string& aDir)
        {
            ta::StringArray myRetVal;
            const ta::StringArray myApps = list_of(rclient::ReseptDesktopClient)(rclient::ReseptConsoleClient)(rclient::ReseptConfigManager);
            foreach (const string& app, myApps)
            {
                try
                {
                    const string mySrcPath = ta::Process::getTempDir() + app + ta::ExceptionDumper::DumpExt;
                    if (ta::isFileExist(mySrcPath))
                    {
                        const string myDestPath = aDir + ta::getDirSep() + app + ta::ExceptionDumper::DumpExt;
                        copyFile(mySrcPath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s minidump to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }
                try
                {
                    const string mySrcPath = ta::Process::getTempDir() + app + ta::ExceptionDumper::DumpReportExt;
                    if (ta::isFileExist(mySrcPath))
                    {
                        const string myDestPath = aDir + ta::getDirSep() + app + ta::ExceptionDumper::DumpReportExt;
                        copyFile(mySrcPath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s minidump report to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }
            }

            return myRetVal;
        }
#else
        ta::StringArray tryCopyApacheFiles(const string& aDir)
        {
            ta::StringArray myRetVal;

            // Apache config
            try
            {
                const string mySrcPath = rclient::Settings::getReseptConfigDir() + "/apache.ini";
                const string myDestPath = aDir + "/apache.ini";
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s apache config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // Apache cron job
            try
            {
                const string mySrcPath = "/etc/cron.d/keytalk.apache";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + "/etc_cron_d_keytalk_apache";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s apache cron job config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // KeyTalk Apache logs
            static const vector<string> myApacheLogs = list_of(ta::Process::getTempDir() + "ktapachecertrenewal.log")
                    (ta::Process::getTempDir() + "cron.ktapachecertrenewal.log");
            foreach (const string& logPath, myApacheLogs)
            {
                try
                {
                    if (ta::isFileExist(logPath))
                    {
                        const string myDestPath = aDir + "/" + fs::path(logPath).filename().string();
                        copyFile(logPath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s apache client log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }
            }

            // KeyTalk CA service logs
            static const vector<string> myKeyTalkCAUpdaterLogs = list_of(ta::Process::getTempDir() + "ktcaupdater.log")("/tmp/ktcaupdater.log");
            foreach (const string& logPath, myKeyTalkCAUpdaterLogs)
            {
                try
                {
                    if (ta::isFileExist(logPath))
                    {
                        const string myDestPath = aDir + "/" + fs::path(logPath).filename().string();
                        copyFile(logPath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s KeyTalk CA updater log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }
            }

            // Apache configuration
            if (ta::isDirExist("/etc/httpd"))
            {
                // copy /etc/httpd/conf/httpd.conf
                try
                {
                    const string myApacheConfigFile = "/etc/httpd/conf/httpd.conf";
                    const string myDestPath = aDir + "/apache_ports.conf";
                    copyFile(myApacheConfigFile, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s apache configuration file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }

                // copy all configs referred from /etc/httpd/conf.d/
                fs::path sitesEnabledDir("/etc/httpd/conf.d");
                fs::directory_iterator it(sitesEnabledDir), eod;
                foreach(fs::path const &p, std::make_pair(it, eod))
                {
                    try
                    {
                        if (fs::is_symlink(p))
                        {
                            const fs::path mySymLinkPath = sitesEnabledDir / fs::read_symlink(p);
                            const string myDestPath = aDir + "/apache_sites_enabled_"  + mySymLinkPath.filename().string();
                            copyFile(mySymLinkPath.string(), myDestPath);
                            myRetVal.push_back(myDestPath);
                        }
                    }
                    catch (std::exception& e)
                    {
                        WARNLOG(boost::format("Failed to copy %s apache configuration site-enabled file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                    }
                }
            }

            if (ta::isDirExist("/etc/apache2"))
            {
                // copy /etc/apache2/ports.conf
                try
                {
                    const string myApacheConfigFile = "/etc/apache2/ports.conf";
                    const string myDestPath = aDir + ta::getDirSep() + "apache_ports.conf";
                    copyFile(myApacheConfigFile, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s apache configuration file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }

                // copy all configs referred from /etc/apache2/sites-enabled/
                fs::path sitesEnabledDir("/etc/apache2/sites-enabled");
                fs::directory_iterator it(sitesEnabledDir), eod;
                foreach(fs::path const &p, std::make_pair(it, eod))
                {
                    try
                    {
                        if (fs::is_symlink(p))
                        {
                            const fs::path mySymLinkPath = sitesEnabledDir / fs::read_symlink(p);
                            const string myDestPath = aDir + "/apache_sites_enabled_"  + mySymLinkPath.filename().string();
                            copyFile(mySymLinkPath.string(), myDestPath);
                            myRetVal.push_back(myDestPath);
                        }
                    }
                    catch (std::exception& e)
                    {
                        WARNLOG(boost::format("Failed to copy %s apache configuration site-enabled file to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                    }
                }
            }
            return myRetVal;
        }

        string guessTomCatDirName()
        {
            string myTomCatDir = "tomcat";

            if (ta::isFileExist("/usr/sbin/tomcat"))
            {
                myTomCatDir = "tomcat";
            }
            else
            {
                static const ta::StringArray Versions = list_of("tomcat")
                                                        ("tomcat6")
                                                        ("tomcat7")
                                                        ("tomcat8")
                                                        ("tomcat9");
                foreach (const string& version, Versions)
                {
                    if (ta::isFileExist("/etc/init.d/" + version))
                    {
                        myTomCatDir = version;
                    }
                }
            }

            return myTomCatDir;
        }

        ta::StringArray tryCopyTomCatFiles(const string& aDir)
        {
            ta::StringArray myRetVal;

            // KeyTalk TomCat config
            try
            {
                const string mySrcPath = rclient::Settings::getReseptConfigDir() + "/tomcat.ini";
                const string myDestPath = aDir + "/tomcat.ini";
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s tomcat config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // Tomcat server configuration
            try
            {
                const string myConfigFilePath = "/etc/" + guessTomCatDirName() + "/server.xml";
                if (ta::isFileExist(myConfigFilePath))
                {
                    const string myDestPath = aDir + "/tomcat_server.xml";
                    copyFile(myConfigFilePath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy tomcat server config to %s. %s. Skipping...") % aDir % e.what());
            }

            // Tomcat cron job
            try
            {
                const string mySrcPath = "/etc/cron.d/keytalk.tomcat";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + "/etc_cron_d_keytalk_tomcat";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s tomcat cron job config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // KeyTalk TomCat logs
            static const vector<string> myLogs = list_of(ta::Process::getTempDir() + "kttomcatcertrenewal.log")
                                                 (ta::Process::getTempDir() + "cron.kttomcatcertrenewal.log");
            foreach (const string& logPath, myLogs)
            {
                try
                {
                    if (ta::isFileExist(logPath))
                    {
                        const string myDestPath = aDir + "/" + fs::path(logPath).filename().string();
                        copyFile(logPath, myDestPath);
                        myRetVal.push_back(myDestPath);
                    }
                }
                catch (std::exception& e)
                {
                    WARNLOG(boost::format("Failed to copy %s tomcat client log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
                }
            }

            // TomCat logs
            try
            {
                const string myLogFilePath  = "/var/log/" + guessTomCatDirName() + "/catalina.out";
                if (ta::isFileExist(myLogFilePath))
                {
                    const string myDestPath = aDir + "/" + fs::path(myLogFilePath).filename().string();
                    copyFile(myLogFilePath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy tomcat log to %s. %s. Skipping...") % aDir % e.what());
            }

            return myRetVal;
        }
#endif  // _WIN32

        ta::StringArray tryCopyKeyTalkConfigUpdaterInstallationLogs(const string& aDir)
        {
            ta::StringArray myRetVal;
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::ConfigUpdaterLogFileName;
                const string myDestPath = aDir + ta::getDirSep() + rclient::ConfigUpdaterLogFileName;
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Config Updater log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::ConfigUpdaterLogFileName + ".old";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::ConfigUpdaterLogFileName + ".old";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Config Updater old log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }

#ifdef _WIN32
        ta::StringArray tryCopyKeyTalkSweeperLogs(const string& aDir)
        {
            ta::StringArray myRetVal;
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::SweeperLogFileName;
                const string myDestPath = aDir + ta::getDirSep() + rclient::SweeperLogFileName;
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Sweeper log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::SweeperLogFileName + ".old";
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + rclient::SweeperLogFileName + ".old";
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Sweeper old log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }
#endif

        ta::StringArray tryCopyKeyTalkConfigs(const string& aDir)
        {
            ta::StringArray myRetVal;
            // KeyTalk common config
            try
            {
                const string mySrcPath = rclient::Settings::getReseptConfigPath();
                const string myDestPath = aDir + ta::getDirSep() + fs::path(mySrcPath).filename().string();
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            // User config
            try
            {
                const string mySrcPath = rclient::Settings::getUserConfigPath();
                const string myDestPath = aDir + ta::getDirSep() + fs::path(mySrcPath).filename().string();
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s User Config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // Master config
            try
            {
                const string mySrcPath = rclient::Settings::getMasterConfigPath();
                if (ta::isFileExist(mySrcPath))
                {
                    const string myDestPath = aDir + ta::getDirSep() + fs::path(mySrcPath).filename().string();
                    copyFile(mySrcPath, myDestPath);
                    myRetVal.push_back(myDestPath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s Master Config to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }

        ta::StringArray tryCopySelfLog(const string& aDir)
        {
            ta::StringArray myRetVal;

            try
            {
                const string mySrcPath = ta::Process::getTempDir() + rclient::PrGeneratorLogName;
                const string myDestPath = aDir + ta::getDirSep() + rclient::PrGeneratorLogName;
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s PR Generator log to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            return myRetVal;
        }

        ta::StringArray tryCopyKeyTalkInstalledCAs(const string& aDir)
        {
            using ta::CertUtils::getCertInfo;

            ta::StringArray myRetVal;
            try
            {
                ta::StringArray myUCAs, mySCAs, myPCAs, myRCAs, myExtraSigningCAs;
                rclient::NativeCertStore::getInstalledCAs(myUCAs, mySCAs, myPCAs, myRCAs, myExtraSigningCAs);

                foreach (const string& pem, myUCAs)
                {
                    const string myCaFilePath = aDir + ta::getDirSep() + "signing_ca_" + getCertInfo(pem).sha1Fingerprint + ".pem";
                    ta::writeData(myCaFilePath, pem);
                    myRetVal.push_back(myCaFilePath);
                }
                foreach (const string& pem, mySCAs)
                {
                    const string myCaFilePath = aDir + ta::getDirSep() + "comm_ca_" + getCertInfo(pem).sha1Fingerprint + ".pem";
                    ta::writeData(myCaFilePath, pem);
                    myRetVal.push_back(myCaFilePath);
                }
                foreach(const string& pem, myPCAs)
                {
                    const string myCaFilePath = aDir + ta::getDirSep() + "primary_ca_" + getCertInfo(pem).sha1Fingerprint + ".pem";
                    ta::writeData(myCaFilePath, pem);
                    myRetVal.push_back(myCaFilePath);
                }
                foreach(const string& pem, myRCAs)
                {
                    const string myCaFilePath = aDir + ta::getDirSep() + "root_ca_" + getCertInfo(pem).sha1Fingerprint + ".pem";
                    ta::writeData(myCaFilePath, pem);
                    myRetVal.push_back(myCaFilePath);
                }
                foreach(const string& pem, myExtraSigningCAs)
                {
                    const string myCaFilePath = aDir + ta::getDirSep() + "extra_signing_ca_" + getCertInfo(pem).sha1Fingerprint + ".pem";
                    ta::writeData(myCaFilePath, pem);
                    myRetVal.push_back(myCaFilePath);
                }
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to save %s CAs to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }
            return myRetVal;
        }


        ta::StringArray tryCopyKeyTalkVersions(const string& aDir)
        {
            ta::StringArray myRetVal;

            // Main version file
            try
            {
                const string myDestPath = aDir + ta::getDirSep() + "version";
                ta::writeData(myDestPath, toStr(rclient::ClientVersion));
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to save %s version to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            // Development stage
            try
            {
                const string mySrcPath = rclient::Settings::getReseptConfigDir() + ta::getDirSep() + "devstage";
                const string myDestPath = aDir + ta::getDirSep() + "devstage";
                copyFile(mySrcPath, myDestPath);
                myRetVal.push_back(myDestPath);
            }
            catch (std::exception& e)
            {
                WARNLOG(boost::format("Failed to copy %s devstage to %s. %s. Skipping...") % resept::ProductName % aDir % e.what());
            }

            return myRetVal;
        }

    }
    //
    // end of private API
    //

    //
    // Public API
    //

    ta::StringArray preparePrFiles(const string& aDir)
    {
        fs::remove_all(aDir);
        fs::create_directories(aDir);

        ta::StringArray myFileList;

        myFileList += tryCopyKeyTalkClientLogs(aDir);
        myFileList += tryCopyKeyTalkConfigManagerLog(aDir);
        myFileList += tryCopyKeyTalkConfigUpdaterInstallationLogs(aDir);
        myFileList += tryCopyKeyTalkConfigs(aDir);
        myFileList += tryCopyKeyTalkVersions(aDir);
        myFileList += tryCopyKeyTalkInstalledCAs(aDir);
#ifdef _WIN32
        myFileList += tryCopyKeyTalkScheduledTasksFiles(aDir);
        myFileList += tryCopyKeyTalkBrokerServiceLog(aDir);
        myFileList += tryCopyKeyTalkSweeperLogs(aDir);
        myFileList += tryCopyMiniDump(aDir);
#else
        myFileList += tryCopyApacheFiles(aDir);
        myFileList += tryCopyTomCatFiles(aDir);
#endif
        myFileList += tryCopySelfLog(aDir);

        return myFileList;
    }

    void generate(const string& aPrFilePath)
    {
        LogInitializer myLogInitializer;
        const string myTempDirPath = ta::Process::getTempDir() + "ktprgenerator";

        try
        {
            // Prepare files
            const ta::StringArray myFileList = preparePrFiles(myTempDirPath);
            ta::Zip::archive(aPrFilePath, myFileList, ta::Zip::makeStem);
        }
        catch (...)
        {
            safeRemoveDir(myTempDirPath);
            throw;
        }
        safeRemoveDir(myTempDirPath);
    }

    std::string getSavePath()
    {
        string mySaveDir;
#ifdef _WIN32
        try
        {
            mySaveDir = ta::Process::getMyDocDir();
        }
        catch (...)
        {
            try
            {
                mySaveDir = ta::Process::getUserAppDataDir();
            }
            catch (...)
            {}
        }
#else
        try
        {
            mySaveDir = ta::Process::getUserAppDataDir();
        }
        catch (...)
        {}
#endif

        std::string mySavePath = boost::to_lower_copy(resept::ProductName) + ".clnt.pr.dat";
        if (!mySaveDir.empty())
        {
            mySavePath = mySaveDir + ta::getDirSep() + mySavePath;
        }
        return mySavePath;
    }

    void safeRemoveDir(const string& aDir)
    {
        try { fs::remove_all(aDir);}
        catch (...) {}
    }

}
