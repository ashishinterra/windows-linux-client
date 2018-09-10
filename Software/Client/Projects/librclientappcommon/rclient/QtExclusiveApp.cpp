#include "QtExclusiveApp.h"
#include "CommonUtils.h"
#include "rclient/Settings.h"
#include "ta/process.h"
#include "ta/thread.h"
#include "ta/common.h"

#include <QApplication>
#include <string>


static std::string getAppName()
{
    try {
        return ta::Process::getSelfShortName();
    }
    catch (...) {
        return "ReseptClient";
    }
}

//calls Q_INIT_RESOURCE outside namespace because this macro cannot be used in a namespace
static void initQtResource()
{
    Q_INIT_RESOURCE(RClientAppCommon);
}

//calls Q_CLEANUP_RESOURCE outside namespace because this macro cannot be used in a namespace
static void cleanupQtResource()
{
    Q_CLEANUP_RESOURCE(RClientAppCommon);
}

namespace rclient
{
    boost::thread_specific_ptr<QApplication> QtExclusiveApp::theQtAppPtr;
    boost::recursive_mutex QtExclusiveApp::theMutex;

    QtExclusiveApp::QtExclusiveApp()
    {
        bool ownsLock = false;
        try
        {
            theLock.reset(new boost::recursive_mutex::scoped_try_lock(theMutex));
            ownsLock = theLock->owns_lock();
        }
        catch (std::exception& e)
        {
            TA_THROW_MSG(std::runtime_error, e.what());
        }
        if (!ownsLock)
            TA_THROW_MSG(QtExclusiveAppLockError, "Already locked by another thread");
        if (theQtAppPtr.get())
            TA_THROW_MSG(QtExclusiveAppLockError, "Forbid recursive use");
        init();
    }

    QtExclusiveApp::~QtExclusiveApp()
    {
        deinit();
    }

    void QtExclusiveApp::init()
    {
        if (!theQtAppPtr.get())
        {
            static const std::string myAppName = getAppName();
            static char mySzAppName[512] = {};
            strncpy(mySzAppName, myAppName.c_str(), sizeof(mySzAppName) - 1);
            static char* args[] = { mySzAppName };
            static int argc = 1;

            theQtAppPtr.reset(new QApplication(argc, args));
        }
        initQtResource();
    }

    void QtExclusiveApp::deinit()
    {
        cleanupQtResource();
        theQtAppPtr.reset();
    }

    QtExclusiveApp::Location QtExclusiveApp::exists()
    {
        try
        {
            boost::recursive_mutex::scoped_try_lock lock(theMutex);
            if (!lock.owns_lock())
                return existAnotherThread;
            if (theQtAppPtr.get())
                return existsSameThread;
            return notExists;
        }
        catch (std::exception& e)
        {
            TA_THROW_MSG(std::runtime_error, e.what());
        }
    }

}

