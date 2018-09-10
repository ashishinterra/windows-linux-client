#include "QtAppSingleton.h"
#include "ta/process.h"
#include "rclient/Settings.h"

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
    QtAppSingleton::QtAppSingleton()
        : theQtAppPtr(NULL)
    {
        static const std::string myAppName = getAppName();
        static char mySzAppName[512] = {};
        strncpy(mySzAppName, myAppName.c_str(), sizeof(mySzAppName) - 1);
        static char* args[] = { mySzAppName };
        static int argc = 1;

        theQtAppPtr = new QApplication(argc, args);

        initQtResource();
    }

    QtAppSingleton::~QtAppSingleton()
    {
        cleanupQtResource();
        delete theQtAppPtr;
    }
}
