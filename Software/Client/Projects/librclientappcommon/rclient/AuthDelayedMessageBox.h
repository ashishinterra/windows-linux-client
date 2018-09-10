#pragma once

#include <string>

class QWidget;

namespace AuthDelayedMessageBox
{
    //@return whether another authentication attempt is requested
    bool show (QWidget* aParent, const size_t aDelay);

    //@return whether another authentication attempt is requested
    bool show (QWidget* aParent, const std::string& aMsgText, const bool aRetryButton, const size_t aDelay);

}
