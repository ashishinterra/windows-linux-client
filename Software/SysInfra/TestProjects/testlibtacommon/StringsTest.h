#pragma once

#include "ta/strings.h"
#include "cxxtest/TestSuite.h"
#include "boost/static_assert.hpp"
#include "boost/algorithm/string.hpp"
#include "boost/assign/list_of.hpp"
#include <string>
#include <iostream>
#include <set>

using namespace ta;
using std::string;

class StringsTest : public CxxTest::TestSuite
{
public:
    void testToString()
    {
        TS_ASSERT_EQUALS(Strings::toString(-12), "-12");
        TS_ASSERT_EQUALS(Strings::toString(12), "12");
        TS_ASSERT_EQUALS(Strings::toString(-12.89), "-12.89");
    }
    void testParseInt()
    {
        TS_ASSERT_EQUALS(Strings::parse<int>("12"), 12);
        TS_ASSERT_EQUALS(Strings::parse<int>("0"), 0);
        TS_ASSERT_EQUALS(Strings::parse<int>("-12"), -12);
        TS_ASSERT_EQUALS(Strings::parse<int>(" -12    "), -12);

        TS_ASSERT_THROWS(Strings::parse<int>(""), std::exception);
        TS_ASSERT_THROWS(Strings::parse<int>("not-a-number"), std::exception);
        TS_ASSERT_THROWS(Strings::parse<int>("2147483648"), std::exception); // integer overflow not allowed (2^31)
    }
    void testParseUint()
    {
        TS_ASSERT_EQUALS(Strings::parse<unsigned int>("12"), 12);
        TS_ASSERT_EQUALS(Strings::parse<unsigned int>("0"), 0);
        TS_ASSERT_EQUALS(Strings::parse<unsigned int>(" 12    "), 12);

        TS_ASSERT_THROWS(Strings::parse<unsigned int>(""), std::exception);
        TS_ASSERT_THROWS(Strings::parse<unsigned int>("not-a-number"), std::exception);
        TS_ASSERT_THROWS(Strings::parse<unsigned int>("4294967296"), std::exception); // integer overflow not allowed (2^32)
        TS_ASSERT_THROWS(Strings::parse<unsigned int>("-12"), std::exception); // ineger promotion not allowed
    }
    void testHex()
    {
        const char* mySrcBufs[] = { "abc.", ""};
        const char* myExpectedHexBufs[] = { "6162632e", ""};
        BOOST_STATIC_ASSERT(sizeof(mySrcBufs)/sizeof(mySrcBufs[0]) == sizeof(myExpectedHexBufs)/sizeof(myExpectedHexBufs[0]));

        for (size_t i = 0; i < sizeof(mySrcBufs)/sizeof(mySrcBufs[0]); ++i)
        {
            const size_t mySrcBufLen = strlen(mySrcBufs[i]);

            string myHexStr = Strings::toHex((const unsigned char*)mySrcBufs[i], mySrcBufLen, Strings::caseLower);
            TS_ASSERT_EQUALS(myHexStr, myExpectedHexBufs[i]);

            std::vector<unsigned char> myActualSrcBuf = Strings::fromHex(myHexStr);
            TS_ASSERT(myActualSrcBuf.size() == mySrcBufLen);
            if (!myActualSrcBuf.empty())
                TS_ASSERT(memcmp(ta::getSafeBuf(myActualSrcBuf), mySrcBufs[i], mySrcBufLen) == 0);

            myHexStr = Strings::toHex((const unsigned char*)mySrcBufs[i], mySrcBufLen, Strings::caseUpper);
            TS_ASSERT_EQUALS(myHexStr, boost::to_upper_copy(string(myExpectedHexBufs[i])));

            myActualSrcBuf = Strings::fromHex(myHexStr);
            TS_ASSERT(myActualSrcBuf.size() == mySrcBufLen);
            if (!myActualSrcBuf.empty())
                TS_ASSERT(memcmp(ta::getSafeBuf(myActualSrcBuf), mySrcBufs[i], mySrcBufLen) == 0);
        }
        TS_ASSERT_THROWS(Strings::fromHex("123"), std::invalid_argument);
        TS_ASSERT_THROWS(Strings::fromHex("[]!-"), std::invalid_argument);
        TS_ASSERT_EQUALS(Strings::fromHex("FF"), Strings::fromHex("ff"));
    }

    void test_parse_bool()
    {
        using ta::Strings::boolToStr;
        using ta::Strings::strToBool;

        {
            TS_ASSERT_EQUALS(boolToStr(true), "true");
            TS_ASSERT_EQUALS(boolToStr(false), "false");
        }

        {
            const ta::StringArray strs = boost::assign::list_of("true")("True")("tRUE")("TRUE");
            foreach (const std::string& s, strs)
            {
                bool result = false;
                TS_ASSERT(strToBool(s, result));
                TS_ASSERT(result);
            }
        }

        {
            const ta::StringArray trueStrs = boost::assign::list_of("false")("False")("fAlse")("FALSE");
            foreach (const std::string& s, trueStrs)
            {
                bool result = true;
                TS_ASSERT(strToBool(s, result));
                TS_ASSERT(!result);
            }
        }

        {
            bool result;
            TS_ASSERT(!strToBool("not-a-boolean", result));
            TS_ASSERT(!strToBool("", result));
        }
    }

    void testSplit_MergeOff_PreserveEmptyTokens()
    {
        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab")("")("cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ';'), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(';');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("whitespace")("-")("")("separated")("")("")("text")("")("");
            const std::vector<char> mySeps = boost::assign::list_of(' ')('\t');
            TS_ASSERT_EQUALS(Strings::split("whitespace - \tseparated \t text\t ", mySeps), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab;;cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ':'), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(':');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("");
            TS_ASSERT_EQUALS(Strings::split("", ':'), myExpectedRes);
        }

        TS_ASSERT_THROWS(Strings::split("", std::vector<char>()), std::logic_error);
    }

    void testSplit_MergeOn_PreserveEmptyTokens()
    {
        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab")("cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ';', Strings::sepsMergeOn), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(';');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOn), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("whitespace")("-")("separated")("text")("");
            const std::vector<char> mySeps = boost::assign::list_of(' ')('\t');
            TS_ASSERT_EQUALS(Strings::split("whitespace - \tseparated \t text\t ", mySeps, Strings::sepsMergeOn), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab;;cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ':', Strings::sepsMergeOn), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(':');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOn), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("");
            TS_ASSERT_EQUALS(Strings::split("", ':', Strings::sepsMergeOn), myExpectedRes);
        }

        TS_ASSERT_THROWS(Strings::split("", std::vector<char>(),  Strings::sepsMergeOn), std::logic_error);
    }

    void testSplit_MergeOff_DropEmptyTokens()
    {
        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab")("cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ';', Strings::sepsMergeOff, Strings::emptyTokensDrop), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(';');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOff, Strings::emptyTokensDrop), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("whitespace")("-")("separated")("text");
            const std::vector<char> mySeps = boost::assign::list_of(' ')('\t');
            TS_ASSERT_EQUALS(Strings::split("whitespace - \tseparated \t text\t ", mySeps, Strings::sepsMergeOff, Strings::emptyTokensDrop), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab;;cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ':', Strings::sepsMergeOff, Strings::emptyTokensDrop), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(':');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOff, Strings::emptyTokensDrop), myExpectedRes);
        }

        TS_ASSERT_EQUALS(Strings::split("", ':', Strings::sepsMergeOff, Strings::emptyTokensDrop), std::vector<string>());

        TS_ASSERT_THROWS(Strings::split("", std::vector<char>(), Strings::sepsMergeOff, Strings::emptyTokensDrop), std::logic_error);
    }

    void testSplit_MergeOn_DropEmptyTokens()
    {
        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab")("cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ';', Strings::sepsMergeOn, Strings::emptyTokensDrop), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(';');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOn, Strings::emptyTokensDrop), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("whitespace")("-")("separated")("text");
            const std::vector<char> mySeps = boost::assign::list_of(' ')('\t');
            TS_ASSERT_EQUALS(Strings::split("whitespace - \tseparated \t text\t ", mySeps, Strings::sepsMergeOn, Strings::emptyTokensDrop), myExpectedRes);
        }

        {
            const ta::StringArray myExpectedRes = boost::assign::list_of("ab;;cd");
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", ':', Strings::sepsMergeOn, Strings::emptyTokensDrop), myExpectedRes);
            const std::vector<char> mySeps = boost::assign::list_of(':');
            TS_ASSERT_EQUALS(Strings::split("ab;;cd", mySeps, Strings::sepsMergeOn, Strings::emptyTokensDrop), myExpectedRes);
        }

        TS_ASSERT_EQUALS(Strings::split("", ':', Strings::sepsMergeOn, Strings::emptyTokensDrop), std::vector<string>());

        TS_ASSERT_THROWS(Strings::split("", std::vector<char>(),  Strings::sepsMergeOn, Strings::emptyTokensDrop), std::logic_error);
    }

    void testJoin()
    {
        {
            const ta::StringArray myStrList = boost::assign::list_of("ab")("")("cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ','), "ab,,cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ',', Strings::emptyStringsSkip), "ab,cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ","), "ab,,cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ",", Strings::emptyStringsSkip), "ab,cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ", "), "ab, , cd");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ""), "abcd");
            TS_ASSERT_EQUALS(Strings::join(std::vector<string>(), ""), "");
        }

        {
            const ta::StringArray myStrList = boost::assign::list_of("")("X");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ","), ",X");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ",", Strings::emptyStringsSkip), "X");
        }

        {
            const ta::StringArray myStrList = boost::assign::list_of("")("");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ','), ",");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ","), ",");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ",", Strings::emptyStringsSkip), "");
            TS_ASSERT_EQUALS(Strings::join(myStrList, ""), "");
        }

        {
            const std::vector<int> myIntList = boost::assign::list_of(-1)(1)(2);
            TS_ASSERT_EQUALS(Strings::join(myIntList, ','), "-1,1,2");
            TS_ASSERT_EQUALS(Strings::join(myIntList, ","), "-1,1,2");
            TS_ASSERT_EQUALS(Strings::join(myIntList, ", "), "-1, 1, 2");
            TS_ASSERT_EQUALS(Strings::join(myIntList, ""), "-112");
            TS_ASSERT_EQUALS(Strings::join(std::vector<int>(), ""), "");
        }

        {
            const std::vector<unsigned int> myUintList = boost::assign::list_of(1)(2);
            TS_ASSERT_EQUALS(Strings::join(myUintList, ','), "1,2");
            TS_ASSERT_EQUALS(Strings::join(myUintList, ","), "1,2");
            TS_ASSERT_EQUALS(Strings::join(myUintList, ", "), "1, 2");
            TS_ASSERT_EQUALS(Strings::join(myUintList, ""), "12");
            TS_ASSERT_EQUALS(Strings::join(std::vector<unsigned int>(), ""), "");
        }
    }

    void testSubstTemplate()
    {
        {
            const ta::StringDict myMappings;
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $(what1) and dislikes $(what2)", myMappings), "$(who) likes $(what1) and dislikes $(what2)");
        }

        {
            const ta::StringDict myMappings = boost::assign::map_list_of("who", "Jos")("what1", "PSV")("what2", "Ajax");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $(what1) and hates $(what2)", myMappings), "Jos likes PSV and hates Ajax");
        }

        {
            const ta::StringDict myMappings = boost::assign::map_list_of("who", "Jos");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $(what)", myMappings), "Jos likes $(what)");
        }

        {
            const ta::StringDict myMappings = boost::assign::map_list_of("who", "Jos")("whatever", "Ajax");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $(what)", myMappings), "Jos likes $(what)");
        }

        // Test that the function does not work recursively
        {
            const ta::StringDict myMappings = boost::assign::map_list_of("who", "$(what)")("what", "$(who)");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $(what)", myMappings), "$(what) likes $(who)");
        }

        //
        // Test quotation
        //
        {
            const ta::StringDict myMappings = boost::assign::list_of <ta::StringDict::value_type>("who", "Jos")("what1", "PSV");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $$(what1) and hates $$(what2)", myMappings), "Jos likes $(what1) and hates $$(what2)");
        }

        {
            const ta::StringDict myMappings = boost::assign::list_of <ta::StringDict::value_type>("who", "Jos")("what2", "Ajax");
            TS_ASSERT_EQUALS(Strings::substTemplate("$$(who) likes $(what1) and hates $(what2)", myMappings), "$(who) likes $(what1) and hates Ajax");
        }

        {
            const ta::StringDict myMappings = boost::assign::map_list_of("who", "$(who)")("what", "Ajax");
            TS_ASSERT_EQUALS(Strings::substTemplate("$(who) likes $$(what)", myMappings), "$(who) likes $(what)");
        }

        // Test invalid keys
        {
            const ta::StringDict myMappings = boost::assign::map_list_of("$(who)", "Jos");
            TS_ASSERT_THROWS(Strings::substTemplate("$(who) likes $(what)", myMappings), std::invalid_argument);
        }
    }

    void testParseTemplate()
    {
        ta::StringSet mySet;

        mySet = Strings::parseTemplate("Some string without any placeholders");
        TS_ASSERT(mySet.empty());

        // make sure all common placeholders are recognized
        mySet = Strings::parseTemplate("This $(userid) contains $(domain) all $(password) six $(pincode) "
                "placeholders $(server)");
        TS_ASSERT_EQUALS(mySet.size(), 5U);
        TS_ASSERT_EQUALS(mySet.count("userid") + mySet.count("domain") + mySet.count("password") +
                mySet.count("pincode") + mySet.count("server"), 5U);

        // check handling of duplicates.
        mySet = Strings::parseTemplate("This $(domain)$(userid) is $(domain) a $(userid)$ test");
        TS_ASSERT_EQUALS(mySet.size(), 2U);
        TS_ASSERT_EQUALS(mySet.count("userid") + mySet.count("domain"), 2U);

        // check escaping, only $(domain) should be parsed
        mySet = Strings::parseTemplate("The $$(userid) on $$(server) in $$$(domain) uses $$$$(password).");
        TS_ASSERT_EQUALS(mySet.size(), 1U);
        TS_ASSERT_EQUALS(mySet.count("userid") + mySet.count("server") + mySet.count("domain") +
                mySet.count("password"), 1U);

        // check unclosed parenthesis
        mySet = Strings::parseTemplate("A string which doesn't $(properly close its placeholder");
        TS_ASSERT(mySet.empty());

        // test end of string handling.
        mySet = Strings::parseTemplate("A $(userid)$(");
        TS_ASSERT_EQUALS(mySet.size(), 1U);
        TS_ASSERT_EQUALS(mySet.count("userid"), 1U);

        // check nesting
        mySet = Strings::parseTemplate("A $(use$(id)) and $$(dom$(ain)) $example$(string)");
        TS_ASSERT_EQUALS(mySet.size(), 3U);
        TS_ASSERT_EQUALS(mySet.count("use$(id") + mySet.count("ain") + mySet.count("string"), 3U);
    }
    void testWideMbyteConversions()
    {
#ifdef _WIN32
        using ta::Strings::utf8ToWide;
        using ta::Strings::toUtf8;

        const std::string myStrUtf8 = "андрей-ü";
        const std::wstring myStrUtf16 = L"\x430\x43D\x434\x440\x435\x439-\xFC";

        TS_ASSERT_EQUALS(utf8ToWide(myStrUtf8), myStrUtf16);
        TS_ASSERT_EQUALS(toUtf8(myStrUtf16), myStrUtf8);

        TS_ASSERT_EQUALS(utf8ToWide(""), L"");
        TS_ASSERT_EQUALS(toUtf8(L""), "");
#else
        TS_SKIP("The test is for Windows only");
#endif
    }

    void testWildcardMatch()
    {
        using namespace ta::Strings;


        // simple
        TS_ASSERT(wildcardMatch("", ""));
        TS_ASSERT(!wildcardMatch("myfile.txt", ""));
        TS_ASSERT(wildcardMatch("myfile.txt", "myfile.txt"));
        TS_ASSERT(!wildcardMatch("mYfile.txt", "myfile.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "mYfile.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "otherfile.txt"));

        // '*'
        TS_ASSERT(!wildcardMatch("*", "*.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "*.txt"));
        TS_ASSERT(!wildcardMatch("myfile.TXT", "*.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "*.tXt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "*file.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "*file.xls"));
        TS_ASSERT(wildcardMatch("myfile.txt", "my*"));
        TS_ASSERT(wildcardMatch("myfile.txt", "my*file.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "my*.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "my*.xls"));
        TS_ASSERT(wildcardMatch("myfile.txt", "*.*"));
        TS_ASSERT(wildcardMatch("myfile.txt", "*"));

        // '?'
        TS_ASSERT(wildcardMatch("myfile.txt", "??file.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "m?file.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "?file.txt"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "???file.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "??file.???"));
        TS_ASSERT(wildcardMatch("myfile.txt", "??????.???"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "?????.???"));

        // '*' and '?'
        TS_ASSERT(wildcardMatch("myfile.txt", "?*file.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "*?file.txt"));
        TS_ASSERT(wildcardMatch("myfile.txt", "myfile.*"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "?myfile.*"));
        TS_ASSERT(!wildcardMatch("myfile.txt", "*myfile.??"));

    }

};
