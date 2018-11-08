#pragma once

#include "ta/utils.h"
#include "ta/process.h"
#include "cxxtest/TestSuite.h"
#include <cstdio>
#include <string>
#include <vector>
#include "boost/assign/list_of.hpp"

template <class T> bool operator==(const std::vector<T>& lhv, const std::basic_string<T>& rhs)
{
    std::string lhs;
    if (!lhv.empty())
    {
        lhs.assign(&lhv[0], lhv.size());
    }
    return lhs == rhs;
}

class UtilsTest : public CxxTest::TestSuite
{
public:
    void testReadWriteData()
    {
        static const std::string myFileName = "file.tmp";

        {
            TS_TRACE("Checking empty file");

            remove(myFileName.c_str());
            ta::writeData(myFileName, std::vector<char>());
            const std::vector<char> myReadDataVec = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, std::vector<char>());
            const std::vector<char> myReadDataStr = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, myReadDataStr);
        }

        {
            TS_TRACE("Checking file with ASCII characters");

            remove(myFileName.c_str());
            const std::vector<char> myExpectedData = boost::assign::list_of('x')('y')('z');
            ta::writeData(myFileName, myExpectedData);
            std::vector<char> myReadDataVec = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, myExpectedData);
            std::vector<char> myReadDataStr = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, myReadDataStr);

            remove(myFileName.c_str());
            const std::string myExpectedDataStr(myExpectedData.begin(), myExpectedData.end());
            ta::writeData(myFileName, myExpectedDataStr);
            myReadDataVec = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, myExpectedData);
            myReadDataStr = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataVec, myReadDataStr);
        }


        {
            TS_TRACE("Checking file with integers");

            remove(myFileName.c_str());
            const std::vector<int> myExpectedDataInt = boost::assign::list_of(1)(0)(-1);
            ta::writeData(myFileName, myExpectedDataInt);
            const std::vector<int> myReadDataInt = ta::readData(myFileName);
            TS_ASSERT_EQUALS(myReadDataInt, myExpectedDataInt);
        }

        remove(myFileName.c_str());
    }

    void testReadTail()
    {
        static const std::string myFileName = "file.tmp";
        std::vector<char> myExpectedData;
        std::string myExpectedDataStr;
        std::vector<char> myReadDataVec;
        std::vector<char> myReadDataStr;
        std::vector<int> myReadDataInt;

        remove(myFileName.c_str());

        TS_TRACE("Checking empty file");

        ta::writeData(myFileName, myExpectedData);
        myReadDataVec = ta::readTail(myFileName, 0);
        TS_ASSERT(myReadDataVec.empty());
        myReadDataStr = ta::readTail(myFileName, 0);
        TS_ASSERT(myReadDataStr.empty());
        myReadDataVec = ta::readTail(myFileName, 123456);
        TS_ASSERT(myReadDataVec.empty());
        myReadDataStr = ta::readTail(myFileName, 654321);
        TS_ASSERT(myReadDataStr.empty());


        TS_TRACE("Checking file with ASCII characters");

        ta::writeData(myFileName, std::string("\n"));
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 0), "");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 1), "\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 123456), "\n");

        ta::writeData(myFileName, std::string("line1"));
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 0), "");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 1), "line1");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 123456), "line1");

        ta::writeData(myFileName, std::string("line1\n"));
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 0), "");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 1), "line1\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 123456), "line1\n");

        ta::writeData(myFileName, std::string("line1\n"
                    "line2\r\n"
                    "line3\n"
                    "\r\n"));
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 0), "");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 1), "\r\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 2), "line3\n\r\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 3), "line2\r\nline3\n\r\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 4), "line1\nline2\r\nline3\n\r\n");
        TS_ASSERT_EQUALS((std::string)ta::readTail(myFileName, 5), "line1\nline2\r\nline3\n\r\n");

        TS_TRACE("Checking file with integers");

        const std::vector<int> myExpectedDataInt = boost::assign::list_of(1)(0)(-1);
        ta::writeData(myFileName, myExpectedDataInt);
        myReadDataInt = ta::readTail(myFileName, 0);
        TS_ASSERT(myReadDataInt.empty());
        myReadDataInt = ta::readTail(myFileName, 45678);
        TS_ASSERT_EQUALS(myReadDataInt, myExpectedDataInt);

        remove(myFileName.c_str());
    }

    void testValidateEmail()
    {
        TS_ASSERT(!ta::isValidEmail(""));
        TS_ASSERT(!ta::isValidEmail("abcdef"));
        TS_ASSERT(!ta::isValidEmail("user@domain"));

        TS_ASSERT(ta::isValidEmail("user@domain.com"));
    }

    void testValidatePhoneNumber()
    {
        TS_ASSERT(!ta::isValidPhoneNumber(""));
        // not in international format
        TS_ASSERT(!ta::isValidPhoneNumber("06450330000"));
        // NaNs
        TS_ASSERT(!ta::isValidPhoneNumber("+31645633000X"));
        // too long
        TS_ASSERT(!ta::isValidPhoneNumber("+3164563300000001"));
        // too short
        TS_ASSERT(!ta::isValidPhoneNumber("+3164563"));

        TS_ASSERT(ta::isValidPhoneNumber("+316456330"));
        TS_ASSERT(ta::isValidPhoneNumber("+316456330000"));
        TS_ASSERT(ta::isValidPhoneNumber("+316456330000000"));
        TS_ASSERT(ta::isValidPhoneNumber("+31-64-563-300-00"));
    }

    void testFileExist()
    {
#ifdef _WIN32
        TS_ASSERT(ta::isFileExist(ta::Process::getSelfFullName()));
        TS_ASSERT(!ta::isFileExist("C:\\i\\hope\\this\\file\\does\\not\\exit"));
        TS_ASSERT(!ta::isFileExist("C:\\"));// directory, not a file
#else
        TS_ASSERT(ta::isFileExist("/bin/sh"));
        TS_ASSERT(!ta::isFileExist("/i/hope/this/file/does/not/exit"));
        TS_ASSERT(!ta::isFileExist("/bin"));// directory, not a file
#endif
        TS_ASSERT(!ta::isFileExist(""));
    }
    void testDirExist()
    {
        TS_ASSERT(ta::isDirExist("./"));
#ifdef _WIN32
        TS_ASSERT(ta::isDirExist(ta::Process::getSelfDirName()));
        TS_ASSERT(ta::isDirExist("C:\\"));
        TS_ASSERT(!ta::isDirExist("C:\\i\\hope\\this\\directory\\does\\not\\exit"));
        TS_ASSERT(!ta::isDirExist(ta::Process::getSelfFullName()));// file, not a directory
#else
        TS_ASSERT(ta::isDirExist("/bin"));
        TS_ASSERT(!ta::isDirExist("/i/hope/this/directory/does/not/exit"));
        TS_ASSERT(!ta::isDirExist("/bin/sh"));// file, not a directory
#endif
    }
    void testRegexEscapeStr()
    {
        TS_ASSERT_EQUALS(ta::regexEscapeStr("abcDEF123"), "abcDEF123");
        TS_ASSERT_EQUALS(ta::regexEscapeStr(""), "");
        TS_ASSERT_EQUALS(ta::regexEscapeStr("ab\\s.*c"), "ab\\\\s\\.\\*c");
    }

    void testUuid()
    {
        std::vector<std::string> myUids;
        for (size_t i=0; i < 1000; ++i)
        {
            const std::string myUid = ta::genUuid();
            TS_ASSERT_EQUALS(myUid.size(), 32U);
            TS_ASSERT(std::find(myUids.begin(), myUids.end(), myUid) == myUids.end());
            myUids.push_back(myUid);
        }
    }

    void testRawUuid()
    {
        std::vector<std::vector<unsigned char> > myRawUids;
        for (size_t i=0; i < 1000; ++i)
        {
            const std::vector<unsigned char> myRawUid = ta::genRawUuid();
            TS_ASSERT_EQUALS(myRawUid.size(), 16U);
            TS_ASSERT(std::find(myRawUids.begin(), myRawUids.end(), myRawUid) == myRawUids.end());
            myRawUids.push_back(myRawUid);
        }
    }

    void testRand()
    {
        TS_ASSERT_EQUALS(ta::genRand(1), 0U);
        TS_ASSERT_LESS_THAN(ta::genRand(1024), 1024U);
        TS_ASSERT_LESS_THAN(ta::genRand(UINT_MAX), UINT_MAX);
        TS_ASSERT_THROWS(ta::genRand(0), std::exception);
    }

    void testRandBufMustGenerateBufferWithTheRequestedSize()
    {
        for (unsigned int buf_size=1; buf_size < 32; ++buf_size)
        {
            TS_ASSERT_EQUALS(ta::genRandBuf(buf_size).size(), buf_size);
        }
    }

    void testRandBufMustGiveErrorForBufferSizeOfZero()
    {
        TS_ASSERT_THROWS(ta::genRandBuf(0), std::exception);
    }

    void testGetUsername()
    {
        const std::string myUserName = ta::getUserName();
        TS_ASSERT(!myUserName.empty());
        TS_TRACE("My username is: " + myUserName);
    }

};
