#pragma once

#include "ta/hashutils.h"
#include "ta/strings.h"
#include "ta/utils.h"
#include "cxxtest/TestSuite.h"
#include "boost/static_assert.hpp"
#include <string>
#include <vector>

class HashUtilsTest : public CxxTest::TestSuite
{
public:
    void tearDown()
    {
        remove(TempFileName.c_str());
    }
	void testMd5()
	{
        static const char* mySrcStrs[] = { "Hello World",
                                           "",
                                           "Some Very Very Long Text Some Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text\nSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text"};
        static const char* myExpectedHashes[] = { "b10a8db164e0754105b7a99be72e3fe5",
                                                  "d41d8cd98f00b204e9800998ecf8427e",
                                                  "6ae13b2655a0961e67e673ea719c8d51"};
        BOOST_STATIC_ASSERT(sizeof(mySrcStrs)/sizeof(mySrcStrs[0]) == sizeof(myExpectedHashes)/sizeof(myExpectedHashes[0]) );

        for (size_t i = 0; i < sizeof(mySrcStrs)/sizeof(mySrcStrs[0]); ++i)
        {
            const char* mySrcStr = mySrcStrs[i];
            const std::vector<unsigned char> mySrc(mySrcStr, mySrcStr + strlen(mySrcStr));

            const string myHashedValHex = ta::HashUtils::getMd5Hex(mySrc);
            TS_ASSERT(myHashedValHex.size() ==  32);
            TS_ASSERT_EQUALS(myHashedValHex, myExpectedHashes[i]);

            const std::vector<unsigned char> myHashedValBin = ta::HashUtils::getMd5Bin(mySrc);
            TS_ASSERT(myHashedValBin.size() == 16);
            TS_ASSERT_EQUALS(myHashedValHex, Strings::toHex(ta::getSafeBuf(myHashedValBin), myHashedValBin.size()));

            ta::writeData(TempFileName, mySrc);
            TS_ASSERT_EQUALS(ta::HashUtils::getMd5HexFile(TempFileName), myHashedValHex);
            TS_ASSERT_EQUALS(ta::HashUtils::getMd5BinFile(TempFileName), myHashedValBin);
        }

        TS_ASSERT_EQUALS(ta::HashUtils::getMd5HexFile(BlobFileName), "65a9495a436f5402bc1c467e1b926c27");
    }

	void testSha1()
	{
        static const char* mySrcStrs[] = { "Hello World",
                                           "",
                                           "Some Very Very Long Text Some Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text\nSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text"};
        static const char* myExpectedHashes[] = { "0a4d55a8d778e5022fab701977c5d840bbc486d0",
                                                  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                                  "0af04507baeab7549c6f69ee4effb8e4045119be"};
        BOOST_STATIC_ASSERT(sizeof(mySrcStrs)/sizeof(mySrcStrs[0]) == sizeof(myExpectedHashes)/sizeof(myExpectedHashes[0]) );

        for (size_t i = 0; i < sizeof(mySrcStrs)/sizeof(mySrcStrs[0]); ++i)
        {
            const char* mySrcStr = mySrcStrs[i];
            const std::vector<unsigned char> mySrc(mySrcStr, mySrcStr + strlen(mySrcStr));

            string myHashedValHex = ta::HashUtils::getSha1Hex(mySrc);
            TS_ASSERT_EQUALS(myHashedValHex.size(), 40U);
            TS_ASSERT_EQUALS(myHashedValHex, myExpectedHashes[i]);

            std::vector<unsigned char> myHashedValBin = ta::HashUtils::getSha1Bin(mySrc);
            TS_ASSERT_EQUALS(myHashedValBin.size(), 20U);
            TS_ASSERT_EQUALS(myHashedValHex, Strings::toHex(ta::getSafeBuf(myHashedValBin), myHashedValBin.size()));

            ta::writeData(TempFileName, mySrc);
            TS_ASSERT_EQUALS(ta::HashUtils::getSha1HexFile(TempFileName), myHashedValHex);
            TS_ASSERT_EQUALS(ta::HashUtils::getSha1BinFile(TempFileName), myHashedValBin);
        }

        TS_ASSERT_EQUALS(ta::HashUtils::getSha1HexFile(BlobFileName), "587f7e2ed04dca2f4dbe84d90afd0c223f52b1cd");
    }

	void testSha256()
	{
        static const char* mySrcStrs[] = { "Hello World",
                                           "",
                                           "Some Very Very Long Text Some Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text Some Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text\nSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long TextSome Very Very Long Text"};
        static const char* myExpectedHashes[] = { "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                                                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                                  "37cdcaca36b7daa9cbec7ec883f74163404faa68af16428f7219ede250ad273a"};
        BOOST_STATIC_ASSERT(sizeof(mySrcStrs)/sizeof(mySrcStrs[0]) == sizeof(myExpectedHashes)/sizeof(myExpectedHashes[0]) );

        for (size_t i = 0; i < sizeof(mySrcStrs)/sizeof(mySrcStrs[0]); ++i)
        {
            const char* mySrcStr = mySrcStrs[i];
            const std::vector<unsigned char> mySrc(mySrcStr, mySrcStr + strlen(mySrcStr));

            string myHashedValHex = ta::HashUtils::getSha256Hex(mySrc);
            TS_ASSERT_EQUALS(myHashedValHex.size(), 64U);
            TS_ASSERT_EQUALS(myHashedValHex, myExpectedHashes[i]);

            std::vector<unsigned char> myHashedValBin = ta::HashUtils::getSha256Bin(mySrc);
            TS_ASSERT_EQUALS(myHashedValBin.size(), 32U);
            TS_ASSERT_EQUALS(myHashedValHex, Strings::toHex(ta::getSafeBuf(myHashedValBin), myHashedValBin.size()));

            ta::writeData(TempFileName, mySrc);
            TS_ASSERT_EQUALS(ta::HashUtils::getSha256HexFile(TempFileName), myHashedValHex);
            TS_ASSERT_EQUALS(ta::HashUtils::getSha256BinFile(TempFileName), myHashedValBin);
        }

        TS_ASSERT_EQUALS(ta::HashUtils::getSha256HexFile(BlobFileName), "f697d5b221ddfd2ffbecaf8cca252701ab976cf8cbb74ce0238ef336093327a8");
    }

    void testBcrypt()
    {
#ifdef RESEPT_SERVER
        {
            //given
            const string myEmptyPwd = "";
            const string myEmptyHash = "";
            //when-then
            TS_TRACE("Testing empty password gets hashed as well");
            TS_ASSERT_DIFFERS(ta::HashUtils::getBcryptHash(myEmptyPwd), myEmptyHash);
        }
        {
            //given
            const string myTestPwd = "Testtesttest";
            //when
            const string myGoodHash = ta::HashUtils::getBcryptHash(myTestPwd);
            //then
            TS_TRACE("Testing if password is validated correctly");
            TS_ASSERT(ta::HashUtils::isBcryptPasswdValid(myTestPwd, myGoodHash));
        }
        {
            //given
            const string myTestPwd = "Testtesttest";
            const string myIncorrectPwd = "INCORRECT";
            //when
            const string myGoodHash = ta::HashUtils::getBcryptHash(myTestPwd);
            //then
            TS_TRACE("Testing if incorrect password is rejected");
            TS_ASSERT(!ta::HashUtils::isBcryptPasswdValid(myIncorrectPwd, myGoodHash));
        }
        {
            //given
            const string myEmptyHash = "";
            const string myVeryLongPwd = "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest";
            //when-hen
            TS_TRACE("Testing very long hash");
            TS_ASSERT(ta::HashUtils::getBcryptHash(myVeryLongPwd) != myEmptyHash);
        }
        {
            //given
            const string myEmptyPwd = "";
            //when
            const string myGoodHash = ta::HashUtils::getBcryptHash(myEmptyPwd);
            //then
            TS_TRACE("Testing that password validation with empty password");
            TS_ASSERT(ta::HashUtils::isBcryptPasswdValid(myEmptyPwd, myGoodHash));
        }
        {
            //given
            const string myFilename = "bcrypt_test_password.txt";
            const string myTestPwd = "Testtesttest";
            //when
            ta::writeData(myFilename, myTestPwd);
            const string myHashFromFile = ta::HashUtils::getBcryptHashFile(myFilename);
            //then
            TS_TRACE("Testing bcrypt file access");
            TS_ASSERT(ta::HashUtils::isBcryptPasswdValid(myTestPwd, myHashFromFile));
        }
        {
            //given
            const string myTestPwd = "Testpassword";
            const string myEmptyHash = "";
            //when-then
            TS_TRACE("Verifying that password validation with empty hash is not possible");
            TS_ASSERT_THROWS(ta::HashUtils::isBcryptPasswdValid(myTestPwd, myEmptyHash), std::exception);
        }
#else
        TS_SKIP("testBcrypt will only be tested on server");
#endif
    }


    static const std::string TempFileName;
    static const std::string BlobFileName;
};

const std::string HashUtilsTest::TempFileName = "hashutilstest.tmp";
const std::string HashUtilsTest::BlobFileName = "blob.tst";
