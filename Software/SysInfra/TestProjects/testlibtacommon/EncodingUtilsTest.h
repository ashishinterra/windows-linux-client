#pragma once

#include "ta/encodingutils.h"
#include "ta/utils.h"
#include "cxxtest/TestSuite.h"
#include <string>
#include <vector>

using namespace ta;
using std::string;
using std::vector;

class EncodingUtilsTest : public CxxTest::TestSuite
{
public:
    void testBase64EncodeDecode()
    {
        using namespace ta::EncodingUtils;

        // Same result for multiline and single line (rather short source string)
        string mySource = "https://siouxdemo.trustalert.com";
        string myExpectedBase64 = "aHR0cHM6Ly9zaW91eGRlbW8udHJ1c3RhbGVydC5jb20=";
        string myActualBase64 = toBase64(str2Vec<unsigned char>(mySource));
        TS_ASSERT_EQUALS(myActualBase64, myExpectedBase64);
        vector<unsigned char> myActualSource = fromBase64(myActualBase64);
        TS_ASSERT_EQUALS(str2Vec<unsigned char>(mySource), myActualSource);
        TS_ASSERT_EQUALS(fromBase64(myActualBase64), fromBase64(myActualBase64+"\n"));

        TS_ASSERT_EQUALS(toBase64(str2Vec<unsigned char>(mySource), true),
                toBase64(str2Vec<unsigned char>(mySource), false));
        TS_ASSERT_EQUALS(fromBase64(myActualBase64, true), fromBase64(myActualBase64, false));
        TS_ASSERT_EQUALS(fromBase64(myActualBase64+"\n", true), fromBase64(myActualBase64+"\n", false));

        // Different result for multiline and single line (rather long source string)
        mySource = "CS-b8769e55a449d693813e50b1a4cc7ae32979dc147369a75dabc6b61a84368893";
        string myActualBase64MultiLine = toBase64(str2Vec<unsigned char>(mySource));
        string myActualBase64SingleLine = toBase64(str2Vec<unsigned char>(mySource), true);
        TS_ASSERT_EQUALS(myActualBase64MultiLine,  "Q1MtYjg3NjllNTVhNDQ5ZDY5MzgxM2U1MGIxYTRjYzdhZTMyOTc5ZGMxNDczNjlh\nNzVkYWJjNmI2MWE4NDM2ODg5Mw==");
        TS_ASSERT_EQUALS(myActualBase64SingleLine, "Q1MtYjg3NjllNTVhNDQ5ZDY5MzgxM2U1MGIxYTRjYzdhZTMyOTc5ZGMxNDczNjlhNzVkYWJjNmI2MWE4NDM2ODg5Mw==");
        vector<unsigned char> myActualSourceMultiLine = fromBase64(myActualBase64MultiLine, false);
        vector<unsigned char> myActualSourceSingleLine = fromBase64(myActualBase64SingleLine, true);
        TS_ASSERT_EQUALS(str2Vec<unsigned char>(mySource), myActualSourceMultiLine);
        TS_ASSERT_EQUALS(str2Vec<unsigned char>(mySource), myActualSourceSingleLine);

        // Boundary conditions
        TS_ASSERT_EQUALS(toBase64(vector<unsigned char>(),true), "");
        TS_ASSERT_EQUALS(toBase64(vector<unsigned char>(),false), "");
        vector<unsigned char> myEmptyVec;
        TS_ASSERT_EQUALS(fromBase64("", true), myEmptyVec);
        TS_ASSERT_EQUALS(fromBase64("\n", false), myEmptyVec);
    }
    void testUrlEncodeDecode()
    {
        using namespace ta::EncodingUtils;

        const string myOrig = "/replace+me%20: \"here~\"/";
        const string myEncodedwithPlus = "/replace%2Bme%2520%3A+%22here%7E%22/";
        const string myEncodedWithHex = "/replace%2Bme%2520%3A%20%22here%7E%22/";

        TS_ASSERT_EQUALS(urlEncode(myOrig), myEncodedwithPlus);
        TS_ASSERT_EQUALS(urlDecode(myEncodedwithPlus), myOrig);
        TS_ASSERT_EQUALS(urlEncode(myOrig, encodeSpaceAsHex), myEncodedWithHex);
        TS_ASSERT_EQUALS(urlDecode(myEncodedWithHex), myOrig);

        TS_ASSERT_EQUALS(urlEncode(" "), "+");
        TS_ASSERT_EQUALS(urlEncode(" ", encodeSpaceAsHex), "%20");
        TS_ASSERT_EQUALS(urlDecode("+"), " ");
        TS_ASSERT_EQUALS(urlDecode("%20"), " ");

        TS_ASSERT_EQUALS(urlEncode("/"), "/");
        TS_ASSERT_EQUALS(urlDecode("/%2F%2f"), "///");

        TS_ASSERT_EQUALS(urlEncode(""), "");
        TS_ASSERT_EQUALS(urlDecode(""), "");
    }
    void testDataUriPngImageEncodeDecode()
    {
        using namespace ta::EncodingUtils;

        const std::vector<unsigned char> myValidPngImage = ta::readData("30x32.png");
        const std::vector<unsigned char> myInvalidPngImage = ta::readData("30x32x8.bmp");

        const std::string myEncodedPng = dataUriEncodePngImage(myValidPngImage);
        TS_ASSERT_EQUALS(dataUriDecodePngImage(myEncodedPng), myValidPngImage);

        TS_ASSERT_THROWS(dataUriEncodePngImage(myInvalidPngImage), std::exception);
        TS_ASSERT_THROWS(dataUriEncodePngImage(std::vector<unsigned char>()), std::exception);
        TS_ASSERT_THROWS(dataUriDecodePngImage(""), std::exception);
        TS_ASSERT_THROWS(dataUriDecodePngImage("data:image/png;base64,NOT-A-PNG-IMAGE"), std::exception);
    }

    void testPropertyTreeEncodeDecode()
    {
        using namespace ta::EncodingUtils;

        // when-then
        TS_ASSERT_EQUALS(toStringArray(toTree(ta::StringArray())), ta::StringArray());
        // given
        const ta::StringArray myArray = boost::assign::list_of("one")("object.member")("!;, []<>\t$? три поросенка");
        // when-then
        TS_ASSERT_EQUALS(toStringArray(toTree(myArray)), myArray);

        // given
        ta::StringDict myDict;
        // when-then
        TS_ASSERT_EQUALS(toStringDict(toTree(myDict)), myDict);
        // given
        myDict["one"] = "first";
        myDict["два"] = "!;, []<>\t$? ниф-ниф";
        // when-then
        TS_ASSERT_EQUALS(toStringDict(toTree(myDict)), myDict);

        // given
        ta::StringDictArray myStringDictArray;
        // when-then
        TS_ASSERT_EQUALS(toStringDictArray(toTree(myStringDictArray)).size(), 0);
        // given
        myStringDictArray.push_back(boost::assign::map_list_of<string, string>("один", "1"));
        myStringDictArray.push_back(boost::assign::map_list_of<string, string>("two", "2")("three", "три"));
        // when
        const ta::StringDictArray myStringDictArrayActual = toStringDictArray(toTree(myStringDictArray));
        // then
        TS_ASSERT_EQUALS(myStringDictArrayActual.size(), 2);
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(0), myStringDictArray.at(0));
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(1), myStringDictArray.at(1));

        // given
        ta::StringDictDict myStringDictDict;
        // when-then
        TS_ASSERT_EQUALS(toStringDictDict(toTree(myStringDictDict)).size(), 0);
        // given
        const ta::StringDict info_nl =  boost::assign::map_list_of("capital", "Amsterdam")("population", "17 million");
        const ta::StringDict info_by =  boost::assign::map_list_of("capital", "Minsk")("population", "10 million");
        const ta::StringDict info_xx;
        myStringDictDict["NL"]  = info_nl;
        myStringDictDict["BY"]  = info_by;
        myStringDictDict["XX"]  = info_xx;
        // when
        const StringDictDict myStringDictDictActual = toStringDictDict(toTree(myStringDictDict));
        // then
        TS_ASSERT_EQUALS(myStringDictDictActual.size(), 3);
        TS_ASSERT_EQUALS(myStringDictDictActual, myStringDictDict);
    }

    void testJsonEncodeEscapesForwardSlashes()
    {
        using namespace ta::EncodingUtils;

        // given
        const ta::StringDict myDict = boost::assign::map_list_of<string, string>("urls", "http://keytalk.com\nhttp://keytalk2.com");
        // when
        const string myJson = toJson(myDict);
        // then
        TS_ASSERT_EQUALS(myJson, "{\"urls\":\"http:\\/\\/keytalk.com\\nhttp:\\/\\/keytalk2.com\"}\n");
        // when-then
        TS_ASSERT_EQUALS(jsonToStringDict(myJson), myDict);
    }

    void testJsonTreeEncodeDecode()
    {
        using namespace ta::EncodingUtils;

        // when-then
        TS_ASSERT_EQUALS(jsonToStringArray(toJson(ta::StringArray())), ta::StringArray());
        TS_ASSERT_EQUALS(jsonToStringArray(toJson(toTree(ta::StringArray()))), ta::StringArray());
        // given
        const ta::StringArray myArray = boost::assign::list_of("один")("two")("!;, []<>/\t$? три");
        // when-then
        TS_ASSERT_EQUALS(jsonToStringArray(toJson(myArray)), myArray);
        TS_ASSERT_EQUALS(jsonToStringArray(toJson(toTree(myArray))), myArray);

        // given
        ta::StringDict myDict;
        // when-then
        TS_ASSERT_EQUALS(jsonToStringDict(toJson(myDict)), myDict);
        TS_ASSERT_EQUALS(jsonToStringDict(toJson(toTree(myDict))), myDict);
        // given
        myDict["one"] = "first";
        myDict["два"] = "!;, []<>/\t$? наф-наф";
        // when-then
        TS_ASSERT_EQUALS(jsonToStringDict(toJson(myDict)), myDict);
        TS_ASSERT_EQUALS(jsonToStringDict(toJson(toTree(myDict))), myDict);

        // given
        ta::StringDictArray myStringDictArray;
        // when-then
        TS_ASSERT_EQUALS(jsonToStringDictArray(toJson(myStringDictArray)).size(), 0);
        TS_ASSERT_EQUALS(jsonToStringDictArray(toJson(toTree(myStringDictArray))).size(), 0);
        // given
        myStringDictArray.push_back(boost::assign::map_list_of<string, string>("один", "1"));
        myStringDictArray.push_back(boost::assign::map_list_of<string, string>("two", "2")("three", "три"));
        // when
        ta::StringDictArray myStringDictArrayActual = jsonToStringDictArray(toJson(myStringDictArray));
        // then
        TS_ASSERT_EQUALS(myStringDictArrayActual.size(), 2);
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(0), myStringDictArray.at(0));
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(1), myStringDictArray.at(1));
        // when
        myStringDictArrayActual = jsonToStringDictArray(toJson(toTree(myStringDictArray)));
        // then
        TS_ASSERT_EQUALS(myStringDictArrayActual.size(), 2);
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(0), myStringDictArray.at(0));
        TS_ASSERT_EQUALS(myStringDictArrayActual.at(1), myStringDictArray.at(1));


        // given
        ta::StringDictDict myStringDictDict;
        // when-then
        TS_ASSERT_EQUALS(jsonToStringDictDict(toJson(myStringDictDict)).size(), 0);
        TS_ASSERT_EQUALS(jsonToStringDictDict(toJson(toTree(myStringDictDict))).size(), 0);
        // given
        const ta::StringDict info_nl =  boost::assign::map_list_of("capital", "Amsterdam")("population", "17 million");
        const ta::StringDict info_by =  boost::assign::map_list_of("capital", "Minsk")("population", "10 million");
        const ta::StringDict info_xx;
        myStringDictDict["NL"]  = info_nl;
        myStringDictDict["BY"]  = info_by;
        myStringDictDict["XX"]  = info_xx;
        // when
        StringDictDict myStringDictDictActual = jsonToStringDictDict(toJson(myStringDictDict));
        // then
        TS_ASSERT_EQUALS(myStringDictDictActual.size(), 3);
        TS_ASSERT_EQUALS(myStringDictDictActual, myStringDictDict);
        // when
        myStringDictDictActual = jsonToStringDictDict(toJson(toTree(myStringDictDict)));
        // then
        TS_ASSERT_EQUALS(myStringDictDictActual.size(), 3);
        TS_ASSERT_EQUALS(myStringDictDictActual, myStringDictDict);
    }
};
