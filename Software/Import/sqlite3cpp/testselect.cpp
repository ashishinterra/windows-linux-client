#include "sqlite3cpp.h"

#include "boost/format.hpp"
#include "boost/assign/list_of.hpp"
#include "boost/foreach.hpp"
#include <string>
#include <map>
#include <iostream>
#include <stdexcept>
#include <cstdio>

struct ContactInfo
{
    ContactInfo();
    ContactInfo(const std::string& aName, const std::string aPhone): name(aName), phone(aPhone) {}
    std::string name;
    std::string phone;
};

typedef std::map<int, ContactInfo> Contacts;
static const Contacts theContacts = boost::assign::map_list_of(1, ContactInfo("Andrei", "06101"))
                                    (2, ContactInfo("Veronica", "06102"))
                                    (3, ContactInfo("Roma", "06103"));

static const std::string getSqlCreate()
{
    std::string mySql =
        "BEGIN TRANSACTION;\n"
        "CREATE TABLE Contacts (\n"
        "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "name char (128) NOT NULL,\n"
        "phone char(67) NULL\n"
        ");\n";
    BOOST_FOREACH(Contacts::value_type contact, theContacts)
    {
        mySql += str(boost::format("INSERT INTO \"Contacts\" VALUES(%1%,'%2%','%3%');\n") % contact.first % contact.second.name % contact.second.phone);
    }
    mySql += "COMMIT;\n";

    return mySql;
}

static ContactInfo getContact(const int id)
{
    Contacts::const_iterator myIt = theContacts.find(id);
    if (myIt != theContacts.end())
    {
        return myIt->second;
    }
    throw std::invalid_argument(str(boost::format("Contact with id %d does not exist") % id));
}


#define TEST_ASSERT_EQUALS(actual, expected) if (actual != expected) { std::cerr << "TEST EQUALITY ASSERTION FAILED at " << __FILE__  << ":" <<__LINE__ << "\nActual: " << actual << "\nExpected: " << expected << "\n"; throw std::runtime_error("TEST FAILED");}

using std::cout;
using std::endl;

int main(int argc, char* argv[])
{
    try
    {
        ::remove("test.db");
        sqlite3cpp::database db("test.db", getSqlCreate());
        sqlite3cpp::query qry(db, "SELECT id, name, phone FROM contacts");

        TEST_ASSERT_EQUALS(qry.column_count(), 3);

        // Just print out data
        for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
        {
            for (int j = 1; j <= qry.column_count(); ++j)
            {
                cout << i->get<char const*>(j) << "\t";
            }

            cout << endl;
        }
        cout << endl;

        int idx = 1;
        for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
        {
            int id;
            std::string name, phone;

            (*i) >> id >> name >> phone;
            TEST_ASSERT_EQUALS(id, idx);
            TEST_ASSERT_EQUALS(name, getContact(id).name);
            TEST_ASSERT_EQUALS(phone, getContact(id).phone);

            cout << id << "\t" << name << "\t" << phone << endl;
            ++idx;
        }

        cout << "TEST OK" << endl;
        return 0;
    }
    catch (std::exception& ex) {
        cout << ex.what() << endl;
        return 1;
    }
}
