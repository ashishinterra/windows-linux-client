#include "sqlite3cpp.h"
#include "boost/format.hpp"
#include <iostream>
#include <cstdio>

static const std::string SqlCreate =
    "BEGIN TRANSACTION;\n"
    "CREATE TABLE Contacts (\n"
    "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "name char (128) NOT NULL,\n"
    "phone char(67) NULL\n"
    ");\n"
    "COMMIT;\n";

#define TEST_ASSERT(condition) if (!(condition)) { std::cerr << "TEST ASSERTION FAILED at " << __FILE__  << ":" <<__LINE__ << "\n" << #condition << "\n"; throw std::runtime_error("TEST FAILED");}
#define TEST_ASSERT_EQUALS(actual, expected) if (actual != expected) { std::cerr << "TEST EQUALITY ASSERTION FAILED at " << __FILE__  << ":" <<__LINE__ << "\nActual: " << actual << "\nExpected: " << expected << "\n"; throw std::runtime_error("TEST FAILED");}

using std::cout;
using std::endl;

int main(int argc, char* argv[])
{
    try
    {
        ::remove("test.db");
        sqlite3cpp::database db("test.db", SqlCreate);

        {
            db.execute("INSERT INTO contacts (name, phone) VALUES ('name_1', '0001')");

            // verify
            sqlite3cpp::query qry(db, "SELECT name, phone FROM contacts");
            int rec_count = 0;
            for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
            {
                std::string name, phone;

                (*i) >> name >> phone;
                TEST_ASSERT_EQUALS(name, "name_1");
                TEST_ASSERT_EQUALS(phone, "0001");

                ++rec_count;
            }
            TEST_ASSERT_EQUALS(rec_count, 1);
        }

        // create transaction but do not commit it
        {
            sqlite3cpp::transaction xct(db);
            sqlite3cpp::command cmd(db, "INSERT INTO contacts (name, phone) VALUES (?, ?)");

            cmd.bind(1, "BBBB");
            cmd.bind(2, "1234");
            cmd.execute();
        }

        // verify: no changes expected
        {
            sqlite3cpp::query qry(db, "SELECT name, phone FROM contacts");
            int rec_count = 0;
            for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
            {
                std::string name, phone;

                (*i) >> name >> phone;
                TEST_ASSERT_EQUALS(name, "name_1");
                TEST_ASSERT_EQUALS(phone, "0001");

                ++rec_count;
            }
            TEST_ASSERT_EQUALS(rec_count, 1);
        }

        // create transaction and commit it afterwards
        {
            sqlite3cpp::transaction xct(db);

            sqlite3cpp::command cmd(db, "INSERT INTO contacts (name, phone) VALUES (?, ?)");

            cmd.bind(1, "name_2");
            cmd.bind(2, "0002");
            cmd.execute();

            cmd.reset();
            cmd << "name_3" << "0003";
            cmd.execute();

            xct.commit();
        }

        // verify: changes should be committed at this time
        {
            sqlite3cpp::query qry(db, "SELECT name, phone FROM contacts");
            int rec_count = 0;
            for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
            {
                std::string name, phone;

                (*i) >> name >> phone;

                ++rec_count;
                TEST_ASSERT_EQUALS(name, str(boost::format("name_%d") % rec_count));
                TEST_ASSERT_EQUALS(phone, str(boost::format("000%d") % rec_count));
            }
            TEST_ASSERT_EQUALS(rec_count, 3);
        }

        // create transaction which will automatically commit on exit
        {
            const bool myCommitOnExit = true;
            sqlite3cpp::transaction xct(db, myCommitOnExit);

            sqlite3cpp::command cmd(db, "INSERT INTO contacts (name, phone) VALUES (:name, :phone)");

            cmd.bind(":name", "name_4");
            cmd.bind(":phone", "0004");
            cmd.execute();
        }

        // verify: changes should be committed even without explicit commit()
        {
            sqlite3cpp::query qry(db, "SELECT name, phone FROM contacts");
            int rec_count = 0;
            for (sqlite3cpp::query::iterator i = qry.begin(); i != qry.end(); ++i)
            {
                std::string name, phone;

                (*i) >> name >> phone;

                ++rec_count;
                TEST_ASSERT_EQUALS(name, str(boost::format("name_%d") % rec_count));
                TEST_ASSERT_EQUALS(phone, str(boost::format("000%d") % rec_count));
            }
            TEST_ASSERT_EQUALS(rec_count, 4);
        }


        cout << "TEST OK" << endl;
        return 0;
    }
    catch (std::exception& ex) {
        cout << ex.what() << endl;
        return 1;
    }

}
