// sqlite3cpp.cpp
//
// The MIT License
//
// Copyright (c) 2012-2016 Andrei Korostelev
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "sqlite3cpp.h"
#include "boost/format.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <limits.h>

using std::string;

namespace sqlite3cpp
{

    null_type ignore;

    //
    // Private API
    //
    namespace
    {
        void createIfNotExist(const string& aDbPath, const string& aDbCreateSql)
        {
            struct stat sb = {0};
            if (stat(aDbPath.c_str(), &sb) != 0 || (sb.st_mode & (S_IFREG | S_IRUSR | S_IWUSR)) != (S_IFREG | S_IRUSR | S_IWUSR) )
            {
                sqlite3 *myDb = NULL;
                int rc = sqlite3_open(aDbPath.c_str(), &myDb);
                if (rc != SQLITE_OK)
                    throw database_error(str(boost::format("Failed to create Db %s. Sqlite3 error code: %d") % aDbPath % rc));
                if (sqlite3_exec(myDb, aDbCreateSql .c_str(), NULL,NULL, NULL)!=SQLITE_OK)
                {
                    string myErr = sqlite3_errmsg(myDb);
                    sqlite3_close(myDb);
                    remove(aDbPath.c_str());
                    throw database_error(str(boost::format("Failed to create Db at %s. %s") % aDbPath % myErr));
                }
                sqlite3_close(myDb);
            }
        }

    } // unnamed ns


    //
    // Database
    //

    database::database()
        : theDb(NULL)
    {}

    database::database(const string& aDbPath, const string& aDbCreateSql, const string& anExtensionPath)
        : theDb(NULL)
    {
        if (!aDbPath.empty())
            open(aDbPath, aDbCreateSql, anExtensionPath);
    }

    database::~database()
    {
        try  { close(); }
        catch (...) {}
    }

    void database::open(const string& aDbPath, const string& aDbCreateSql, const string& anExtensionPath)
    {
        close();
        createIfNotExist(aDbPath, aDbCreateSql);

        int rc = sqlite3_open(aDbPath.c_str(), &theDb);
        if (rc != SQLITE_OK)
            throw database_error(str(boost::format("Failed to open Db %s. Sqlite3 error code: %d") % aDbPath % rc));

        if (!anExtensionPath.empty())
            load_extension(anExtensionPath);

        theDbPath = aDbPath;
    }

    void database::close()
    {
        if (theDb)
        {
            if (sqlite3_close(theDb) != SQLITE_OK)
                throw database_error(*this, "Failed to close Db.");
            theDb = NULL;
            theDbPath = "";
        }
    }

    sqlite3_int64 database::last_insert_rowid() const
    {
        return sqlite3_last_insert_rowid(theDb);
    }

    void database::execute(const string& anSql)
    {
        if (sqlite3_exec(theDb, anSql.c_str(), NULL,NULL, NULL) != SQLITE_OK)
            throw database_error(*this, str(boost::format("Failed to execute '%s'.") % anSql));
    }

    int database::set_busy_timeout(int ms)
    {
        return sqlite3_busy_timeout(theDb, ms);
    }

    void database::enable_foreign_keys(bool aEnable)
    {
        execute(str(boost::format("PRAGMA foreign_keys = %s;") % (aEnable?"ON":"OFF")));
    }

    void database::load_extension(const string& anExtensionPath)
    {
        int ret = sqlite3_enable_load_extension(theDb, 1);
        if (ret != SQLITE_OK)
            throw database_error(str(boost::format("Failed to Db enable extensions. Error code: %d") % ret));

        char* errMsg = NULL;
        ret = sqlite3_load_extension(theDb, anExtensionPath.c_str(), 0, &errMsg);
        if (ret != SQLITE_OK)
        {
            if (errMsg)
            {
                const string myErrorMsg = errMsg;
                sqlite3_free(errMsg);
                throw database_error(str(boost::format("Failed to load Db extension from %s. %s") % anExtensionPath % myErrorMsg));
            }
            else
            {
                throw database_error(str(boost::format("Failed to load Db xtension from %s. Error code: %d") % anExtensionPath % ret));
            }
        }
    }


    //
    // Statement
    //

    statement::statement(database& db, const string& anSql)
        : theDb(db), theStmt(NULL), theCurBindIndx(1)
    {
        if (!anSql.empty())
            prepare(anSql);
    }

    statement::~statement()
    {
        try { finish(); }
        catch (...) {}
    }

    void statement::prepare(const string& anSql)
    {
        finish();
        if (sqlite3_prepare(theDb.theDb, anSql.c_str(), -1, &theStmt, 0) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to prepare query '%s'") % anSql));
        theSql = anSql;
    }

    void statement::finish()
    {
        if (theStmt)
        {
            if (sqlite3_finalize(theStmt) != SQLITE_OK)
                throw database_error(theDb, str(boost::format("Failed to finalise query '%s'") % theSql));
            theStmt = NULL;
            theSql = "";
            theCurBindIndx = 1;
        }
    }

    void statement::reset(ClearBindings aClearBindings)
    {
        if (sqlite3_reset(theStmt) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to reset query '%s'") % theSql));
        if (aClearBindings == clearBindingsOn)
        {
            if (sqlite3_clear_bindings(theStmt) != SQLITE_OK)
                throw database_error(theDb, str(boost::format("Failed to clear bindings for query '%s'") % theSql));
            theCurBindIndx = 1;
        }
    }

    int statement::step()
    {
        return sqlite3_step(theStmt);
    }

    void statement::bind(int idx, int value)
    {
        bind(idx, static_cast<long int>(value));
    }

    void statement::bind(int idx, long int value)
    {
        if (sqlite3_bind_int(theStmt, idx, value) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind integer value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, unsigned int value)
    {
        bind(idx, static_cast<unsigned long>(value));
    }

    void statement::bind(int idx, unsigned long value)
    {
        if (value > INT_MAX)
            throw database_error(str(boost::format("Failed to bind unsigned integer value %1% because it cannot be promoted to an integer") % value));
        if (sqlite3_bind_int(theStmt, idx, value) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind unsigned integer value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, double value)
    {
        if (sqlite3_bind_double(theStmt, idx, value) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind double value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, sqlite3_int64 value)
    {
        if (sqlite3_bind_int64(theStmt, idx, value) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind int64 value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, const string& value)
    {
        if (sqlite3_bind_text(theStmt, idx, value.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind string value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, void const* value, int n)
    {
        if (sqlite3_bind_blob(theStmt, idx, value, n, SQLITE_TRANSIENT) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind BLOB value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx)
    {
        if (sqlite3_bind_null(theStmt, idx) != SQLITE_OK)
            throw database_error(theDb, str(boost::format("Failed to bind NULL value at position %d for query '%s'") % idx % theSql));
    }

    void statement::bind(int idx, null_type)
    {
        bind(idx);
    }

    void statement::bind(const string& name, int value)
    {
        bind(name, static_cast<long int>(value));
    }

    void statement::bind(const string& name, long int value)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value);
    }

    void statement::bind(const string& name, unsigned int value)
    {
        bind(name, static_cast<unsigned long>(value));
    }

    void statement::bind(const string& name, unsigned long value)
    {
        if (value > INT_MAX)
            throw database_error(str(boost::format("Failed to bind unsigned integer value %1% because it cannot be promoted to an integer") % value));
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value);
    }

    void statement::bind(const string& name, double value)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value);
    }

    void statement::bind(const string& name, sqlite3_int64 value)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value);
    }

    void statement::bind(const string& name, const string& value)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value);
    }

    void statement::bind(const string& name, void const* value, int n)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx, value, n);
    }

    void statement::bind(const string& name)
    {
        int idx = sqlite3_bind_parameter_index(theStmt, name.c_str());
        if (idx <= 0)
            throw database_error(theDb, str(boost::format("Invalid bind placeholder %s for query '%s'") % name % theSql));
        return bind(idx);
    }

    void statement::bind(const string& name, null_type)
    {
        return bind(name);
    }


    //
    // Command
    //


    command::command(database& db, const string& anSql)
        : statement(db, anSql)
    {}

    void command::execute()
    {
        if (step() != SQLITE_DONE)
            throw database_error(theDb, str(boost::format("Failed to execute command '%s'") % theSql));
    }


    //
    // Query
    //

    query::row::row(sqlite3_stmt* stmt, const string& anSql)
        : theStmt(stmt), theSql(anSql), theCurGetIndex(1)
    {
        if (!theStmt)
            throw database_error("Statement is NULL");
    }


    int query::row::get(int idx, int) const
    {
        if (idx > sqlite3_data_count(theStmt))
            throw database_error(str(boost::format("Column %d is out-of-bounds for query '%s'") % idx % theSql));

        return sqlite3_column_int(theStmt, idx-1);
    }

    long int query::row::get(int idx, long int) const
    {
        return static_cast<long int>(get<int>(idx));
    }

    unsigned int query::row::get(int idx, unsigned int) const
    {
        return static_cast<unsigned int>(get<int>(idx));
    }

    unsigned long query::row::get(int idx, unsigned long int) const
    {
        return static_cast<unsigned long>(get<int>(idx));
    }

    double query::row::get(int idx, double) const
    {
        if (idx > sqlite3_data_count(theStmt))
            throw database_error(str(boost::format("Column %d is out-of-bounds for query '%s'") % idx % theSql));

        return sqlite3_column_double(theStmt, idx-1);
    }

    sqlite3_int64 query::row::get(int idx, sqlite3_int64) const
    {
        if (idx > sqlite3_data_count(theStmt))
            throw database_error(str(boost::format("Column %d is out-of-bounds for query '%s'") % idx % theSql));

        return sqlite3_column_int64(theStmt, idx-1);
    }

    char const* query::row::get(int idx, char const*) const
    {
        if (idx > sqlite3_data_count(theStmt))
            throw database_error(str(boost::format("Column %d is out-of-bounds for query '%s'") % idx % theSql));

        return reinterpret_cast<char const*>(sqlite3_column_text(theStmt, idx-1));
    }

    string query::row::get(int idx, string) const
    {
        return get(idx, (char const*)NULL);
    }

    void const* query::row::get(int idx, void const*) const
    {
        if (idx > sqlite3_data_count(theStmt))
            throw database_error(str(boost::format("Column %d is out-of-bounds for query '%s'") % idx % theSql));

        return sqlite3_column_blob(theStmt, idx-1);
    }

    null_type query::row::get(int idx, null_type) const
    {
        return ignore;
    }

    query::query_iterator::query_iterator()
        : theQuery(NULL)
    {
        theRc = SQLITE_DONE;
    }

    query::query_iterator::query_iterator(query* aQuery)
        : theQuery(aQuery)
    {
        if (!theQuery)
            throw database_error("NULL query passed");
        theRc = theQuery->step();
        if (theRc != SQLITE_ROW && theRc != SQLITE_DONE)
            throw database_error(theQuery->theDb, str(boost::format("Failed to step through the query '%s'") % theQuery->theSql));
    }

    void query::query_iterator::increment()
    {
        if (!theQuery)
            throw database_error("Cannot increment NULL query");
        theRc = theQuery->step();
        if (theRc != SQLITE_ROW && theRc != SQLITE_DONE)
            throw database_error(theQuery->theDb, str(boost::format("Failed to step through the query '%s'") % theQuery->theSql));
    }

    bool query::query_iterator::equal(query_iterator const& other) const
    {
        return theRc == other.theRc;
    }

    query::row query::query_iterator::dereference() const
    {
        if (!theQuery)
            throw database_error("Cannot dereference NULL query");
        return row(theQuery->theStmt, theQuery->theSql);
    }

    query::query(database& db, const string& anSql)
        : statement(db, anSql)
    {}

    int query::column_count() const
    {
        return sqlite3_column_count(theStmt);
    }

    query::iterator query::begin()
    {
        reset();
        return query_iterator(this);
    }

    query::iterator query::end()
    {
        return query_iterator();
    }


    //
    // Transaction
    //

    transaction::transaction(database& db, bool fcommit, bool freserve) : theDb(&db), theCcommit(fcommit)
    {
        theDb->execute(freserve ? "BEGIN IMMEDIATE" : "BEGIN");
    }

    transaction::~transaction()
    {
        if (theDb)
        {
            try { theDb->execute(theCcommit ? "COMMIT" : "ROLLBACK"); }
            catch (...) {}
        }
    }

    void transaction::commit()
    {
        database* db = theDb;
        theDb = NULL;
        db->execute("COMMIT");
    }

    void transaction::rollback()
    {
        database* db = theDb;
        theDb = NULL;
        db->execute("ROLLBACK");
    }


    database_error::database_error(const string& aMsg)
        : std::runtime_error(aMsg)
    {}

    database_error::database_error(database& db, const string& aMsg)
        : std::runtime_error(str(boost::format("%s. %s. Db at %s") % aMsg % sqlite3_errmsg(db.theDb) % db.theDbPath))
    {}


}
