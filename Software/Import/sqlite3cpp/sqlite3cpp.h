// sqlite3cpp.h
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

#ifndef SQLITE3CPP_H
#define SQLITE3CPP_H

#include <string>
#include <stdexcept>
#include <sqlite3.h>
#include <boost/cstdint.hpp>
#include <boost/utility.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/iterator/iterator_facade.hpp>

namespace sqlite3cpp
{
    class null_type {};
    extern null_type ignore;

    enum ClearBindings
    {
        clearBindingsOff, clearBindingsOn
    };

    class database : boost::noncopyable
    {
        friend class statement;
        friend class database_error;

    public:
        database();
        database(const std::string& aDbPath, const std::string& aDbCreateSql, const std::string& anExtensionPath = "");
        ~database();

        void open(const std::string& aDbPath, const std::string& aDbCreateSql, const std::string& anExtensionPath = "");
        void close();

        sqlite3_int64 last_insert_rowid() const;

        void execute(const std::string& anSql);
        int set_busy_timeout(int ms);
        // Foreign kets are effectively supported only from sqlite 3.6.19
        void enable_foreign_keys(bool aEnable = true);

    private:
        void load_extension(const std::string& anExtensionPath);

    private:
        std::string theDbPath;
        sqlite3* theDb;
    };

    struct database_error : std::runtime_error
    {
        explicit database_error(const std::string& aMsg);
        database_error(database& db, const std::string& aMsg);
    };

    class statement : boost::noncopyable
    {
    public:
        void prepare(const std::string& anSql);
        void finish();
        void reset(ClearBindings aClearBindings = clearBindingsOff);

        // positional bind (index is 1-based)
        void bind(int idx, int value);
        void bind(int idx, long int value);
        void bind(int idx, unsigned int value);
        void bind(int idx, unsigned long value);
        void bind(int idx, double value);
        void bind(int idx, sqlite3_int64 value);
        void bind(int idx, const std::string& value);
        void bind(int idx, void const* value, int n);
        void bind(int idx);
        void bind(int idx, null_type);

        // name bind
        void bind(const std::string& name, int value);
        void bind(const std::string& name, long int value);
        void bind(const std::string& name, unsigned int value);
        void bind(const std::string& name, unsigned long value);
        void bind(const std::string& name, double value);
        void bind(const std::string& name, sqlite3_int64 value);
        void bind(const std::string& name, const std::string& value);
        void bind(const std::string& name, void const* value, int n);
        void bind(const std::string& name);
        void bind(const std::string& name, null_type);

        // stream-like bind using << operator
        template <class T>  statement& operator << (T value)
        {
            bind(theCurBindIndx, value);
            ++theCurBindIndx;
            return *this;
        }


    protected:
        statement(database& db, const std::string& anSql);
        ~statement();

        int step();
    protected:
        database& theDb;
        std::string theSql;
        sqlite3_stmt* theStmt;
    private:
        int theCurBindIndx;
    };


    class command : public statement
    {
    public:
        command(database& db, const std::string& anSql);
        void execute();
    };


    class query : public statement
    {
    public:
        class row
        {
        public:
            row(sqlite3_stmt* stmt, const std::string& anSql);

            template <class T> T get(int idx) const  // index is 1-based
            {
                return get(idx, T());
            }

            template <class T> row& operator >> (T& value)
            {
                value = get(theCurGetIndex, T());
                ++theCurGetIndex;
                return *this;
            }

        private:
            int get(int idx, int) const;
            long int get(int idx, long int) const;
            unsigned int get(int idx, unsigned int) const;
            unsigned long get(int idx, unsigned long) const;
            double get(int idx, double) const;
            sqlite3_int64 get(int idx, sqlite3_int64) const;
            char const* get(int idx, char const*) const;
            std::string get(int idx, std::string) const;
            void const* get(int idx, void const*) const;
            null_type get(int idx, null_type) const;

        private:
            sqlite3_stmt* theStmt;
            std::string theSql;
            int theCurGetIndex;
        }; // row

        class query_iterator : public boost::iterator_facade<query_iterator, row, boost::single_pass_traversal_tag, row>
        {
        public:
            query_iterator();
            explicit query_iterator(query* aQuery);

        private:
            friend class boost::iterator_core_access;

            void increment();
            bool equal(query_iterator const& other) const;

            row dereference() const;

            query* theQuery;
            int theRc;
        }; // query_iterator

        explicit query(database& db, const std::string& anSql);

        int column_count() const;

        typedef query_iterator iterator;
        iterator begin();
        iterator end();
    };

    class transaction : boost::noncopyable
    {
    public:
        explicit transaction(database& db, bool fcommit = false, bool freserve = false);
        ~transaction();

        void commit();
        void rollback();

    private:
        database* theDb;
        bool theCcommit;
    };

} // namespace sqlite3cpp

#endif
