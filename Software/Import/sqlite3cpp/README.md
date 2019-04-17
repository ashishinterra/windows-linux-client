sqlite3cpp
==========
[![Build Status](https://travis-ci.org/kindkaktus/sqlite3cpp.svg)](https://travis-ci.org/kindkaktus/sqlite3cpp)

SQLite3cpp is a C++ wrapper to SQLite3 C API.

The library was initially a clone from SQlite3pp from https://code.google.com/p/sqlite3pp/. The following adjustments were made to the original library:
- added a possibility to load sqlite extensions
- allowed for creation of the Db from SQL schema if it does not exist
- added support for foreign keys appeared in sqlite 3.6.19
- added support for OpenBSD
- improved C++ interface (consistent usage of exceptions, non-throwing d'tors etc)
- dropped support for some rarely-used functionality like attach/detach/aggregate/function etc


INSTALLATION
--------------
Prerequisites:
    - libsqlite C library with developent headers shall be available
    - boost

To build static library libsqlite3cpp.a:<br>
    <code>make</code>

Optionally run tests by invoking:<br>
    <code>make test</code>




