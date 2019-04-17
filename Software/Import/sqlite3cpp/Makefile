all release debug:
	g++ -c sqlite3cpp.cpp -Wall -I../$(BOOST_INCLUDE_DIR)
	mkdir -p lib
	ar rcs lib/libsqlite3cpp.a *.o

clean:
	rm -f *.o
	rm -rf ./lib

# @todo support other distros
deps:
	apt-get install libboost-dev libsqlite3-dev

install:

buildtestinsert:
	rm -f ./testinsert ./test.db
	g++ testinsert.cpp -Wall -I./ -I../$(BOOST_INCLUDE_DIR) lib/libsqlite3cpp.a -lsqlite3 -o testinsert

buildtestselect:
	rm -f ./testselect ./test.db
	g++ testselect.cpp -Wall -I./ -I../$(BOOST_INCLUDE_DIR) lib/libsqlite3cpp.a -lsqlite3 -o testselect

test: buildtestinsert buildtestselect
	./testinsert
	./testselect
