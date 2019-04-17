CXX = g++
CFLAGS = -Wall -std=c++11
INCLUDE = -Iinclude -I/usr/local/include -I/usr/include
LDFLAGS = -L/usr/local/lib -I/usr/lib
LDLIBS = -lcurl

LIB=lib/libtwilio.a
TEST_APP = bin/twilio_demo

all: $(LIB)

test: $(TEST_APP)

$(LIB): src/twilio.cc
	$(CXX) -c $(INCLUDE) $(CFLAGS) src/twilio.cc -o twilio.o
	ar rcs $@ twilio.o

$(TEST_APP): src/cpp_demo.cc $(LIB)
	$(CXX) $(INCLUDE) $(CFLAGS) $(LDFLAGS)  $< $(LIB) $(LDLIBS) -o $@

clean:
	rm -rf ./*.o $(TEST_APP) $(LIB)
