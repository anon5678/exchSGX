SSLDIR := /home/ib327/local/openssl
INCDIR := $(SSLDIR)/include
LIBDIR := $(SSLDIR)/lib

merkpath: merkpath.o base64.o
	g++ -o merkpath merkpath.o base64.o -L "$(LIBDIR)" -l:libcrypto.a

merkpath.o: merkpath.cpp
	g++ -c merkpath.cpp -I "$(INCDIR)"

base64.o: base64.cpp
	g++ -c base64.cpp

clean:
	rm -f merkpath merkpath.o base64.o
