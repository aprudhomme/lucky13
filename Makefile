all: l13

l13: lucky13.cpp sslclient.cpp
	g++ -o lucky13 lucky13.cpp
	g++ -o sslclient sslclient.cpp -lssl -lcrypto

clean:
	rm lucky13
