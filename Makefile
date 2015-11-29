all: l13

l13: lucky13.cpp
	g++ -o lucky13 -lpcap lucky13.cpp

clean:
	rm lucky13
