LDLIBS += -lpcap

all: csa

airodump_on: csa.cpp

clean:
	rm -f csa *.o