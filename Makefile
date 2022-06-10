CC = gcc
CFLAGS = -std=c++17 -pedantic -Wall -g
OBJECTS = cracker.o
LIBS = -lstdc++

all: cracker README.md

%.o: %.cc
	$(CC) $(CFLAGS) -c $<

cracker: $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBS) -o $@

clean: clean-doc
	rm -f *.o cracker

clean-doc:
	rm -rf README.md doc/xml

# Generate README from my source file
README.md: cracker.md .doxygen-installed
	cat warning-for-README.txt $< > $@
	cat cracker.md >> $@

cracker.md: .moxygen-installed doc/xml
	moxygen --output $@ doc/xml

doc/xml: cracker.cc Doxyfile .doxygen-installed
	doxygen

# Install doc extractor if it's not already installed
.moxygen-installed:
	which moxygen && touch $@ || npm install moxygen -g && touch $@

.doxygen-installed:
	(which doxygen && touch $@) || (echo -e "You must install doxygen first" && exit 1)