TARGETS = crypto

ifeq (, $(shell which g++-5))
	CXX = g++
else
	CXX = g++-5
endif

CXXFLAGS = -std=c++14 -O3 -fPIC
LFLAGS = -lcryptopp -pthread

CLASSES := $(shell ls src/*.h)
OBJS := $(CLASSES:src/%.h=%.o)

all: ${TARGETS}

${TARGETS}: % : %.o ${OBJS}
	${CXX} $^ ${LFLAGS} -o $@

${TARGETS:%=%.o} : %.o : src/%.cpp
	${CXX} $< ${CXXFLAGS} -c -o $@

${OBJS}: %.o : src/%.cpp src/%.h
	${CXX} $< ${CXXFLAGS} -c -o $@

clean:
	rm -f ${OBJS} ${TARGETS:%=%.o} ${TARGETS}

