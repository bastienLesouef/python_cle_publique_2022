CPPFLAGS += -I /usr/include/python3.9
LIBS=-lpython3.9

COMPOSANT = composant_cle

LIB_ECC = micro-ecc/uECC
LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o ${LIB_ECC}.o

include ../gcc.mk
include ../pybind11.mk


all: $(LIBSO)
clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@
