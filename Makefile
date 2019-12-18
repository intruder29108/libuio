OBJS := uio_helper.o main.o
EXEC := uio_app
LIBS := -lpthread

all : $(OBJS)
	 $(CC) $(OBJS) $(LIBS) -o $(EXEC)

%.o : %.c
	$(CC) -g $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o $(EXEC)
