/*
 * main.c
 * Simple program to illustra use of libuio.
 *
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <limits.h>

#include "uio.h"

static void print_help_command(void) {

	printf("Available commands:\n"\
               "    help\n"\
	       "    dump\n"\
	       "    open <uioXX>\n"\
	       "    close\n"\
	       "    map\n"\
	       "    read 0x<idx> 0x<offset> 0x<nbytes>\n"\
	       "    getid\n"\
	       "    write 0x<idx> 0x<offset> 0x<32bit data>\n"\
	       "    notify <peerid> <vector>\n"\
	       "    attach <vector>\n"\
	       "    detach <vector>\n"\
	       "    poll <efd>\n"\
	       "    exit\n");
}

struct thread_info_t {
	pthread_t tid;
	int efd;
	char tname[NAME_MAX];
};

static void *eventfd_thread(void *arg) {

	struct thread_info_t *tinfo = (struct thread_info_t *)arg;
	unsigned long value = 0;
	ssize_t ret;

	printf("[%s-%lu]: created\n", tinfo->tname, tinfo->tid);

	ret = read(tinfo->efd, &value, sizeof(value));
	if (ret == -1) {
		printf("[%s-%lu]: read failed error(%s)\n",
				tinfo->tname, tinfo->tid,
				strerror(errno));
	} else {
		printf("[%s-%lu]: read value(%lu)\n", tinfo->tname,
				tinfo->tid, value);
	}

	pthread_exit(NULL);
}

static int process_command(libuio_handle_t handle, char *buf) {

	char *token;
	char str_arg1[NAME_MAX];
	uint32_t int_arg1, int_arg2, int_arg3;
	static libuio_dev_handle_t dev_handle = NULL;
	int efd;

	while ((token = strsep(&buf, "\n\r"))) {

		if (!strcmp(token, "help")) {
			print_help_command();
		}
		else if (sscanf(token, "open %s", str_arg1) == 1) {
			dev_handle = uio_device_open(handle, str_arg1);
			if (!dev_handle) {
				printf("[ERR ]: open failed\n");
				break;
			}
			printf("[INFO]: open success, handle(%p)\n",
					dev_handle);
		}
		else if (!strcmp(token, "close")) {
			if (dev_handle) {
				uio_device_close(dev_handle);
			}
			printf("[INFO]: closed device\n");
			dev_handle = NULL;
		}
		else if(!strcmp(token, "map")) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			if (uio_device_map_all(dev_handle) == 0) {
				printf("[INFO]: map success\n");
			} else {
				printf("[ERR ]: map failed\n");
			}
		}
		else if(sscanf(token, "read 0x%x 0x%x 0x%x", &int_arg1,
					&int_arg2, &int_arg3) == 3) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			void *addr = uio_device_mapped_addr(dev_handle,
					int_arg1);
			if (!addr) {
				printf("[ERR ]: map the device first\n");
				break;
			}

			for (int i = 0; i < int_arg3; i++) {
				if ( i && (i % 16 == 0) ) {
					printf("\n");
				}
				printf("0x%02x ", ((uint8_t *)addr)[int_arg2 + i]);
			}
			printf("\n");
		}
		else if(!strcmp(token, "getid")) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			void *addr = uio_device_mapped_addr(dev_handle, 0);
			if (!addr) {
				printf("[ERR ]: map the device first\n");
				break;
			}
			printf("[INFO]: id=0x%x\n", ((uint32_t *)addr)[2]);
		}
		else if(sscanf(token, "write 0x%x 0x%x 0x%x", &int_arg1, &int_arg2,
					&int_arg3) == 3) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			void *addr = uio_device_mapped_addr(dev_handle,
					int_arg1);
			if (!addr) {
				printf("[ERR ]: map the device first\n");
				break;
			}
			((uint32_t *)addr)[int_arg2/sizeof(uint32_t)] = int_arg3;
		}
		else if(sscanf(token, "notify %d %d", &int_arg1,
					&int_arg2) == 2) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			void *addr = uio_device_mapped_addr(dev_handle, 0);
			if (!addr) {
				printf("[ERR ]: map the device first\n");
				break;
			}
			((uint32_t *)addr)[3] = (int_arg1 << 16) | int_arg2;

		}
		else if(sscanf(token, "attach %d", &int_arg1) == 1) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			efd = uio_attach_event(dev_handle, int_arg1);
			if (efd == -1) {
				printf("[ERR ]: failed to attach to vector(%d)\n",
						int_arg1);
				break;
			}
			printf("[INFO]: attached efd(%d) to vector(%d)\n",
					efd, int_arg1);

		}
		else if(sscanf(token, "detach %d", &int_arg1) == 1) {
			if (!dev_handle) {
				printf("[ERR ]: open a device first\n");
				break;
			}
			efd = uio_detach_event(dev_handle, int_arg1);
			if (efd == -1) {
				printf("[ERR ]: failed to detach to vector(%d)\n",
						int_arg1);
				break;
			}
			printf("[INFO]: detached vector(%d)\n", int_arg1);

		}
		else if(sscanf(token, "poll %d", &int_arg1) == 1) {
			struct thread_info_t *tinfo = calloc(1, sizeof(*tinfo));
			int ret;

			if (!tinfo) {
				printf("[ERR ]: failed to alloc thred info\n");
				break;
			}
			tinfo->efd = int_arg1;
			snprintf(tinfo->tname, NAME_MAX, "efd-%d", int_arg1);
			ret = pthread_create(&tinfo->tid, NULL,
					eventfd_thread, tinfo);
			if (ret != 0) {
				printf("[ERR ]: failed to created thread, %s",
						strerror(errno));
			}
		}
		else if(!strcmp(token, "dump")) {
			uio_dump(handle);
		}
		else if(!strcmp(token, "exit")) {
			return -1;
		}
		else if(strlen(token)){
			printf("[ERR ]: invalid command, see \"help\"\n");
		}
		break;
	}
	printf("cmd>");
	fflush(stdout);

	return 0;
}

static int poll_events(libuio_handle_t handle) {

	int ret;
	fd_set fds;
	int maxfd = 1;
	ssize_t rd_size;
	char line_buf[LINE_MAX];

	while (1) {
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		maxfd = 1;
		ret = select(maxfd, &fds, NULL, NULL, NULL);

		if (ret == -1) {
			printf("[ERR ]: select error(%s)\n", strerror(errno));
			break;
		}
		if (ret == 0) {
			continue;
		}

		if (FD_ISSET(0, &fds)) {
			rd_size = read(0, line_buf, LINE_MAX);
			if (rd_size == -1) {
				continue;
			}
			if (process_command(handle, line_buf) != 0) {
				ret = -1;
				break;
			}
		}
	}

	return 0;
}

int main(int argc, char *argv[]) {

	libuio_handle_t lib_hdl;
	uio_init(&lib_hdl, true);
	printf("[INFO]: uiolib_handle(%p)\n", lib_hdl);
	printf("cmd>");
	fflush(stdout);
	poll_events(lib_hdl);

	return 0;
}
