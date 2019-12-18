/*
 * uio_helper.c
 * Simple helper library to interface to linux UIO subsystem.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <stropts.h>

#include "list.h"
#include "uio.h"

#define MAX_NAME		(255)
#define MAX_UIO_MAPS		(5)
#define UIO_MAP_NONE		(0)
#define UIO_MAP_DONE		(1)
#define UIO_MAP_FAILED		(2)

#define UIO_SEARCH_PREFIX	"/sys/class/uio"
#define UIO_DEV_PREFIX		"/dev"

#define uio_err(fmt, ...) do {			\
		printf(fmt, ## __VA_ARGS__);	\
} while (0)

#define uio_dbg(d, fmt, ...) do {		\
	if (d->verbose) {			\
		printf(fmt, ## __VA_ARGS__);	\
	}					\
} while (0)

struct uio_mem_t {
	unsigned long int phy_addr;
	void  *map_addr;
	unsigned long int size;
	int status;
};

struct uio_dev_info_t {
	int fd;
	char path[PATH_MAX];
	char name[MAX_NAME];
	char id[MAX_NAME];
	char version[MAX_NAME];
	int instance;
	int num_maps;
	struct uio_mem_t mem[MAX_UIO_MAPS];
	int nvectors;
	int *efds;
	struct list_head_t node;
	bool verbose;
};

struct uio_internal_t {
	struct list_head_t uio_device_list;
	bool verbose;
};

/*
 * irq_eventfd interface.
 */
struct irq_eventfd_ioctl_arg {
	int dfd;	/* fd to the device which owns the interrupt */
	int efd;	/* eventfd to be attached */
	int eidx;	/* index to the event to be attached */
	int nevts;	/* number events supported/attached */
};

#define ATTACH_EVENT		(0x0600)
#define DETACH_EVENT		(0x0601)
#define GET_NUM_EVENTS		(0x0602)

static inline int uio_filterdir(const struct dirent *dir) {

	return (strcmp(dir->d_name, ".") && strcmp(dir->d_name, ".."));
}

static int uio_readline(const char *filepath, char *line_buf) {

	FILE *fp;
	int ret;

	fp = fopen(filepath, "r");
	if (!fp) {
		uio_err("[ERR ]: failed to open file(\"%s\"), %s\n",
				filepath, strerror(errno));
		return -1;
	}
	ret = fscanf(fp, "%s", line_buf);
	if (ret == EOF) {
		uio_err("[ERR ]: failed to read file(\"%s\"), %s\n",
				filepath, strerror(errno));
		return -1;
	}

	return 0;
}

static int uio_readlong(const char *filepath, unsigned long *buf) {

	FILE *fp;
	int ret;

	fp = fopen(filepath, "r");
	if (!fp) {
		uio_err("[ERR ]: failed to open file(\"%s\"), %s\n",
				filepath, strerror(errno));
		return -1;
	}
	ret = fscanf(fp, "0x%lx", buf);
	if (ret == EOF) {
		uio_err("[ERR ]: failed to read file(\"%s\"), %s\n",
				filepath, strerror(errno));
		return -1;
	}

	return 0;
}

int uio_init(libuio_handle_t *handle, bool verbose) {

	struct uio_internal_t *uio_priv;
	struct dirent **namelist;
	struct dirent **maplist;
	struct uio_dev_info_t *uio_dev;
	char path[PATH_MAX];
	int n, hits, ret;

	uio_priv = calloc(1, sizeof *uio_priv);
	INIT_LIST_HEAD(&uio_priv->uio_device_list);
	uio_priv->verbose = verbose;

	n = scandir(UIO_SEARCH_PREFIX, &namelist, uio_filterdir, alphasort);
	if ( n <= 0 ) {
		uio_err("[ERR ]: uio driver module not loaded\n");
		return -1;
	}

	while (n--) {
		/*
		 * Allocate device and populate details.
		 */
		uio_dev = calloc(1, sizeof *uio_dev);

		strcpy(uio_dev->id, namelist[n]->d_name);
		snprintf(uio_dev->path, PATH_MAX, UIO_DEV_PREFIX"/%s",
				namelist[n]->d_name);
		snprintf(path, PATH_MAX, UIO_SEARCH_PREFIX"/%s/name",
				namelist[n]->d_name);
		ret = uio_readline(path, uio_dev->name);
		if (ret != 0) {
			uio_err("[ERR ]: %s failed read name\n",
					namelist[n]->d_name);
			goto fail;
		}
		snprintf(path, PATH_MAX, UIO_SEARCH_PREFIX"/%s/version",
				namelist[n]->d_name);
		ret = uio_readline(path, uio_dev->version);
		if (ret != 0) {
			uio_err("[ERR ]: %s failed read verion\n",
					namelist[n]->d_name);
			goto fail;
		}
		snprintf(path, PATH_MAX, UIO_SEARCH_PREFIX"/%s/maps",
				uio_dev->id);
		hits = scandir(path, &maplist, uio_filterdir, alphasort);
		for (int j  = 0; j < hits; j++) {
			int map_index = 0;

			sscanf(maplist[j]->d_name, "map%d", &map_index);
			snprintf(path, PATH_MAX,
					UIO_SEARCH_PREFIX"/%s/maps/%s/addr",
					uio_dev->id,
					maplist[j]->d_name);
			ret = uio_readlong(path, &uio_dev->mem[map_index].phy_addr);
			snprintf(path, PATH_MAX,
					UIO_SEARCH_PREFIX"/%s/maps/%s/size",
					uio_dev->id,
					maplist[j]->d_name);
			ret = uio_readlong(path, &uio_dev->mem[map_index].size);
#if 0
			uio_dev->mem[map_index].size =
				(uio_dev->mem[map_index].size < getpagesize() ?
				getpagesize() : uio_dev->mem[map_index].size);
#endif
			uio_dev->mem[map_index].status = UIO_MAP_NONE;
			uio_dev->mem[map_index].map_addr = MAP_FAILED;
			free(maplist[j]);
		}
		uio_dev->num_maps = hits;
		uio_dev->verbose = uio_priv->verbose;
		list_add(&uio_dev->node, &uio_priv->uio_device_list);
		free(maplist);
		free(namelist[n]);
	}
	free(namelist);
	*handle = uio_priv;

	return 0;
fail:
	free(uio_dev);
	free(uio_priv);

	return -1;
}

libuio_dev_handle_t uio_device_open(libuio_handle_t handle, const char *name) {

	struct uio_internal_t *uio_priv = (struct uio_internal_t *)handle;
	struct uio_dev_info_t *uio_dev;
	int fd = -1;

	list_for_each_entry(uio_dev, &uio_priv->uio_device_list, node) {
		if (!strcmp(name, uio_dev->id)) {
			fd = open(uio_dev->path, O_RDWR);
			if (fd == -1) {
				uio_err("[ERR ]: failed to open file \"%s\""
						" error \"%s\"\n",
						uio_dev->path, strerror(errno));
			}
			uio_dev->fd = fd;
			break;
		}
	}

	if (fd == -1) {
		uio_err("[ERR ]: cannot find device \"%s\"\n", name);

		return NULL;
	}

	uio_dbg(uio_priv, "[INFO]: opened file \"%s\" with fd(%d)\n",
			uio_dev->path, fd);

	return (void *)uio_dev;
}

static int uio_device_map_single(struct uio_dev_info_t *uio_dev, int idx) {


	if (uio_dev->mem[idx].status == UIO_MAP_DONE) {

		return 0;
	}

	uio_dev->mem[idx].map_addr = mmap(NULL, getpagesize(),
			PROT_READ | PROT_WRITE,
			MAP_SHARED, uio_dev->fd,
			idx * getpagesize());
	if (uio_dev->mem[idx].map_addr == MAP_FAILED) {
		uio_err("[ERR ]: failed to map memory(%d) phy_addr(0x%lx)"\
				" size(0x%lx) error(%s)\n", idx,
				uio_dev->mem[idx].phy_addr,
				uio_dev->mem[idx].size, strerror(errno));
		return -1;
	}
	uio_dev->mem[idx].status = UIO_MAP_DONE;

	return 0;
}

static void uio_device_munmap_single(struct uio_dev_info_t *uio_dev, int idx) {

	if (uio_dev->mem[idx].status == UIO_MAP_NONE) {
		return;
	}
	munmap(uio_dev->mem[idx].map_addr, getpagesize() /*uio_dev->mem[idx].size*/);
	uio_dev->mem[idx].status = UIO_MAP_NONE;

	return;
}

int uio_device_map_all(libuio_dev_handle_t handle) {

	struct uio_dev_info_t *uio_dev = (struct uio_dev_info_t *)handle;

	for (int i = uio_dev->num_maps - 1; i >= 0; i--) {
		if (uio_device_map_single(uio_dev, i) != 0) {
			return -1;
		}
	}

	return 0;
}

void *uio_device_mapped_addr(libuio_dev_handle_t handle, int idx) {

	struct uio_dev_info_t *uio_dev = (struct uio_dev_info_t *)handle;


	if (uio_dev->mem[idx].status != UIO_MAP_DONE) {
		uio_err("[ERR ]: memory region(%d) not mapped\n", idx);

		return NULL;
	}

	return uio_dev->mem[idx].map_addr;
}

int uio_attach_event(libuio_dev_handle_t handle, int vector) {

	struct uio_dev_info_t *uio_dev = (struct uio_dev_info_t *)handle;
	int irq_eventfd = -1;
	struct irq_eventfd_ioctl_arg ioctl_arg = {0};
	int efd = -1;
	int ret;

	irq_eventfd = open("/dev/irq_eventfd", O_RDWR);
	if (irq_eventfd == -1) {
		uio_err("[ERR ]: failed to open \"/dev/irq_eventfd\", %s",
				strerror(errno));
		return -1;
	}
	ioctl_arg.dfd = uio_dev->fd;
	ret = ioctl(irq_eventfd, GET_NUM_EVENTS, (unsigned long)&ioctl_arg);
	if (ret < 0) {
		uio_err("[ERR ]: failed query number of events\n");
		goto fail;
	}
	uio_dbg(uio_dev, "[INFO]: device supports (%d) events\n",
			ioctl_arg.nevts);
	uio_dev->nvectors = ioctl_arg.nevts;
	if (!uio_dev->efds) {
		uio_dev->efds = (int *)calloc(uio_dev->nvectors,
				sizeof *uio_dev->efds);
	}
	if (vector > ioctl_arg.nevts) {
		uio_err("[ERR ]: overflow (%d > max(%d)\n", vector,
				ioctl_arg.nevts);
		ret = -1;
		goto fail;
	}
	efd = eventfd(0, EFD_SEMAPHORE);
	if (efd == -1) {
		uio_err("[ERR ]: failed to create eventfd, %s\n",
				strerror(errno));
	}
	uio_dbg(uio_dev, "[INFO]: created eventfd(%d)\n", efd);
	ioctl_arg.dfd = uio_dev->fd;
	ioctl_arg.efd = efd;
	ioctl_arg.eidx = vector;
	ret = ioctl(irq_eventfd, ATTACH_EVENT, (unsigned long)&ioctl_arg);
	if (ret < 0) {
		uio_err("[ERR ]: failed to attach eventfd(%d) to vector(%d)\n",
				efd, vector);
		goto fail;
	}
	uio_dev->efds[vector] = efd;
	close(irq_eventfd);

	return efd;
fail:
	if (efd) {
		close(efd);
	}

	if (irq_eventfd) {
		close(irq_eventfd);
	}

	return ret;
}

int uio_detach_event(libuio_dev_handle_t handle, int vector) {

	struct uio_dev_info_t *uio_dev = (struct uio_dev_info_t *)handle;
	int irq_eventfd = -1;
	struct irq_eventfd_ioctl_arg ioctl_arg = {0};
	int ret;

	irq_eventfd = open("/dev/irq_eventfd", O_RDWR);
	if (irq_eventfd == -1) {
		uio_err("[ERR ]: failed to open \"/dev/irq_eventfd\", %s",
				strerror(errno));
		return -1;
	}

	if (!uio_dev->efds || uio_dev->efds[vector] <= 0) {
		uio_err("[ERR ]: event not attached\n");

		goto fail;
	}

	ioctl_arg.dfd = uio_dev->fd;
	ioctl_arg.efd = uio_dev->efds[vector];
	ioctl_arg.eidx = vector;
	ret = ioctl(irq_eventfd, DETACH_EVENT, (unsigned long)&ioctl_arg);
	if (ret < 0) {
		uio_err("[ERR ]: failed to detach vector(%d)\n", vector);
		goto fail;
	}
	uio_dev->efds[vector] = -1;

	return 0;
fail:
	if (irq_eventfd) {
		close(irq_eventfd);
	}

	return -1;
}

void uio_device_close(libuio_dev_handle_t handle) {

	struct uio_dev_info_t *uio_dev = (struct uio_dev_info_t *)handle;

	for (int i = 0; i < uio_dev->nvectors; i++) {
		if(uio_detach_event(uio_dev, i) != 0) {
			uio_err("[ERR ]: failed to close vector(%d)\n", i);
		} else {
			uio_dbg(uio_dev, "[INFO]: closed vector(%d)\n", i);
		}
	}

	for (int i = 0; i < uio_dev->num_maps; i++) {
		if (uio_dev->mem[i].status == UIO_MAP_DONE) {
			uio_device_munmap_single(uio_dev, i);
		}
	}
	close(uio_dev->fd);
	uio_dev->fd = -1;
}

void uio_dump(libuio_handle_t handle) {

	struct uio_internal_t *uio_priv = (struct uio_internal_t *)handle;
	struct uio_dev_info_t *uio_dev;

	list_for_each_entry(uio_dev, &uio_priv->uio_device_list, node) {
		uio_dbg(uio_priv, "[INFO]: id(%s) name(%s) version(%s)\n",
				uio_dev->id, uio_dev->name, uio_dev->version);
		for (int i = 0; i < uio_dev->num_maps; i++) {
			uio_dbg(uio_priv,
					"        map[%d]: phy_addr(0x%lx) size(0x%lx)\n",
					i, uio_dev->mem[i].phy_addr,
					uio_dev->mem[i].size);
		}
		for (int i = 0; i < uio_dev->nvectors&& uio_dev->efds; i++) {
			uio_dbg(uio_priv,
					"        vector(%d) = efd(%d)\n",
					i, uio_dev->efds[i]);
		}

	}
}
