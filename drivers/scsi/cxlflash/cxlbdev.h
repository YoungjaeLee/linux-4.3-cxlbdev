#ifndef _CXLFLASH_CXLBDEV_H
#define _CXLFLASH_CXLBDEV_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <misc/cxl.h>
#include <linux/blk-mq.h>

#include "sislite.h"

#define MAX_CAPI_CARD	(4)

#define CXLBDEV_MAX_CMDS	(64)
#define CXLBDEV_MAX_SEGMENTS	(16)

#define CXLBDEV_NUM_RRQ_ENTRY	(CXLBDEV_MAX_CMDS * CXLBDEV_MAX_SEGMENTS)

#define CXLBDEV_NUM_CMDS	(2 * CXLBDEV_MAX_CMDS)

#define MAX_HW_QUEUES	(512)
#define MAX_CXLBDEV_NUMS	(256)

#define CORES_PER_NODE	(40)

extern int cxlbdev_submit_queues;

#define get_cxlbdev_afu(cxlbdev_cfg, idx)	\
	cxlbdev_cfg->afu_per_cpu[idx]

struct cxlbdev_cfg {
	struct cxlbdev_afu *afu_per_cpu[MAX_HW_QUEUES];
	struct cxl_context *ctx_per_cpu[MAX_HW_QUEUES];
	struct sisl_rht_entry *rhte_per_cpu[MAX_HW_QUEUES];

	struct list_head cxlbdev_list_head;
	int num_cxlbdev;
	u64	max_lba[MAX_CXLBDEV_NUMS];
	u32 blk_len[MAX_CXLBDEV_NUMS];
	u64 lun_id[MAX_CXLBDEV_NUMS];
	u8 port_sel[MAX_CXLBDEV_NUMS];
	u64 vuiU[MAX_CXLBDEV_NUMS];
	u64 vuiL[MAX_CXLBDEV_NUMS];
	int cxlbdev_major;
	int cfg_idx;

	struct cxlflash_cfg *cfg;
};

struct cxlbdev_afu_cmd {
	struct sisl_ioarcb rcb;
	struct sisl_ioasa sa;
	char *buf;
	struct cxlbdev_afu *parent;
	int slot;
	atomic_t free;
	struct cxlbdev_cmd *cxlbdev_cmd;
} __aligned(cache_line_size());


struct cxlbdev_afu {
	u64 rrq_entry[CXLBDEV_NUM_RRQ_ENTRY];
	struct cxlbdev_afu_cmd cxlbdev_afu_cmd[CXLBDEV_NUM_CMDS];

	struct cxl_ioctl_start_work work;
	//struct cxlflash_afu_map	*afu_map;
	struct sisl_host_map *host_map;
	struct sisl_ctrl_map *ctrl_map;

	ctx_hndl_t ctx_hndl;
	u64 *hrrq_start;
	u64 *hrrq_end;
	u64 *hrrq_curr;
	bool toggle;
	bool read_room;
	atomic64_t room;
	u64 hb;
	u32 cmd_couts;
	u32 internal_lun;

	int rrq_irq_num[MAX_HW_QUEUES];

	struct cxlbdev_cfg *parent;
	struct work_struct work_q;
};

#define CXLBDEV_MAX_SEGMENT_SIZE_IN_BYTES	(16 * 1024 * 1024)
#define CXLBDEV_MAX_SECTORS	((CXLBDEV_MAX_SEGMENT_SIZE_IN_BYTES >> 9) * CXLBDEV_MAX_SEGMENTS)

struct cxlbdev_cmd {
	struct request *req;
	atomic_t nr_afu_cmds;
	sector_t sectors_issued;
	short nr_segs_issued;
	struct scatterlist sglist[CXLBDEV_MAX_SEGMENTS];
	struct scatterlist *cursg;
	int nseg;
};

struct cxlbdev_queue {
	int queue_idx;
};

struct cxlbdev {
	struct blk_mq_tag_set tag_set;
	struct request_queue *request_queue;
	struct gendisk *disk;
	sector_t size;
	u32 bs;
	struct cxlbdev_queue *cxlbdev_queue;
	u8 port_sel[MAX_CAPI_CARD];
	u64 lun_id;
	int index;
	u64 vuiU;
	u64 vuiL;

	unsigned int cfg_idx;
	struct cxlbdev_cfg	*cxlbdev_cfg[MAX_CAPI_CARD];
	struct list_head list[MAX_CAPI_CARD];
	struct list_head g_list;
	atomic_t num_cfg;
};

#endif /* ifndef _CXLFLASH_CXLBDEV_H */
