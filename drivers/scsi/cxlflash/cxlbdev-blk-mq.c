#include <asm/unaligned.h>
#include <linux/blkdev.h>
#include <scsi/scsi_cmnd.h>
#include <linux/blk-mq.h>
#include <linux/numa.h>
#include <scsi/sg.h>
#include <uapi/misc/cxl.h>

#include "sislite.h"
#include "main.h"
#include "common.h"
#include "cxlbdev.h"

extern struct afu_cmd *cxlflash_cmd_checkout(struct afu *);
extern void cxlflash_cmd_checkin(struct afu_cmd *);
extern int cxlflash_send_cmd(struct afu *, struct afu_cmd *);
extern struct cxlbdev_afu_cmd* cxlbdev_afu_cmd_checkout(struct cxlbdev_afu *);
extern void cxlbdev_afu_cmd_checkin(struct cxlbdev_afu_cmd *);

static void cxlbdev_cmd_end(struct cxlbdev_cmd *cxlbdev_cmd, int error){
	struct request *req = cxlbdev_cmd->req;

	cxlbdev_cmd->sectors_issued = 0;
	cxlbdev_cmd->nr_segs_issued = 0;

	sg_init_table(cxlbdev_cmd->sglist, CXLBDEV_MAX_SEGMENTS);
	cxlbdev_cmd->cursg = NULL;

	blk_mq_end_request(req, error);	

	return;
}

void cxlbdev_cmd_complete(struct cxlbdev_cmd *cxlbdev_cmd, int error){
	if(atomic_dec_and_test(&cxlbdev_cmd->nr_afu_cmds)){
#ifndef SOFT_IRQ
		cxlbdev_cmd_end(cxlbdev_cmd, error);
#else
		blk_mq_complete_request(cxlbdev_cmd->req, error);
#endif
	}

	return;
}

static int cxlbdev_send_cmd(struct cxlbdev_afu *cxlbdev_afu, struct cxlbdev_afu_cmd *cxlbdev_afu_cmd){
	int nretry = 0;
	int rc = 0;
	u64 room;
	long newval;

retry:
	newval = atomic64_dec_if_positive(&cxlbdev_afu->room);
	if(!newval){
		do{
			room = readq_be(&cxlbdev_afu->host_map->cmd_room);
			atomic64_set(&cxlbdev_afu->room , room);
			if(room)
				goto write_ioarrin;
			udelay(nretry);
		} while(nretry++ < MC_ROOM_RETRY_CNT);

		goto no_room;
	} else if(unlikely(newval < 0)){
		if(nretry++ < MC_ROOM_RETRY_CNT){
			udelay(nretry);
			goto retry;
		}
		goto no_room;
	}

write_ioarrin:
	writeq_be((u64)&cxlbdev_afu_cmd->rcb, &cxlbdev_afu->host_map->ioarrin);
out:
	pr_devel("%s: cxlbdev_afu_cmd=%p len=%d ea=%p rc=%d\n", __func__, cxlbdev_afu_cmd,
			cxlbdev_afu_cmd->rcb.data_len, (void*)cxlbdev_afu_cmd->rcb.data_ea, rc);
	return rc;

no_room:
	cxlbdev_afu->read_room = true;
	schedule_work(&cxlbdev_afu->work_q);

	rc = SCSI_MLQUEUE_HOST_BUSY;
	goto out;
}

static int cxlbdev_build_cdb(struct request *req, u8 *cdb, sector_t offset, unsigned int this_count){
	sector_t block;

	block = blk_rq_pos(req) + offset;

	if(rq_data_dir(req) == WRITE)
		cdb[0] = WRITE_16;
	else if(rq_data_dir(req) == READ)
		cdb[0] = READ_16;
	else if(req->cmd_flags & REQ_FLUSH)
		cdb[0] = SYNCHRONIZE_CACHE;
	else {
		pr_err("%s: unknown command %llu\n", __func__, (unsigned long long)req->cmd_flags);
		return -1;
	}

	cdb[1] = (req->cmd_flags | REQ_FUA) ? 0x8 : 0;
	cdb[2] = sizeof(block) > 4 ? (unsigned char) (block >> 56) & 0xff : 0;
	cdb[3] = sizeof(block) > 4 ? (unsigned char) (block >> 48) & 0xff : 0;
	cdb[4] = sizeof(block) > 4 ? (unsigned char) (block >> 40) & 0xff : 0;
	cdb[5] = sizeof(block) > 4 ? (unsigned char) (block >> 32) & 0xff : 0;
	cdb[6] = (unsigned char) (block >> 24) & 0xff;
	cdb[7] = (unsigned char) (block >> 16) & 0xff;
	cdb[8] = (unsigned char) (block >> 8) & 0xff;
	cdb[9] = (unsigned char) block & 0xff;
	cdb[10] = (unsigned char) (this_count >> 24) & 0xff;
	cdb[11] = (unsigned char) (this_count >> 16) & 0xff;
	cdb[12] = (unsigned char) (this_count >> 8) & 0xff;
	cdb[13] = (unsigned char) this_count & 0xff;
	cdb[14] = cdb[15] = 0;

	return 0;
}

// hctx->driver_data = cxlbdev_queue;
static int cxlbdev_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd){
	struct cxlbdev_cmd *cxlbdev_cmd = NULL;
	struct cxlbdev_queue *cxlbdev_queue = NULL;
	struct cxlbdev_cfg *cxlbdev_cfg = NULL;
	struct cxlflash_cfg *cfg = NULL;
	struct cxlbdev *cxlbdev = NULL;
	struct cxlbdev_afu *cxlbdev_afu = NULL;
	struct cxlbdev_afu_cmd *cxlbdev_afu_cmd = NULL;
	struct request *req = NULL;
	struct request_queue *q = NULL;
	int ret = BLK_MQ_RQ_QUEUE_OK, ncmds;
	u8 cdb[16];

	cxlbdev_cmd = blk_mq_rq_to_pdu(bd->rq);
	cxlbdev_cmd->req = bd->rq;
	req = cxlbdev_cmd->req;
	q = req->q;
	cxlbdev = (struct cxlbdev*)q->queuedata;
	cxlbdev_queue = (struct cxlbdev_queue *)hctx->driver_data;

	while(1){
		cxlbdev_cfg = cxlbdev->cxlbdev_cfg[cxlbdev->cfg_idx++ % MAX_CAPI_CARD];
		if(cxlbdev_cfg == NULL)
			cxlbdev_cfg = cxlbdev->cxlbdev_cfg[cxlbdev->cfg_idx++ % MAX_CAPI_CARD];
		else break;
	}

	cfg = cxlbdev_cfg->cfg;
	cxlbdev_afu = get_cxlbdev_afu(cxlbdev_cfg, cxlbdev_queue->queue_idx);

	if(cfg->tmf_active){
		ret = BLK_MQ_RQ_QUEUE_BUSY;
		goto out;
	}

	switch(cfg->state){
		case STATE_LIMBO:
			dev_dbg_ratelimited(&cfg->dev->dev, "%s: device is in reset\n", __func__);
			ret = BLK_MQ_RQ_QUEUE_BUSY;
			goto out;
		case STATE_FAILTERM:
			dev_dbg_ratelimited(&cfg->dev->dev, "%s: devies has failed\n", __func__);
			cxlbdev_cmd_complete(cxlbdev_cmd, -EIO);
			ret = 0;
			goto out;
		default:
			break;
	}

	if(req->cmd_flags & REQ_DISCARD){
		pr_err("%s: REQ_DISCARD not supported\n", __func__);
		ret = BLK_MQ_RQ_QUEUE_ERROR;
		goto out;
	} else if(req->cmd_flags & REQ_WRITE_SAME){
		pr_err("%s: REQ_WRITE_SAME not supported\n", __func__);
		ret = BLK_MQ_RQ_QUEUE_ERROR;
		goto out;
	}

	if(cxlbdev_cmd->cursg == NULL){
		cxlbdev_cmd->nseg = blk_rq_map_sg(q, req, cxlbdev_cmd->sglist);
		if(unlikely(cxlbdev_cmd->nseg < 0)) BUG();

		ncmds = cxlbdev_cmd->nseg ? : 1;
		atomic_set(&cxlbdev_cmd->nr_afu_cmds, ncmds);
		sg_mark_end(&cxlbdev_cmd->sglist[ncmds - 1]);
		cxlbdev_cmd->cursg = &cxlbdev_cmd->sglist[0];
	}

	blk_mq_start_request(bd->rq);

	while(1){
		sector_t cur_length;
		struct scatterlist *prev_cursg;

		cxlbdev_afu_cmd = cxlbdev_afu_cmd_checkout(cxlbdev_afu);
		if(unlikely(cxlbdev_afu_cmd == NULL)){
			dev_dbg_ratelimited(&cfg->dev->dev, "%s: could not get a free command %d\n",
								__func__, hctx->queue_num);
			ret = BLK_MQ_RQ_QUEUE_BUSY;
			goto out;
		}

		cxlbdev_afu_cmd->rcb.ctx_id = cxlbdev_afu->ctx_hndl;
		cxlbdev_afu_cmd->rcb.port_sel = cxlbdev->port_sel[cxlbdev_cfg->cfg_idx];
		cxlbdev_afu_cmd->rcb.lun_id = cxlbdev->lun_id;

		if(rq_data_dir(req) == WRITE)
			cxlbdev_afu_cmd->rcb.req_flags = SISL_REQ_FLAGS_HOST_WRITE;
		else
			cxlbdev_afu_cmd->rcb.req_flags = SISL_REQ_FLAGS_HOST_READ;

		cxlbdev_afu_cmd->rcb.req_flags |= (SISL_REQ_FLAGS_PORT_LUN_ID | SISL_REQ_FLAGS_SUP_UNDERRUN);

		cxlbdev_afu_cmd->rcb.scp = NULL;
		cxlbdev_afu_cmd->cxlbdev_cmd = cxlbdev_cmd;

		cur_length = cxlbdev_cmd->cursg->length;

		if(likely(cxlbdev_cmd->nseg > 0)){
			cxlbdev_afu_cmd->rcb.data_len = cur_length;
			cxlbdev_afu_cmd->rcb.data_ea = (u64)sg_virt(cxlbdev_cmd->cursg);
			cxlbdev_build_cdb(req, cdb, cxlbdev_cmd->sectors_issued, cxlbdev_cmd->cursg->length >> 9);
		} else // maybe it is a flush command.
			cxlbdev_build_cdb(req, cdb, 0, blk_rq_sectors(req));

		memcpy(cxlbdev_afu_cmd->rcb.cdb, cdb, sizeof(cxlbdev_afu_cmd->rcb.cdb));

		cxlbdev_cmd->sectors_issued += (cur_length >> 9);
		cxlbdev_cmd->nr_segs_issued++;

		prev_cursg = cxlbdev_cmd->cursg;
		cxlbdev_cmd->cursg = sg_next(cxlbdev_cmd->cursg);

		ret = cxlbdev_send_cmd(cxlbdev_afu, cxlbdev_afu_cmd);
		if(unlikely(ret)){
			cxlbdev_afu_cmd_checkin(cxlbdev_afu_cmd);
			ret = BLK_MQ_RQ_QUEUE_BUSY;
			cxlbdev_cmd->cursg = prev_cursg;
			cxlbdev_cmd->sectors_issued -= (cur_length >> 9);
			cxlbdev_cmd->nr_segs_issued--;

			goto out;
		}
		if(cxlbdev_cmd->cursg == NULL) break;
	}

out:
	pr_debug("%s returing ret=%d\n", __func__, ret);
	return ret;
}

static int cxlbdev_init_hctx(struct blk_mq_hw_ctx *hctx, void *data, unsigned int index){
	struct cxlbdev *cxlbdev = data;
	struct cxlbdev_queue *cxlbdev_queue = &cxlbdev->cxlbdev_queue[index];

	cxlbdev_queue->queue_idx = index;
	hctx->driver_data = cxlbdev_queue;

	return 0;
}


#ifdef SOFT_IRQ
static void cxlbdev_softirq_done_fn(struct request *req){
	cxlbdev_cmd_complete(blk_mq_rq_to_pdu(req), req->errors);
	return;
}
#endif

static int cxlbdev_init_request(void *data, struct request *req, unsigned int hctx_idx, unsigned int rq_idx, unsigned int numa_node){
	struct cxlbdev_cmd *cxlbdev_cmd = blk_mq_rq_to_pdu(req);

	BUG_ON(cxlbdev_cmd == NULL);

	cxlbdev_cmd->sectors_issued = 0;
	cxlbdev_cmd->nr_segs_issued = 0;

	sg_init_table(cxlbdev_cmd->sglist, CXLBDEV_MAX_SEGMENTS);
	cxlbdev_cmd->cursg = NULL;

	return 0;
}

static struct blk_mq_ops cxlbdev_mq_ops = {
	.queue_rq = cxlbdev_queue_rq,
	.map_queue = blk_mq_map_queue,
	.init_hctx = cxlbdev_init_hctx,
#ifdef SOFT_IRQ
	.complete = cxlbdev_softirq_done_fn,
#endif
	.init_request = cxlbdev_init_request,
};

static int cxlbdev_open(struct block_device *bdev, fmode_t mode){
	return 0;
}

static void cxlbdev_release(struct gendisk *disk, fmode_t mode){
}

static int cxlbdev_trans_completion(struct sg_io_hdr *hdr, u8 status, u8 sense_key, u8 asc, u8 ascq){
	u8 xfer_len;
	u8 resp[8];

	if (scsi_status_is_good(status)) {
		hdr->status = SAM_STAT_GOOD;
		hdr->masked_status = GOOD;
		hdr->host_status = DID_OK;
		hdr->driver_status = DRIVER_OK;
		hdr->sb_len_wr = 0;
	} else {
		hdr->status = status;
		hdr->masked_status = status >> 1;
		hdr->host_status = DID_OK;
		hdr->driver_status = DRIVER_OK;

		memset(resp, 0, 8);
		//resp[0] = DESC_FORMAT_SENSE_DATA;
		resp[0] = 0x72;
		resp[1] = sense_key;
		resp[2] = asc;
		resp[3] = ascq;

		xfer_len = min_t(u8, hdr->mx_sb_len, 8);
		hdr->sb_len_wr = xfer_len;
		if (copy_to_user(hdr->sbp, resp, xfer_len) > 0)
			return -EFAULT;
	}

	return 0;

}

int cxlbdev_sg_io(struct cxlbdev *cxlbdev, struct sg_io_hdr __user *u_hdr){
	struct sg_io_hdr hdr;
	u8 cmd[BLK_MAX_CDB];
	unsigned int opcode;
	int retcode = 0;
	struct cxlflash_cfg *cfg = NULL;
	struct afu *afu = NULL;
	struct afu_cmd *afu_cmd = NULL;
	u8 *cmd_buf = NULL;
	u8 *scsi_cmd = NULL;

	if(copy_from_user(&hdr, u_hdr, sizeof(hdr)))
		return -EFAULT;
	if(hdr.cmd_len > BLK_MAX_CDB)
		return -EINVAL;

	if(hdr.cmdp == NULL)
		return -EINVAL;
	if(copy_from_user(cmd, hdr.cmdp, hdr.cmd_len))
		return -EFAULT;

	opcode = cmd[0];

	switch (opcode) {
		case INQUIRY: {
			int alloc_len, ret;

			alloc_len = get_unaligned_be16(&cmd[3]);

			cmd_buf = kzalloc(CMD_BUFSIZE, GFP_KERNEL);
			scsi_cmd = kzalloc(MAX_COMMAND_SIZE, GFP_KERNEL);
			if(unlikely(cmd_buf == NULL || scsi_cmd == NULL)){
				retcode = -ENOMEM;
				goto out;
			}

			scsi_cmd[0] = INQUIRY;
			scsi_cmd[1] = cmd[1] & 0x01; // evpd
			scsi_cmd[2] = cmd[2]; // page_code

			put_unaligned_be16(CMD_BUFSIZE, &scsi_cmd[3]);

			cfg = cxlbdev->cxlbdev_cfg[0]->cfg;
			afu = cfg->afu;
			afu_cmd = cxlflash_cmd_checkout(afu);

			afu_cmd->rcb.ctx_id = afu->ctx_hndl;
			afu_cmd->rcb.port_sel = 1;
			afu_cmd->rcb.lun_id = cxlbdev->lun_id;

			afu_cmd->rcb.req_flags = SISL_REQ_FLAGS_HOST_READ |
								SISL_REQ_FLAGS_PORT_LUN_ID |
								SISL_REQ_FLAGS_SUP_UNDERRUN;

			afu_cmd->rcb.scp = NULL;

			afu_cmd->rcb.data_ea = (u64)cmd_buf;
			afu_cmd->rcb.data_len = CMD_BUFSIZE;

			memcpy(afu_cmd->rcb.cdb, scsi_cmd, sizeof(afu_cmd->rcb.cdb));

			init_completion(&afu_cmd->cevent);

			ret = cxlflash_send_cmd(afu, afu_cmd);
			if(unlikely(ret)){
				dev_err(&cfg->dev->dev, "%s: send_cmd failed %d\n", __func__, ret);
				cxlflash_cmd_checkin(afu_cmd);
				retcode = -EBUSY;
				goto out;
			}

			wait_for_completion(&afu_cmd->cevent);

			if(afu_cmd->sa.ioasc){
				struct sisl_ioasa *ioasa;

				ioasa = &(afu_cmd->sa);
				printk("%s: afu_cmd failed afu_rc=%d scsi_rc=%d fc_rc=%d "
				 "afu_extra=0x%X, scsi_extra=0x%X, fc_extra=0x%X\n",
				 __func__, ioasa->rc.afu_rc, ioasa->rc.scsi_rc,
				 ioasa->rc.fc_rc, ioasa->afu_extra, ioasa->scsi_extra,
				 ioasa->fc_extra);

				retcode = -EBUSY;
			} else {
				if(copy_to_user(hdr.dxferp, cmd_buf, alloc_len))
					retcode = -EFAULT;
			}

			cxlflash_cmd_checkin(afu_cmd);

			if(cmd_buf) kfree(cmd_buf);
			if(scsi_cmd) kfree(scsi_cmd);

			break;
		}
		default:
			retcode = cxlbdev_trans_completion(&hdr, SAM_STAT_CHECK_CONDITION,
				ILLEGAL_REQUEST, 0x20,
				0);
				//ILLEGAL_REQUEST, SCSI_ASC_ILLEGAL_COMMAND,
				//SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
			break;
	}

out:
	return retcode;
}

static int cxlbdev_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg){
	struct cxlbdev *cxlbdev;

	cxlbdev = (struct cxlbdev *)bdev->bd_disk->private_data;

	switch (cmd) {
		case SG_IO:
			return cxlbdev_sg_io(cxlbdev, (void __user *)arg);
	}

	return 0;
}

static const struct block_device_operations cxlbdev_fops = {
	.owner = THIS_MODULE,
	.open = cxlbdev_open,
	.release = cxlbdev_release,
	.ioctl = cxlbdev_ioctl,
};

static int setup_cxlbdev_queues(struct cxlbdev *cxlbdev){
	cxlbdev->cxlbdev_queue = kzalloc(cxlbdev_submit_queues * sizeof(struct cxlbdev_queue), GFP_KERNEL);
	if(unlikely(cxlbdev->cxlbdev_queue == NULL)){
		return -ENOMEM;
	}

	return 0;
}

static void cxlbdev_init_request_queue(struct cxlbdev *cxlbdev){
	struct request_queue *q = cxlbdev->request_queue;

	q->queuedata = cxlbdev;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);
	queue_flag_clear_unlocked(QUEUE_FLAG_IO_STAT, q);
	blk_queue_logical_block_size(q, cxlbdev->bs);
	blk_queue_physical_block_size(q, cxlbdev->bs);

	blk_queue_max_segments(q, CXLBDEV_MAX_SEGMENTS);
	blk_queue_max_hw_sectors(q, CXLBDEV_MAX_SECTORS);
	blk_queue_max_segment_size(q, CXLBDEV_MAX_SEGMENT_SIZE_IN_BYTES);

	return;
}

static void cleanup_queues(struct cxlbdev *cxlbdev){
	kfree(cxlbdev->cxlbdev_queue);
	return;
}

int add_bdev(struct cxlbdev_cfg *cxlbdev_cfg, struct cxlbdev *cxlbdev){
	struct gendisk *disk;
	int rc = 0;

	rc = setup_cxlbdev_queues(cxlbdev);
	if(unlikely(rc)) goto out;

	cxlbdev->tag_set.ops = &cxlbdev_mq_ops;
	cxlbdev->tag_set.nr_hw_queues = cxlbdev_submit_queues;
	cxlbdev->tag_set.queue_depth = CXLBDEV_MAX_CMDS;
	cxlbdev->tag_set.numa_node = NUMA_NO_NODE;
	cxlbdev->tag_set.cmd_size = sizeof(struct cxlbdev_cmd);
	cxlbdev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	cxlbdev->tag_set.driver_data = cxlbdev;

	rc = blk_mq_alloc_tag_set(&cxlbdev->tag_set);
	if(unlikely(rc)) goto out_cleanup_queues;

	cxlbdev->request_queue = blk_mq_init_queue(&cxlbdev->tag_set);
	if(IS_ERR(cxlbdev->request_queue)){
		rc = -ENOMEM;
		goto out_cleanup_tags;
	}

	cxlbdev_init_request_queue(cxlbdev);

	disk = cxlbdev->disk = alloc_disk_node(1, NUMA_NO_NODE);
	if(unlikely(disk == NULL)){
		rc = -ENOMEM;
		goto out_cleanup_blk_queue;
	}

	set_capacity(disk, cxlbdev->size);

	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_SUPPRESS_PARTITION_INFO;
	disk->major = cxlbdev_cfg->cxlbdev_major;
	disk->first_minor = cxlbdev->index * 16;
	disk->fops = &cxlbdev_fops;
	disk->private_data = cxlbdev;
	disk->queue = cxlbdev->request_queue;
	sprintf(disk->disk_name, "cxlbdev%d", cxlbdev->index);
	add_disk(disk);

	return 0;

out_cleanup_blk_queue:
	blk_cleanup_queue(cxlbdev->request_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&cxlbdev->tag_set);
out_cleanup_queues:
	cleanup_queues(cxlbdev);
out:
	return rc;
}


void del_bdev(struct cxlbdev *cxlbdev){
	del_gendisk(cxlbdev->disk);
	blk_cleanup_queue(cxlbdev->request_queue);
	blk_mq_free_tag_set(&cxlbdev->tag_set);
	put_disk(cxlbdev->disk);
	cleanup_queues(cxlbdev);
	kfree(cxlbdev);
}
