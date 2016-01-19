/*
 * CXL Flash Device Driver
 *
 * Written by: Manoj N. Kumar <manoj@linux.vnet.ibm.com>, IBM Corporation
 *             Matthew R. Ochs <mrochs@linux.vnet.ibm.com>, IBM Corporation
 *			   Youngjae Lee <leeyo@linux.vnet.ibm.com>, IBM Corporation
 *
 * Copyright (C) 2015 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/unaligned.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <uapi/misc/cxl.h>
#include <linux/async.h>


#include "main.h"
#include "sislite.h"
#include "common.h"
#include "cxlbdev.h"

extern int add_bdev(struct cxlbdev_cfg *, struct cxlbdev *);
extern void del_bdev(struct cxlbdev *);
extern void cxlbdev_cmd_complete(struct cxlbdev_cmd *, int);

int cxlbdev_submit_queues;
DEFINE_SPINLOCK(g_cfg_spinlock);
int num_cfg = 0;

void cxlbdev_free_mem(struct cxlflash_cfg *cfg){
	int i, j;
	char *buf = NULL;
	struct cxlbdev_cfg *cxlbdev_cfg = NULL;
	struct cxlbdev_afu *cxlbdev_afu = NULL;

	if(cfg->cxlbdev_cfg == NULL) return;

	cxlbdev_cfg = cfg->cxlbdev_cfg;

	for(i = 0; i< cxlbdev_submit_queues; i++){
		cxlbdev_afu = cxlbdev_cfg->afu_per_cpu[i];
		if(cxlbdev_afu != NULL){
			for(j = 0; j < CXLBDEV_NUM_CMDS; j++){
				buf = cxlbdev_afu->cxlbdev_afu_cmd[j].buf;
				if(!((u64)buf & (PAGE_SIZE - 1)))
					free_page((ulong)buf);
			}

			free_pages((ulong)cxlbdev_afu, get_order(sizeof(struct cxlbdev_afu)));
			cxlbdev_cfg->afu_per_cpu[i] = NULL;
		}
	}
}

int cxlbdev_alloc_mem(struct cxlflash_cfg *cfg){
	int rc = 0;
	int i, j;
	char *buf = NULL;
	struct cxlbdev_cfg *cxlbdev_cfg = NULL;
	struct cxlbdev_afu *cxlbdev_afu = NULL;
	unsigned long flags;

	cxlbdev_submit_queues = nr_cpu_ids;
	if(cxlbdev_submit_queues > MAX_HW_QUEUES) cxlbdev_submit_queues = MAX_HW_QUEUES;

	pr_debug("cxlbdev_submit_queues: %d\n", cxlbdev_submit_queues);

	cxlbdev_cfg = kzalloc(sizeof(struct cxlbdev_cfg), GFP_KERNEL);
	if(unlikely(cxlbdev_cfg == NULL)){
		pr_err("%s: cannot allocate memory for cxlbdev_cfg(%lu)\n", __func__, sizeof(struct cxlbdev_cfg));
		rc = -ENOMEM;
		goto out;
	}
	cxlbdev_cfg->cfg = cfg;
	cfg->cxlbdev_cfg = cxlbdev_cfg;

	spin_lock_irqsave(&g_cfg_spinlock, flags);
	cxlbdev_cfg->cfg_idx = num_cfg++;
	spin_unlock_irqrestore(&g_cfg_spinlock, flags);

	for(i = 0; i < cxlbdev_submit_queues; i++){
		cxlbdev_afu = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
										get_order(sizeof(struct cxlbdev_afu)));
		if(unlikely(cxlbdev_afu == NULL)){
			pr_err("%s: cannot get %d free pages\n", __func__,
					get_order(sizeof(struct cxlbdev_afu)));
			rc = -ENOMEM;
			cxlbdev_free_mem(cfg);
			goto out;
		}
		cxlbdev_afu->parent = cxlbdev_cfg;
		cxlbdev_cfg->afu_per_cpu[i] = cxlbdev_afu;

		for(j = 0; j < CXLBDEV_NUM_CMDS; buf += CMD_BUFSIZE, j++){
			if(!((u64)buf & (PAGE_SIZE - 1))){
				buf = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
				if(unlikely(buf == NULL)){
					pr_err("%s: Allocate command buffers fail\n", __func__);
					rc = -ENOMEM;
					cxlbdev_free_mem(cfg);
					goto out;
				}
			}
			cxlbdev_afu->cxlbdev_afu_cmd[j].buf = buf;
			atomic_set(&cxlbdev_afu->cxlbdev_afu_cmd[j].free, 1);
			cxlbdev_afu->cxlbdev_afu_cmd[j].slot = j;
		}
	}

out:
	return rc;
}

static irqreturn_t cxlbdev_sync_err_irq(int irq, void *data){
	struct cxlbdev_afu *cxlbdev_afu = (struct cxlbdev_afu*)data;
	u64 reg;
	u64 reg_unmasked;

	reg = readq_be(&cxlbdev_afu->host_map->intr_status);
	reg_unmasked = (reg & SISL_ISTATUS_UNMASK);

	if(reg_unmasked == 0UL){
		pr_err("%s: %llX: spurious interrupt, intr_status %016llX\n",
				__func__, (u64)cxlbdev_afu, reg);
		goto out;
	}

	pr_err("%s: %llX: unexpected interrupt, intr_status %016llX\n",
			__func__, (u64)cxlbdev_afu, reg);

	writeq_be(reg_unmasked, &cxlbdev_afu->host_map->intr_clear);

out:
	pr_debug("%s: returning rc=%d\n", __func__, IRQ_HANDLED);

	return IRQ_HANDLED;
}

struct cxlbdev_afu_cmd* cxlbdev_afu_cmd_checkout(struct cxlbdev_afu *cxlbdev_afu){
	int k, dec = CXLBDEV_NUM_CMDS;
	struct cxlbdev_afu_cmd *cxlbdev_afu_cmd;

	while(dec--){
		k = (cxlbdev_afu->cmd_couts++ & (CXLBDEV_NUM_CMDS - 1));

		cxlbdev_afu_cmd = &cxlbdev_afu->cxlbdev_afu_cmd[k];

		if(!atomic_dec_if_positive(&cxlbdev_afu_cmd->free)){
			pr_devel("%s: returning found index=%d cxlbdev_afu_cmd=%p\n",
					__func__, cxlbdev_afu_cmd->slot, cxlbdev_afu_cmd);
			return cxlbdev_afu_cmd;
		}
	}

	return NULL;
}

void cxlbdev_afu_cmd_checkin(struct cxlbdev_afu_cmd *cxlbdev_afu_cmd){
	cxlbdev_afu_cmd->rcb.scp = NULL;
	cxlbdev_afu_cmd->rcb.timeout = 0;
	cxlbdev_afu_cmd->sa.ioasc = 0;

	if(unlikely(atomic_inc_return(&cxlbdev_afu_cmd->free) != 1)){
		pr_err("%s: Freeing cxlbdev_afu_cmd (%d) that is not in use\n", __func__, cxlbdev_afu_cmd->slot);
		return;
	}

	pr_devel("%s: released cxlbdev_afu_cmd %p index=%d\n",
			__func__, cxlbdev_afu_cmd, cxlbdev_afu_cmd->slot);
}

static void cxlbdev_afu_cmd_complete(struct cxlbdev_afu_cmd *cxlbdev_afu_cmd){
	int rc = 0;
	struct cxlbdev_cmd *cxlbdev_cmd;
	struct sisl_ioarcb *ioarcb;
	struct sisl_ioasa *ioasa;

	ioarcb = &cxlbdev_afu_cmd->rcb;
	ioasa = &cxlbdev_afu_cmd->sa;

	if(unlikely(cxlbdev_afu_cmd->sa.ioasc)){
		pr_debug("%s: cxlbdev_afu_cmd failed afu_rc=%d scsi_rc=%d fc_rc=%d "
				"afu_extra=0x%X, scsi_extra=0x%X, fc_extra=0x%X\n",
				__func__, ioasa->rc.afu_rc, ioasa->rc.scsi_rc,
				ioasa->rc.fc_rc, ioasa->afu_extra, ioasa->scsi_extra,
				ioasa->fc_extra);

		rc = -EIO;
	}

	cxlbdev_cmd = cxlbdev_afu_cmd->cxlbdev_cmd;
	cxlbdev_afu_cmd_checkin(cxlbdev_afu_cmd);

	cxlbdev_cmd_complete(cxlbdev_cmd, rc);
}

static irqreturn_t cxlbdev_rrq_irq(int irq, void *data){
	struct cxlbdev_afu *cxlbdev_afu = (struct cxlbdev_afu*)data;
	struct cxlbdev_afu_cmd *cxlbdev_afu_cmd;
	bool toggle = cxlbdev_afu->toggle;
	u64 entry, *hrrq_start,*hrrq_end, *hrrq_curr;

	hrrq_start = cxlbdev_afu->hrrq_start;
	hrrq_end = cxlbdev_afu->hrrq_end;
	hrrq_curr = cxlbdev_afu->hrrq_curr;

	while(1){
		entry = *hrrq_curr;
		if((entry & SISL_RESP_HANDLE_T_BIT) != toggle)
			break;

		cxlbdev_afu_cmd = (struct cxlbdev_afu_cmd *)(entry & ~SISL_RESP_HANDLE_T_BIT);
		cxlbdev_afu_cmd_complete(cxlbdev_afu_cmd);

		if(hrrq_curr < hrrq_end)
			hrrq_curr++;
		else {
			hrrq_curr = hrrq_start;
			toggle ^= SISL_RESP_HANDLE_T_BIT;
		}
	}

	cxlbdev_afu->hrrq_curr = hrrq_curr;
	cxlbdev_afu->toggle = toggle;

	return IRQ_HANDLED;
}

static void term_ctx_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg, enum undo_level level, int queue_idx){
	int rc = 0;
	struct cxlbdev_afu *cxlbdev_afu = get_cxlbdev_afu(cxlbdev_cfg, queue_idx);
	struct cxl_context *ctx = cxlbdev_cfg->ctx_per_cpu[queue_idx];
	struct device *dev = &cxlbdev_cfg->cfg->dev->dev;

	if(cxlbdev_afu == NULL || ctx == NULL){
		dev_err(dev, "%s: returning from %s with NULL cxlbdev_afr or ctx per cpu\n", __func__, __func__);
		return;
	}

	switch(level){
		case UNDO_START:
			rc = cxl_stop_context(ctx);
			BUG_ON(rc);
		case UNMAP_TWO:
			irq_set_affinity_hint(cxlbdev_afu->rrq_irq_num[queue_idx], NULL);
			cxl_unmap_afu_irq(ctx, 2, cxlbdev_afu);
		case UNMAP_ONE:
			cxl_unmap_afu_irq(ctx, 1, cxlbdev_afu);
		case FREE_IRQ:
			cxl_free_afu_irqs(ctx);
		case RELEASE_CONTEXT:
			cxl_release_context(ctx);
			break;
		default:
			dev_err(dev, "%s: unsupported undo_level: %d\n", __func__, level);
	}

	cxlbdev_cfg->ctx_per_cpu[queue_idx] = NULL;

	return;
}

void cxlbdev_term_ctx_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg){
	int i;

	for(i = 0; i < cxlbdev_submit_queues; i++)
		if(cxlbdev_cfg->ctx_per_cpu[i] != NULL)
			term_ctx_per_cpu(cxlbdev_cfg, UNDO_START, i);
}

char irq_name[160][64];

int init_ctx_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg, int queue_idx){
	int rc = 0, i, maxcpu;
	struct cxlbdev_afu *cxlbdev_afu = get_cxlbdev_afu(cxlbdev_cfg, queue_idx);
	struct cxl_context *ctx;
	struct cxlflash_cfg *cfg = cxlbdev_cfg->cfg;
	struct device *dev = &cfg->dev->dev;
	enum undo_level level;
	struct cpumask cpumask;

	ctx = cxl_dev_context_init(cfg->dev);
	if(unlikely(IS_ERR_OR_NULL(ctx))){
		dev_err(dev, "%s: Could not initialize context %p\n", __func__, ctx);
		rc = -ENODEV;
		goto out;
	}

	rc = cxl_allocate_afu_irqs(ctx, 2);
	if(unlikely(rc)){
		dev_err(dev, "%s: fails to allocate afu_irqs rc=%d\n", __func__, rc);
		level = RELEASE_CONTEXT;
		goto err;
	}

	rc = cxl_map_afu_irq(ctx, 1, cxlbdev_sync_err_irq, cxlbdev_afu, "SISL_MSI_SYNC_ERROR");
	if(unlikely(rc < 0)){
		dev_err(dev, "%s: IRQ 1 (SISL_MSI_SYNC_ERROR) map failed\n", __func__);
		level = FREE_IRQ;
		goto err;
	}

	snprintf(irq_name[queue_idx], 64, "SISL_MSI_RRQ_UPDATED_CXLBDEV_%d_", queue_idx);
	rc = cxl_map_afu_irq(ctx, 2, cxlbdev_rrq_irq, cxlbdev_afu, irq_name[queue_idx]);
	if(unlikely(rc < 0)){
		dev_err(dev, "%s: IRQ 2 (%s) map failed\n", __func__, irq_name[queue_idx]);
		level = UNMAP_ONE;
		goto err;
	}
	cxlbdev_afu->rrq_irq_num[queue_idx] = rc;
	
	cpumask_clear(&cpumask);
	i = queue_idx / CORES_PER_NODE;
	maxcpu = (i + 1) * CORES_PER_NODE;
	for(i *= CORES_PER_NODE; i < maxcpu; i++)
		cpumask_set_cpu(i, &cpumask);
	rc = irq_set_affinity_hint(rc, &cpumask);
	if(unlikely(rc < 0)){
		dev_err(dev, "%s: IRQ 2 (%s) cpu affinity set failed\n", __func__, irq_name[queue_idx]);
	}

	rc = cxl_start_context(ctx, cxlbdev_afu->work.work_element_descriptor, NULL);
	if(unlikely(rc)){
		dev_err(dev, "%s: fails to start context %d\n", __func__, rc);
		level = UNMAP_TWO;
		goto err;
	}

	cxlbdev_cfg->ctx_per_cpu[queue_idx] = ctx;
out:
	return rc;
err:
	term_ctx_per_cpu(cxlbdev_cfg, level, queue_idx);
	goto out;
}

int cxlbdev_init_ctx(struct cxlflash_cfg *cfg){
	struct cxlbdev_cfg *cxlbdev_cfg = cfg->cxlbdev_cfg;
	int i;

	for(i = 0; i < cxlbdev_submit_queues; i++){
		if(init_ctx_per_cpu(cxlbdev_cfg, i)){
			cxlbdev_term_ctx_per_cpu(cxlbdev_cfg);
			return -1;
		}
	}

	return 0;
}

void stop_afu_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg, int queue_idx){
	struct cxlbdev_afu *cxlbdev_afu = get_cxlbdev_afu(cxlbdev_cfg, queue_idx);

	cancel_work_sync(&cxlbdev_afu->work_q);
	if(cxlbdev_cfg->rhte_per_cpu[queue_idx] != NULL)
		free_page((u64)cxlbdev_cfg->rhte_per_cpu[queue_idx]);
}

void cxlbdev_stop_afu_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg){
	int i;

	for(i = 0; i < cxlbdev_submit_queues; i++)
		stop_afu_per_cpu(cxlbdev_cfg, i);
}

static void cxlbdev_worker_thread(struct work_struct *work){
	struct cxlbdev_afu *cxlbdev_afu = container_of(work, struct cxlbdev_afu, work_q);

	if(cxlbdev_afu->read_room){
		atomic64_set(&cxlbdev_afu->room, readq_be(&cxlbdev_afu->host_map->cmd_room));
		cxlbdev_afu->read_room = false;
	}
}

int start_afu_per_cpu(struct cxlbdev_cfg *cxlbdev_cfg, int queue_idx){
	struct cxlbdev_afu *cxlbdev_afu = get_cxlbdev_afu(cxlbdev_cfg, queue_idx);
	struct cxl_context *ctx = cxlbdev_cfg->ctx_per_cpu[queue_idx];
	struct afu *mc_afu = cxlbdev_cfg->cfg->afu;
	struct cxlbdev_afu_cmd *cxlbdev_afu_cmd;
	struct sisl_rht_entry *rhte;
	int i = 0, rc = 0;
	u64 val;

	cxlbdev_afu->ctx_hndl = (u16)cxl_process_element(ctx);
	cxlbdev_afu->host_map = &mc_afu->afu_map->hosts[cxlbdev_afu->ctx_hndl].host;
	cxlbdev_afu->ctrl_map = &mc_afu->afu_map->ctrls[cxlbdev_afu->ctx_hndl].ctrl;

	writeq_be(SISL_ENDIAN_CTRL, &cxlbdev_afu->host_map->endian_ctrl);

	for(i = 0; i < CXLBDEV_NUM_CMDS; i++){
		cxlbdev_afu_cmd = &cxlbdev_afu->cxlbdev_afu_cmd[i];
		cxlbdev_afu_cmd->parent = cxlbdev_afu;
		cxlbdev_afu_cmd->rcb.ctx_id = cxlbdev_afu->ctx_hndl;
		cxlbdev_afu_cmd->rcb.msi = SISL_MSI_RRQ_UPDATED;
		cxlbdev_afu_cmd->rcb.rrq = 0x0;
	}

	memset(&cxlbdev_afu->rrq_entry, 0, sizeof(cxlbdev_afu->rrq_entry));

	cxlbdev_afu->hrrq_start = &cxlbdev_afu->rrq_entry[0];
	cxlbdev_afu->hrrq_end = &cxlbdev_afu->rrq_entry[CXLBDEV_NUM_RRQ_ENTRY - 1];
	cxlbdev_afu->hrrq_curr = cxlbdev_afu->hrrq_start;
	cxlbdev_afu->toggle = 1;

	writeq_be((u64)cxlbdev_afu->hrrq_start, &cxlbdev_afu->host_map->rrq_start);
	writeq_be((u64)cxlbdev_afu->hrrq_end, &cxlbdev_afu->host_map->rrq_end);

	readq_be(&cxlbdev_afu->ctrl_map->mbox_r);
	val = (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD |
			SISL_CTX_CAP_AFU_CMD | SISL_CTX_CAP_GSCSI_CMD |
			SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE);
	writeq_be(val, &cxlbdev_afu->ctrl_map->ctx_cap);
	val = readq_be(&cxlbdev_afu->ctrl_map->ctx_cap);
	if(val != (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD |
			SISL_CTX_CAP_AFU_CMD | SISL_CTX_CAP_GSCSI_CMD |
			SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE)){
		dev_err(&cxlbdev_cfg->cfg->dev->dev, "%s: ctx may be closed val=%06llX\n", __func__, val);
		rc = -EAGAIN;
		goto out;
	}

	atomic64_set(&cxlbdev_afu->room, readq_be(&cxlbdev_afu->host_map->cmd_room));

	rhte = (struct sisl_rht_entry *)get_zeroed_page(GFP_KERNEL);
	if(unlikely(rhte == NULL)){
		dev_err(&cxlbdev_cfg->cfg->dev->dev, "%s: fails to allocate rhte\n", __func__);
		rc = -ENOMEM;
		goto out;
	}

	cxlbdev_cfg->rhte_per_cpu[queue_idx] = rhte;

	writeq_be((u64)cxlbdev_cfg->rhte_per_cpu[queue_idx], &cxlbdev_afu->ctrl_map->rht_start);
	val = SISL_RHT_CNT_ID((u64)MAX_RHT_PER_CONTEXT, (u64)(cxlbdev_afu->ctx_hndl));
	writeq_be(val, &cxlbdev_afu->ctrl_map->rht_cnt_id);

	INIT_WORK(&cxlbdev_afu->work_q, cxlbdev_worker_thread);
	cxlbdev_afu->read_room = false;

out:
	return rc;
}

int cxlbdev_start_cxlbdev_afu(struct cxlflash_cfg *cfg){
	int rc = 0, i, j;

	for(i = 0; i < cxlbdev_submit_queues; i++){
		rc = start_afu_per_cpu(cfg->cxlbdev_cfg, i);
		if(rc){
			for(j = 0; j < i; j++)
				stop_afu_per_cpu(cfg->cxlbdev_cfg, j);
			dev_err(&cfg->dev->dev, "%s: fails to start cxlbdev_afu(%d)\n", __func__, i);
			return rc;
		}
	}

	return rc;
}

static int cxlbdev_scan_bdev(struct cxlflash_cfg *cfg){
	struct cxlbdev_cfg *cxlbdev_cfg = cfg->cxlbdev_cfg;
	struct afu *afu = cfg->afu;
	struct device *dev = &cfg->dev->dev;
	struct afu_cmd *cmd;
	struct scsi_device *sdev;
	u8 *cmd_buf;
	u8 *scsi_cmd;
	int rc = 0, retry_cnt = 0;
	int idx;
	int offset, i;

	while(1){
		if(cfg->host->async_scan == 1) msleep(500);
		else break;
	}

	cmd_buf = kzalloc(CMD_BUFSIZE, GFP_KERNEL);
	scsi_cmd = kzalloc(MAX_COMMAND_SIZE, GFP_KERNEL);
	if(unlikely(cmd_buf == NULL || scsi_cmd == NULL)){
		rc = -ENOMEM;
		goto out;
	}

	idx = 0;

	shost_for_each_device(sdev, cfg->host){
		retry_cnt = 0;
		cmd = cxlflash_cmd_checkout(afu);
		if(unlikely(cmd == NULL)){
			dev_err(dev, "%s: count not get a free commmand\n", __func__);
			rc = -EBUSY;
			goto out;
		}
retry:
		memset(scsi_cmd, 0, MAX_COMMAND_SIZE);
		memset(cmd_buf, 0, CMD_BUFSIZE);

		scsi_cmd[0] = SERVICE_ACTION_IN_16;
		scsi_cmd[1] = SAI_READ_CAPACITY_16;
		put_unaligned_be32(CMD_BUFSIZE, &scsi_cmd[10]);

		cmd->rcb.ctx_id = afu->ctx_hndl;
		cmd->rcb.port_sel = sdev->channel + 1;
		cmd->rcb.lun_id = lun_to_lunid(sdev->lun);

		cmd->rcb.req_flags = SISL_REQ_FLAGS_HOST_READ |
								SISL_REQ_FLAGS_PORT_LUN_ID |
								SISL_REQ_FLAGS_SUP_UNDERRUN;

		cmd->rcb.scp = NULL;

		cmd->rcb.data_ea = (u64)cmd_buf;
		cmd->rcb.data_len = CMD_BUFSIZE;

		memcpy(cmd->rcb.cdb, scsi_cmd, sizeof(cmd->rcb.cdb));

		init_completion(&cmd->cevent);

		rc = cxlflash_send_cmd(afu, cmd);
		if(unlikely(rc)){
			dev_err(dev, "%s: send_cmd failed %d\n", __func__, rc);
			cxlflash_cmd_checkin(cmd);
			goto out;
		}

		wait_for_completion(&cmd->cevent);

		if(cmd->sa.ioasc){
			if(retry_cnt++ < 3)
				goto retry;
			else {
				struct sisl_ioasa *ioasa;

				ioasa = &(cmd->sa);

				pr_err("%s: cmd failed afu_rc=%d scsi_rc=%d fc_rc=%d "
				 "afu_extra=0x%X, scsi_extra=0x%X, fc_extra=0x%X\n",
				 __func__, ioasa->rc.afu_rc, ioasa->rc.scsi_rc,
				 ioasa->rc.fc_rc, ioasa->afu_extra, ioasa->scsi_extra,
				 ioasa->fc_extra);

				rc = -EBUSY;
				goto out;
			}
		}

		cxlbdev_cfg->max_lba[idx] = be64_to_cpu(*((__be64 *)&cmd_buf[0]));
		cxlbdev_cfg->blk_len[idx] = be32_to_cpu(*((__be32 *)&cmd_buf[8]));
		cxlbdev_cfg->lun_id[idx] = lun_to_lunid(sdev->lun);
		cxlbdev_cfg->port_sel[idx] = sdev->channel + 1;
		pr_debug("%s: read_cap16 [%d] %llu %u %u\n",
				__func__, idx, cxlbdev_cfg->max_lba[idx],
				cxlbdev_cfg->blk_len[idx], cxlbdev_cfg->port_sel[idx]);

		retry_cnt = 0;
retry1:
		memset(scsi_cmd, 0, MAX_COMMAND_SIZE);
		memset(cmd_buf, 0, CMD_BUFSIZE);

		scsi_cmd[0] = INQUIRY;
		scsi_cmd[1] = 0x01;
		scsi_cmd[2] = 0x83;
		put_unaligned_be16(CMD_BUFSIZE, &scsi_cmd[3]);

		cmd->rcb.ctx_id = afu->ctx_hndl;
		cmd->rcb.port_sel = sdev->channel + 1;
		cmd->rcb.lun_id = lun_to_lunid(sdev->lun);

		cmd->rcb.req_flags = SISL_REQ_FLAGS_HOST_READ |
								SISL_REQ_FLAGS_PORT_LUN_ID |
								SISL_REQ_FLAGS_SUP_UNDERRUN;

		cmd->rcb.scp = NULL;

		cmd->rcb.data_ea = (u64)cmd_buf;
		cmd->rcb.data_len = CMD_BUFSIZE;

		memcpy(cmd->rcb.cdb, scsi_cmd, sizeof(cmd->rcb.cdb));

		init_completion(&cmd->cevent);

		rc = cxlflash_send_cmd(afu, cmd);
		if(unlikely(rc)){
			dev_err(dev, "%s: send_cmd failed %d\n", __func__, rc);
			cxlflash_cmd_checkin(cmd);
			goto out;
		}

		wait_for_completion(&cmd->cevent);

		if(cmd->sa.ioasc){
			if(retry_cnt++ < 3)
				goto retry1;
			else{
				struct sisl_ioasa *ioasa;

				ioasa = &(cmd->sa);

				pr_err("%s: cmd failed afu_rc=%d scsi_rc=%d fc_rc=%d "
				 "afu_extra=0x%X, scsi_extra=0x%X, fc_extra=0x%X\n",
				 __func__, ioasa->rc.afu_rc, ioasa->rc.scsi_rc,
				 ioasa->rc.fc_rc, ioasa->afu_extra, ioasa->scsi_extra,
				 ioasa->fc_extra);

				goto next;
			}
		}

		offset = 4;
		while(1){
			i = 0;
			if(cmd_buf[offset + 1] == 0x3){
				cxlbdev_cfg->vuiU[idx] = be64_to_cpu(*((__be64 *)&cmd_buf[offset + 4]));
				cxlbdev_cfg->vuiL[idx] = be64_to_cpu(*((__be64 *)&cmd_buf[offset + 12]));
			}
			while(1){
				if(i == cmd_buf[offset + 3]) break;
				i++;
			}
			offset += (4 + i);
			if(offset >= (3 + be16_to_cpu(*((__be16 *)&cmd_buf[2])))) break;
		}

		pr_debug("%s: read_cap16 [%d] %llx%llx\n",
				__func__, idx, cxlbdev_cfg->vuiU[idx], cxlbdev_cfg->vuiL[idx]);
next:
		cxlflash_cmd_checkin(cmd);


		idx++;
	}

	cxlbdev_cfg->num_cxlbdev = idx;

out:
	if(cmd_buf) kfree(cmd_buf);
	if(scsi_cmd) kfree(scsi_cmd);

	return rc;
}

DEFINE_SPINLOCK(lock_for_cxlbdev_major);
volatile int cxlbdev_major = -1;
volatile int cxlbdev_base_index = 0;
struct list_head g_cxlbdev_list_head;

int cxlbdev_init_bdev(struct cxlflash_cfg *cfg){
	struct cxlbdev_cfg *cxlbdev_cfg = cfg->cxlbdev_cfg;
	struct cxlbdev *cxlbdev;
	int i, rc, cfg_idx;
	unsigned long flags;

	INIT_LIST_HEAD(&cxlbdev_cfg->cxlbdev_list_head);
	for(i = 0; i < MAX_CXLBDEV_NUMS; i++){
		cxlbdev_cfg->max_lba[i] = 0;
		cxlbdev_cfg->blk_len[i] = 0; 
		cxlbdev_cfg->lun_id[i] = 0;
		cxlbdev_cfg->port_sel[i] = 0;
	}

	rc = cxlbdev_scan_bdev(cfg);
	if(unlikely(rc)){
		dev_err(&cfg->dev->dev, "%s: cxlbdev_scan_bdev failed: %d\n", __func__, rc);
		goto out;
	}

	spin_lock_irqsave(&lock_for_cxlbdev_major, flags);
	if(cxlbdev_major == -1){
		rc = register_blkdev(0, "cxlb");
		if(unlikely(rc < 0)){
			dev_err(&cfg->dev->dev, "%s: register_blkdev failed: %d\n", __func__, rc);
			goto out;
		}
		cxlbdev_major = rc;
		INIT_LIST_HEAD(&g_cxlbdev_list_head);
	}
	spin_unlock_irqrestore(&lock_for_cxlbdev_major, flags);

	cxlbdev_cfg->cxlbdev_major = cxlbdev_major;
	cfg_idx = cxlbdev_cfg->cfg_idx;

	rc = 0;

	for(i = 0; i < cxlbdev_cfg->num_cxlbdev; i++){
		struct list_head *pos;
		bool found;

		spin_lock_irqsave(&lock_for_cxlbdev_major, flags);
		found = false;
		list_for_each(pos, &g_cxlbdev_list_head){
			cxlbdev = list_entry(pos, struct cxlbdev, g_list);

			if(cxlbdev->vuiU == cxlbdev_cfg->vuiU[i] && cxlbdev->vuiL == cxlbdev_cfg->vuiL[i]){
				if(cxlbdev->cxlbdev_cfg[cfg_idx] == NULL){
					cxlbdev->port_sel[cfg_idx] = cxlbdev_cfg->port_sel[i];
					list_add(&cxlbdev->list[cfg_idx], &cxlbdev_cfg->cxlbdev_list_head);
					atomic_inc(&cxlbdev->num_cfg);
					cxlbdev->cxlbdev_cfg[cfg_idx] = cxlbdev_cfg;
				} else {
					cxlbdev->port_sel[cfg_idx] |= cxlbdev_cfg->port_sel[i];
				}
				pr_debug("%s: add_cfg[%d] %llx%llx %u\n",
						__func__, cfg_idx, cxlbdev_cfg->vuiU[i], cxlbdev_cfg->vuiL[i],
						cxlbdev->port_sel[cfg_idx]);
				found = true;
				break;
			}
		}
		
		if(found){
			spin_unlock_irqrestore(&lock_for_cxlbdev_major, flags);
			continue;
		}

		cxlbdev = kzalloc(sizeof(struct cxlbdev), GFP_ATOMIC);
		if(unlikely(cxlbdev == NULL)){
			dev_err(&cfg->dev->dev, "%s: failed to allocate cxlbdev\n", __func__);
			goto out;
		}

		cxlbdev->size = cxlbdev_cfg->max_lba[i] + 1;
		cxlbdev->bs = cxlbdev_cfg->blk_len[i];
		cxlbdev->lun_id = cxlbdev_cfg->lun_id[i];
		cxlbdev->port_sel[cfg_idx] = cxlbdev_cfg->port_sel[i];
		cxlbdev->vuiU = cxlbdev_cfg->vuiU[i];
		cxlbdev->vuiL = cxlbdev_cfg->vuiL[i];	
		cxlbdev->index = cxlbdev_base_index++;
		cxlbdev->cfg_idx = cfg_idx;
		atomic_set(&cxlbdev->num_cfg, 1);
		cxlbdev->cxlbdev_cfg[cfg_idx] = cxlbdev_cfg;
		list_add(&cxlbdev->list[cfg_idx], &cxlbdev_cfg->cxlbdev_list_head);
		list_add(&cxlbdev->g_list, &g_cxlbdev_list_head);
		pr_debug("%s: create_bdev[%d] %llx%llx %u\n",
				__func__, cfg_idx, cxlbdev_cfg->vuiU[i], cxlbdev_cfg->vuiL[i],
				cxlbdev->port_sel[cfg_idx]);
		spin_unlock_irqrestore(&lock_for_cxlbdev_major, flags);

		rc = add_bdev(cxlbdev_cfg, cxlbdev);
		if(unlikely(rc < 0)){
			dev_err(&cfg->dev->dev, "%s: failed to add bdev %d\n", __func__, rc);
			list_del(&cxlbdev->list[cfg_idx]);
			spin_lock_irqsave(&lock_for_cxlbdev_major, flags);
			list_del(&cxlbdev->g_list);
			spin_unlock_irqrestore(&lock_for_cxlbdev_major, flags);
			kfree(cxlbdev);

			goto out;
		}
	}
out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);

	return rc;
}

void cxlbdev_remove_bdevs(struct cxlbdev_cfg *cxlbdev_cfg){
	struct list_head *pos, *n;
	struct cxlbdev *cxlbdev;
	int cfg_idx = cxlbdev_cfg->cfg_idx;
	unsigned long flags;

	list_for_each_safe(pos, n, &cxlbdev_cfg->cxlbdev_list_head){
		cxlbdev = list_entry(pos, struct cxlbdev, list[cfg_idx]);
		list_del(&cxlbdev->list[cfg_idx]);
		cxlbdev->cxlbdev_cfg[cfg_idx] = NULL;
		if(atomic_dec_and_test(&cxlbdev->num_cfg)){
			spin_lock_irqsave(&lock_for_cxlbdev_major, flags);
			list_del(&cxlbdev->g_list);
			spin_unlock_irqrestore(&lock_for_cxlbdev_major, flags);
			del_bdev(cxlbdev);
		}
	}
}

void cxlbdev_remove(struct cxlflash_cfg *cfg){
	switch (cfg->init_state) {
	case INIT_STATE_CXLBDEV_BDEV:
		cxlbdev_remove_bdevs(cfg->cxlbdev_cfg);
	case INIT_STATE_CXLBDEV_AFU:
		cxlbdev_stop_afu_per_cpu(cfg->cxlbdev_cfg);
	case INIT_STATE_CXLBDEV_CTX:
		cxlbdev_term_ctx_per_cpu(cfg->cxlbdev_cfg);
	case INIT_STATE_CXLBDEV_ALLOC:
		cxlbdev_free_mem(cfg);
	default:
		break;
	}
	cfg->init_state = INIT_STATE_SCSI;

	return;
}

int cxlbdev_pci_slot_reset(struct cxlflash_cfg *cfg){
	int rc = 0;

	rc = cxlbdev_init_ctx(cfg);
	if(rc) goto err;

	rc = cxlbdev_start_cxlbdev_afu(cfg);
	if(rc){
		cxlbdev_term_ctx_per_cpu(cfg->cxlbdev_cfg);
		goto err;
	}

out:
	return rc;
err:
	cxlbdev_remove_bdevs(cfg->cxlbdev_cfg);
	cfg->init_state = INIT_STATE_SCSI;
	goto out;
}

int cxlbdev_afu_reset(struct cxlflash_cfg *cfg){
	int rc = 0;

	cxlbdev_stop_afu_per_cpu(cfg->cxlbdev_cfg);
	cxlbdev_term_ctx_per_cpu(cfg->cxlbdev_cfg);

	rc = cxlbdev_init_ctx(cfg);
	if(rc) goto err;

	rc = cxlbdev_start_cxlbdev_afu(cfg);
	if(rc){
		cxlbdev_term_ctx_per_cpu(cfg->cxlbdev_cfg);
		goto err;
	}

out:
	return rc;
err:
	cxlbdev_remove_bdevs(cfg->cxlbdev_cfg);
	cfg->init_state = INIT_STATE_SCSI;
	goto out;
}



static void do_cxlbdev_init_bdev(void *data, async_cookie_t c){
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)data;
	int rc;

	rc = cxlbdev_init_bdev(cfg);
	if (rc) {
		dev_err(&cfg->dev->dev, "%s: cxlbdev_init_bdev failed rc=%d\n", __func__, rc);
		cxlbdev_remove_bdevs(cfg->cxlbdev_cfg);
		goto out;
	}
	cfg->init_state = INIT_STATE_CXLBDEV_BDEV;

out:
	return;
}

int cxlbdev_init(struct cxlflash_cfg *cfg){
	int rc = 0;

	rc = cxlbdev_alloc_mem(cfg);
	if (rc) {
		dev_err(&cfg->dev->dev, "%s: call to cxlbdev_alloc_mem failed rc=%d!\n", __func__, rc);
		goto out;
	}
	cfg->init_state = INIT_STATE_CXLBDEV_ALLOC;

	rc = cxlbdev_init_ctx(cfg);
	if (rc) {
		dev_err(&cfg->dev->dev, "%s: call to cxlbdev_init_ctx failed rc=%d!\n", __func__, rc);
		goto out;
	}
	cfg->init_state = INIT_STATE_CXLBDEV_CTX;

	rc = cxlbdev_start_cxlbdev_afu(cfg);
	if (rc) {
		dev_err(&cfg->dev->dev, "%s: call to cxlbdev_start_afu failed rc=%d!\n", __func__, rc);
		goto out;
	}
	cfg->init_state = INIT_STATE_CXLBDEV_AFU;

	async_schedule(do_cxlbdev_init_bdev, cfg);

out:
	return rc;
}
