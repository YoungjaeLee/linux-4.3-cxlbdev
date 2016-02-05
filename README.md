# linux-4.3-cxlbdev

Linux kernel 4.3 with the updated cxlflash including a new light-weight and scalable block device driver, called cxlbdev, for POWER8's CAPI flash.

With the new cxlflash, we can access volumes via block device files named /dev/cxlbdevX as well as traditional scsi device files (e.g. /dev/sdX).

The cxlbdev is based on blk-mq so supports a number of request-queues same as the number of CPUs, while the previous cxlflash based on scsi-mod supports only a single request-queue that can be a major performance bottleneck.

The cxlbdev shows 2X~ IOPs than the previous cxlflash with fewer threads. (4KB requests).
