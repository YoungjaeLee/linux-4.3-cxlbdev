# linux-4.3-cxlbdev

Linux kernel 4.3 with the updated cxlflash including a new light-weight and scalable block device driver, called cxlbdev, for POWER8's CAPI flash.

With the new cxlflash, we can access volumes via block device files named /dev/cxlbdevX as well as traditional scsi device files (e.g. /dev/sdX).

The cxlbdev is based on blk-mq so supports a number of request-queues same as the number of CPUs, while the previous cxlflash based on scsi-mod supports only a single request-queue that can be a major performance bottleneck.

On /dev/cxlbdevX, we can install any file system and it shows 2X~ IOPs than the previous cxlflash with fewer threads. (4KB requests).

Also, you can get vuid of a volume corresponded to /dev/cxlbdevX with a SCSI INQUIRY command.
ex)
$ sg_vpd -p 0x83 /dev/cxlbdev0
Device Identification VPD page:
  Addressed logical unit:
    designator type: T10 vendor identification,  code set: ASCII
      vendor id: IBM
      vendor specific: FlashSystem-9840029262c40292-0000-0002-000047
    designator type: NAA,  code set: Binary
      0x6005076a498b100a4800000002000047
  Target port:
    designator type: Relative target port,  code set: Binary
     transport: Fibre Channel Protocol for SCSI (FCP-4)
      Relative target port: 0xc00
