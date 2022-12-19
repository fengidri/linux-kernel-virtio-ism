/* SPDX-License-Identifier: GPL-2.0 */
/* Shared Memory Communications Direct over ISM devices (SMC-D)
 *
 * SMC-D for virtio-ism.
 */

#ifndef SMC_VISM_H
#define SMC_VISM_H

#define SMC_VISM_DMB_NUM	1920		/* max DMB limitation per device */
#define SMC_VISM_DMB_SIZE	1024 * 1024	/* 1 MiB */

struct smc_vism_systemeid {
        u8      seid_string[24];
        u8      serial_number[4];
        u8      type[4];
};

#if IS_ENABLED(CONFIG_VIRTIO_ISM)

int smc_vism_init(void) __init;
void smc_vism_exit(void);

#else

static inline int smc_vism_init(void)
{
	return 0;
}

static inline void smc_vism_exit(void) { }

#endif /* CONFIG_VIRTIO_ISM */
#endif /* SMC_VISM_H */
