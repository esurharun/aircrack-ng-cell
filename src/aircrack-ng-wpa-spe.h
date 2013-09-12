#ifndef AIRCRACK_NG_WPA_SPE_H_
#define AIRCRACK_NG_WPA_SPE_H_

#include <stdint.h>

struct cell_spe_wpa_params {
	uint64_t keys[2];	/* Effective addresses of the key buffers */
	uint64_t pmks[2];	/* Effective addresses of the PMK buffers */
	uint64_t essid;		/* Effective address of the ESSID buffer */
	uint8_t essid_size;	/* Length of the ESSID */

	uint8_t __padding[7];
};

#endif /* AIRCRACK_NG_WPA_SPE_H_ */