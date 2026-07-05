/*	$OpenBSD$ */

/*
 * Copyright (c) 2026 Stefan Huber <stefan.huber@stusta.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ixlnvm - manage the NVM (Flash) of Intel 700-series controllers via ixl(4).
 *
 * Uses SIOCSIFNVMOPEN / SIOCSIFNVMCMD / SIOCSIFNVMCLOSE to hold an NVM
 * session across a sequence of admin-queue commands.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <net/if.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/*
 * AQ opcodes and NVM command flags (datasheet sections 3.4.10.x).
 * Mirrored from sys/dev/pci/if_ixl.c; the chip ABI is stable.
 */
#define IXL_AQ_OP_NVM_READ		0x0701
#define IXL_AQ_OP_NVM_ERASE		0x0702
#define IXL_AQ_OP_NVM_UPDATE		0x0703
#define IXL_AQ_OP_NVM_CFG_READ		0x0704

/*
 * NVM_UPDATE command_flags byte (byte 16 of the AQ descriptor).
 * Datasheet 3.4.10.3 documents bit 0 (LAST_COMMAND) and bit 7
 * (FLASH_ONLY) and marks bits 6:1 as "reserved".  In practice
 * (datasheet 3.4.5.6 prose, and Intel's i40e Linux driver
 * adminq_cmd.h) the chip recognises additional bits:
 */
#define IXL_AQ_NVM_LAST_COMMAND		(1 << 0)
#define IXL_AQ_NVM_PRESERVE_ALL		(1 << 1)
#define IXL_AQ_NVM_PRESERVE_SELECTED	(3 << 1)
#define IXL_AQ_NVM_REARRANGE_TO_FLAT	(1 << 5)
#define IXL_AQ_NVM_REARRANGE_TO_STRUCT	(1 << 6)
#define IXL_AQ_NVM_FLASH_ONLY		(1 << 7)

/* NVM Image module pointer, used by the flat update flow (3.4.5.6). */
#define IXL_NVM_MODULE_FLAT_IMAGE	0x42

#define IXL_NVM_CHUNK			IFNVM_CMD_MAX_BUFLEN

/* NVM_CFG_READ response buffer per datasheet 3.4.10.7 (6 bytes per element). */
#define IXL_NVM_CFG_ELEMENT_SIZE	6

/* Selected NVM header word offsets (datasheet 6.1.2 / 6.3 / table 6-2). */
#define NVM_W_CONTROL1			0x00
#define NVM_W_PCIE_ANALOG		0x03
#define NVM_W_PHY_ANALOG		0x04
#define NVM_W_OPTION_ROM		0x05
#define NVM_W_EMP_GLOBAL		0x09
#define NVM_W_EMP_IMAGE			0x0b
#define NVM_W_MANAGEABILITY		0x0e
#define NVM_W_EMP_SETTINGS		0x0f
#define NVM_W_PBA_BLOCK			0x16
#define NVM_W_BOOT_CONFIG		0x17
#define NVM_W_DEV_STARTER_VERSION	0x18	/* high=major, low=minor */
#define NVM_W_PERM_SAN_MAC		0x28
#define NVM_W_EETRACK_LO		0x2d
#define NVM_W_EETRACK_HI		0x2e
#define NVM_W_VPD			0x2f
#define NVM_W_PHY_SCRIPTS		0x3d
#define NVM_W_PCIE_ALT			0x3e
#define NVM_W_SW_CHECKSUM		0x3f
#define NVM_W_CONFIG_META		0x4d
#define NVM_W_EXT_25G_PHY		0x4f

/*
 * Sub-module offsets within the Boot Config Block (pointed to by word
 * 0x17).  The OEM version is two words starting at word 0x83.  This
 * specific offset isn't in the public datasheet section we have but is
 * documented in Intel's open-source i40e driver (i40e_type.h).
 */
#define BOOT_CFG_OEM_VER_OFFSET		0x83

/* Software checksum coverage (datasheet 6.1.4.1). */
#define NVM_SR_SIZE_WORDS		(64 * 1024 / 2)
#define NVM_SR_CHECKSUM_BASE		0xBABA
/*
 * Sizes used by the checksum-skipping logic.  Per datasheet table
 * 6-2: VPD area has max provisioned size 1024 bytes (512 words);
 * PCIe ALT Auto-load has max size 1024 bytes (512 words).  The
 * checksum routine skips the maximum range so it works regardless
 * of the module's actual size.
 */
#define NVM_CHECKSUM_VPD_SKIP_WORDS	512
#define NVM_CHECKSUM_PCIE_ALT_SKIP_WORDS 512

static __dead void	usage(void);
static int		cmd_dump(int, const char *, int, char **);
static int		cmd_show(int, const char *, int, char **);
static int		cmd_cfg_read(int, const char *, int, char **);
static int		cmd_selftest(int, const char *, int, char **);
static int		cmd_image_show(int, const char *, int, char **);
static int		cmd_image_diff(int, const char *, int, char **);
static int		cmd_match(int, const char *, int, char **);
static int		cmd_verify_checksum(int, const char *, int, char **);
static int		cmd_image_apply(int, const char *, int, char **);
static int		cmd_module_update(int, const char *, int, char **);
static int		cmd_scan(int, char **);

static void		nvm_open(int, const char *, uint8_t);
static void		nvm_close(int, const char *);
static void		nvm_read(int, const char *, uint32_t, uint16_t,
			    void *, int);
static void		nvm_read_full(int, const char *, uint32_t, size_t,
			    void *, const char *);
static int		nvm_erase_chunk(int, const char *, uint8_t,
			    uint32_t, uint16_t, uint8_t, int, uint16_t);

/*
 * Per datasheet 3.4.10.2 the NVM_Erase command's module_pointer
 * field must be the word address of a FREE PROVISIONING AREA
 * pointer, not the target module's pointer; using the target
 * module's pointer gets EPERM from the chip.  NVM_Update uses the
 * target module's pointer (3.4.5.4 / 3.4.5.5 step 2).
 *
 * FLOW_AUTH (3.4.5.5, RSA-signed):
 *   Option ROM, EMP Image          -> erase via 0x40 (1st free, 1160 KB)
 *   PCIe Analog, PHY Analog        -> erase via 0x46 (2nd free, 8 KB)
 *
 * FLOW_NONAUTH (3.4.5.4, no signature):
 *   EMP Global, Manageability,
 *   EMP Settings, PHY Cfg Scripts  -> erase via 0x46 (2nd free, 8 KB)
 *   Config Metadata,
 *   External 25G PHY Global        -> erase via 0x44 (3rd free, 128 KB)
 *
 * Modules share a free area sequentially (one update at a time);
 * the per-module max-size is the free area's capacity since each
 * module image in the source NVM is padded to that size.
 */
struct module_info {
	const char	*cli_name;
	const char	*display_name;
	uint16_t	 update_ptr_word;	/* NVM_Update module_pointer */
	uint16_t	 erase_ptr_word;	/* NVM_Erase  module_pointer */
	uint32_t	 max_size_bytes;
};

/*
 * EXPERIMENTAL.  Shadow-RAM modules (FLOW_SHADOW, datasheet 3.4.5.3).
 * Only reached via image-apply -s, which is not the supported upgrade
 * path: the chip's EMP regenerates most of these modules on its own
 * (verified -- a no-`-s` upgrade leaves POR/CORER/RO-PCIe-LCB/etc.
 * already matching the image), and direct shadow writes have proven
 * fragile and chip-state-dependent (intermittent EIO mid-batch).  The
 * production flow is Phase 1 (FLOW_NONAUTH) + header version + Phase 3
 * (FLOW_AUTH).  Kept for completeness / experimentation only.
 *
 * These live
 * inside the 64 KB shadow RAM; their pointer-word value (bit 15 clear)
 * is interpreted in word units within shadow RAM (byte_offset =
 * value * 2).  The module's first word holds its length in words,
 * exclusive of the length word itself (datasheet 6.1.5.1 / Table 6-4).
 *
 * Only firmware-dependent RW modules appear here.  The PFA list (PBA
 * 0x16, Boot Config 0x17, SAN MAC 0x28, VPD 0x2f, PXE 0x30/0x31, VLAN
 * 0x37) is preserved by NOT including those words.
 *
 * Writes use NVM_Update with module_pointer = 0; no NVM_Erase is
 * needed (the chip stages writes in the inactive bank and commits on
 * LAST_COMMAND).  Software must recompute word 0x3f checksum.
 */
struct shadow_module_info {
	const char	*cli_name;
	const char	*display_name;
	uint16_t	 pointer_word;
};

static const struct shadow_module_info shadow_module_table[] = {
	{ "auto-gen-ptrs", "Auto Generated Pointers", 0x07 },
	{ "pcir-autoload", "PCIR Auto-load",          0x08 },
	{ "por-autoload",  "POR Auto-load",           0x38 },
	{ "globr-autoload","GLOBR Auto-load",         0x3b },
	{ "corer-autoload","CORER Auto-load",         0x3c },
	{ "emp-sr",        "EMP SR Settings",         0x48 },
	{ "feature-cfg",   "Feature Configuration",   0x49 },
	{ "core-mem",      "Core Mem Config",         0x4a },
	{ "immediate",     "Immediate Fields",        0x4e },
	/*
	 * The *_Registers Auto-load modules (0x08, 0x38, 0x3b, 0x3c) are
	 * RW, length-prefixed (datasheet 6.1.5.1 Table 6-4), and mapped
	 * IN shadow RAM (Table 6-2: pointer type 0b = word units).  They
	 * are large (CORER ~43 KB) and frequently begin mid-page, so they
	 * must be written with write_shadow_region()'s page-boundary
	 * clipping (see its comment) or the chip returns EINVAL.
	 *
	 * Excluded by design (all RO per Table 6-2, datasheet 6.3.1.x):
	 *   RO PCIR Auto-load (0x06), RO PCIe LCB (0x0a), Reserved EMPR
	 *     Auto-load (0x3a), PCIe ALT Auto-load (0x3e),
	 *     SW-Data-Recovery (0x59), Preservation Rules (0x70).
	 *   PCIR-Data-Recovery (0x5a) -- RO per datasheet 6.3.1.78;
	 *     firmware-managed runtime recovery state (validity bits the
	 *     EMP sets), not image content.  The chip rejects direct
	 *     shadow writes to it (EPERM, AQ retval 0x0001).
	 *   0x0a likewise rejects direct writes (EPERM); the EMP
	 *     regenerates it from other modules.
	 */
};

static const struct module_info module_table[] = {
	/* FLOW_AUTH (3.4.5.5) */
	{ "option-rom",  "Option ROM",  NVM_W_OPTION_ROM,  0x40, 1160 * 1024 },
	{ "emp-image",   "EMP Image",   NVM_W_EMP_IMAGE,   0x40, 1160 * 1024 },
	{ "pcie-analog", "PCIe Analog", NVM_W_PCIE_ANALOG, 0x46,    8 * 1024 },
	{ "phy-analog",  "PHY Analog",  NVM_W_PHY_ANALOG,  0x46,    8 * 1024 },
	/* FLOW_NONAUTH (3.4.5.4) */
	{ "emp-global",   "EMP Global",         NVM_W_EMP_GLOBAL,   0x46,   8 * 1024 },
	{ "manageability","Manageability",      NVM_W_MANAGEABILITY,0x46,   8 * 1024 },
	{ "emp-settings", "EMP Settings",       NVM_W_EMP_SETTINGS, 0x46,   8 * 1024 },
	{ "phy-scripts",  "PHY Config Scripts", NVM_W_PHY_SCRIPTS,  0x46,   8 * 1024 },
	{ "config-meta",  "Configuration Meta", NVM_W_CONFIG_META,  0x44, 128 * 1024 },
	{ "ext-25g-phy",  "External 25G PHY",   NVM_W_EXT_25G_PHY,  0x44, 128 * 1024 },
};

static int		apply_module(int, const char *,
			    const struct module_info *, const uint8_t *,
			    uint32_t, uint32_t);
static int		cmd_shadow_update_single(int, const char *,
			    const struct shadow_module_info *,
			    const char *, int);
struct shadow_step {
	const struct shadow_module_info *sm;
	uint32_t	byte_start;
	uint32_t	byte_len;
	int		present;
};
static size_t		resolve_shadow_batch(const uint8_t *,
			    struct shadow_step *, size_t);
static void		apply_shadow_batch(int, const char *, const uint8_t *,
			    struct shadow_step *, size_t);
static void		apply_header_version(int, const char *,
			    const uint8_t *);

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ixlnvm [scan] [-c nvmupdate.cfg] [-q]\n"
	    "       ixlnvm -i ifname dump [-o file]\n"
	    "       ixlnvm -i ifname show\n"
	    "       ixlnvm -i ifname cfg-read feature_id\n"
	    "       ixlnvm -i ifname selftest [-y]\n"
	    "       ixlnvm -i ifname image-diff file\n"
	    "       ixlnvm image-show file\n"
	    "       ixlnvm [-i ifname] match -c nvmupdate.cfg [-e eepid]\n"
	    "       ixlnvm -i ifname verify-checksum\n"
	    "       ixlnvm -i ifname image-apply -f file.bin [-s] [-y]\n"
	    "                  (-s: also write shadow-RAM modules; "
	    "EXPERIMENTAL)\n"
	    "       ixlnvm -i ifname module-update -m module -f file.bin [-y]\n"
	    "         (outside-shadow: option-rom, emp-image, pcie-analog,\n"
	    "                  phy-analog, emp-global, manageability,\n"
	    "                  emp-settings, phy-scripts, config-meta,\n"
	    "                  ext-25g-phy)\n"
	    "         (shadow-RAM, experimental: auto-gen-ptrs,\n"
	    "                  pcir-autoload, por-autoload, globr-autoload,\n"
	    "                  corer-autoload, emp-sr, feature-cfg,\n"
	    "                  core-mem, immediate)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *ifname = NULL;
	int s, ch;

	while ((ch = getopt(argc, argv, "i:")) != -1) {
		switch (ch) {
		case 'i':
			ifname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* No subcommand and no -i: default to scanning the system. */
	if (argc < 1) {
		if (ifname != NULL)
			usage();
		return (cmd_scan(argc, argv));
	}

	/* scan: walk all ixl(4) interfaces against ./nvmupdate.cfg */
	if (strcmp(argv[0], "scan") == 0)
		return (cmd_scan(argc, argv));

	/* image-* subcommands operate on a file, not a card */
	if (strcmp(argv[0], "image-show") == 0)
		return (cmd_image_show(-1, NULL, argc, argv));

	/* match works with or without -i (offline -e mode or live -i mode) */
	if (strcmp(argv[0], "match") == 0) {
		int s2 = -1;
		if (ifname != NULL) {
			s2 = socket(AF_INET, SOCK_DGRAM, 0);
			if (s2 == -1)
				err(1, "socket");
		}
		return (cmd_match(s2, ifname, argc, argv));
	}

	if (ifname == NULL)
		usage();

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");

	if (strcmp(argv[0], "dump") == 0)
		return (cmd_dump(s, ifname, argc, argv));
	if (strcmp(argv[0], "show") == 0)
		return (cmd_show(s, ifname, argc, argv));
	if (strcmp(argv[0], "cfg-read") == 0)
		return (cmd_cfg_read(s, ifname, argc, argv));
	if (strcmp(argv[0], "selftest") == 0)
		return (cmd_selftest(s, ifname, argc, argv));
	if (strcmp(argv[0], "image-diff") == 0)
		return (cmd_image_diff(s, ifname, argc, argv));
	if (strcmp(argv[0], "verify-checksum") == 0)
		return (cmd_verify_checksum(s, ifname, argc, argv));
	if (strcmp(argv[0], "image-apply") == 0)
		return (cmd_image_apply(s, ifname, argc, argv));
	if (strcmp(argv[0], "module-update") == 0)
		return (cmd_module_update(s, ifname, argc, argv));

	usage();
}

/*
 * Tunnel wrappers around the SIOCSIFNVM* ioctls.
 *
 * They err()/errx() on failure rather than returning, since none of the
 * subcommands need finer-grained recovery for the minimal feature set.
 */

static void
nvm_open(int s, const char *ifname, uint8_t access)
{
	struct if_nvmsess ns;

	memset(&ns, 0, sizeof(ns));
	if (strlcpy(ns.ns_ifname, ifname, sizeof(ns.ns_ifname)) >=
	    sizeof(ns.ns_ifname))
		errx(1, "interface name too long");
	ns.ns_access = access;

	if (ioctl(s, SIOCSIFNVMOPEN, &ns) == -1) {
		if (errno == EPERM && access == IFNVM_ACCESS_WRITE) {
			errx(1, "%s: cannot open NVM write session: writing "
			    "firmware requires securelevel <= 0 (boot single-"
			    "user, at the local console); reads are allowed at "
			    "any securelevel", ifname);
		}
		err(1, "%s: open NVM session", ifname);
	}
}

static void
nvm_close(int s, const char *ifname)
{
	struct if_nvmsess ns;

	memset(&ns, 0, sizeof(ns));
	if (strlcpy(ns.ns_ifname, ifname, sizeof(ns.ns_ifname)) >=
	    sizeof(ns.ns_ifname))
		errx(1, "interface name too long");
	ns.ns_access = IFNVM_ACCESS_READ;	/* ignored by close */

	if (ioctl(s, SIOCSIFNVMCLOSE, &ns) == -1)
		warn("%s: close NVM session", ifname);
}

static void
nvm_read(int s, const char *ifname, uint32_t offset, uint16_t length,
    void *buf, int last)
{
	struct if_nvmcmd nc;

	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_READ;
	nc.nc_cmdflags = last ? IXL_AQ_NVM_LAST_COMMAND : 0;
	nc.nc_module = 0;	/* 0 = flat Flash */
	nc.nc_offset = offset;
	nc.nc_aqlen = length;	/* bytes to read */
	nc.nc_buflen = length;	/* same buffer size */
	nc.nc_buf = buf;

	if (ioctl(s, SIOCSIFNVMCMD, &nc) == -1)
		err(1, "%s: NVM read offset 0x%x length %u",
		    ifname, offset, length);
	if (nc.nc_aqlen != length)
		warnx("%s: short NVM read at 0x%x: requested %u, got %u",
		    ifname, offset, length, nc.nc_aqlen);
}

static int
cmd_dump(int s, const char *ifname, int argc, char **argv)
{
	const size_t total = IFNVM_MAX_WORDS * sizeof(uint16_t);
	const char *outpath = NULL;
	uint8_t *buf;
	int ch, ofd = STDOUT_FILENO;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			outpath = optarg;
			break;
		default:
			usage();
		}
	}

	buf = malloc(total);
	if (buf == NULL)
		err(1, "malloc");

	nvm_open(s, ifname, IFNVM_ACCESS_READ);
	nvm_read_full(s, ifname, 0, total, buf, NULL);
	nvm_close(s, ifname);

	if (outpath != NULL) {
		ofd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (ofd == -1)
			err(1, "open %s", outpath);
	} else if (isatty(STDOUT_FILENO))
		errx(1, "refusing to write binary NVM to a terminal; "
		    "redirect stdout or use -o");

	if (write(ofd, buf, total) != (ssize_t)total)
		err(1, "write");
	if (outpath != NULL)
		close(ofd);

	free(buf);
	return (0);
}

static int
cmd_show(int s, const char *ifname, int argc, char **argv)
{
	uint16_t words[64];	/* first 128 bytes of NVM */

	(void)argc;
	(void)argv;

	nvm_open(s, ifname, IFNVM_ACCESS_READ);
	nvm_read_full(s, ifname, 0, sizeof(words), words, NULL);
	nvm_close(s, ifname);

	printf("%s NVM header:\n", ifname);
	printf("  control word 1:        0x%04x\n", words[NVM_W_CONTROL1]);
	printf("  pointer PCIe Analog:   0x%04x\n", words[NVM_W_PCIE_ANALOG]);
	printf("  pointer PHY Analog:    0x%04x\n", words[NVM_W_PHY_ANALOG]);
	printf("  pointer Option ROM:    0x%04x\n", words[NVM_W_OPTION_ROM]);
	printf("  pointer EMP Image:     0x%04x\n", words[NVM_W_EMP_IMAGE]);
	printf("  pointer PBA Block:     0x%04x\n", words[NVM_W_PBA_BLOCK]);
	printf("  pointer Perm SAN MAC:  0x%04x\n", words[NVM_W_PERM_SAN_MAC]);
	printf("  pointer VPD:           0x%04x\n", words[NVM_W_VPD]);
	printf("  software checksum:     0x%04x\n", words[NVM_W_SW_CHECKSUM]);

	return (0);
}

/*
 * Issue a single NVM_CFG_READ (datasheet 3.4.10.4) for the given Feature_ID
 * and dump the 6-byte response. This is the smallest user-visible exercise
 * of the kernel's ARQ-event-driven async completion path.
 *
 * Example: feature 0xFFF1 is the link mode selection (1x40G/2x40G/4x10G).
 */
static int
cmd_cfg_read(int s, const char *ifname, int argc, char **argv)
{
	struct if_nvmcmd nc;
	uint8_t buf[IXL_NVM_CFG_ELEMENT_SIZE];
	unsigned long ul;
	uint16_t feature_id;
	char *end;

	if (argc != 2)
		usage();

	errno = 0;
	ul = strtoul(argv[1], &end, 0);
	if (errno != 0 || *end != '\0' || ul == 0 || ul > 0xffff)
		errx(1, "invalid feature_id: %s", argv[1]);
	feature_id = (uint16_t)ul;

	/*
	 * Datasheet 3.4.5.7 step 1 requires WRITE access on the NVM
	 * resource before issuing NVM_CFG_READ, even though no write
	 * happens.
	 */
	nvm_open(s, ifname, IFNVM_ACCESS_WRITE);

	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_CFG_READ;
	nc.nc_cmdflags = 0;	/* single feature, feature mode */
	nc.nc_module = 0;	/* reserved zero */
	nc.nc_offset = feature_id;	/* bytes 20-21 of AQ cmd */
	nc.nc_aqlen = 0;	/* element count filled in response */
	nc.nc_buflen = sizeof(buf);
	nc.nc_buf = buf;
	nc.nc_flags = IFNVM_CMD_F_WAIT_ARQ;
	nc.nc_timeout_ms = 5000;

	{
		int r = ioctl(s, SIOCSIFNVMCMD, &nc);
		int saved = errno;
		nvm_close(s, ifname);

		printf("feature 0x%04x: ioctl=%d errno=%d "
		    "AQ_retval=0x%04x elements=%u\n",
		    feature_id, r, r == -1 ? saved : 0,
		    nc.nc_retval, nc.nc_aqlen);
		printf("  raw response:      %02x %02x %02x %02x %02x %02x\n",
		    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
		if (r == -1)
			return (1);
	}

	printf("  echo Feature_ID:   0x%04x\n", buf[0] | (buf[1] << 8));
	printf("  Feature options:   0x%04x\n", buf[2] | (buf[3] << 8));
	printf("  Feature selection: 0x%04x\n", buf[4] | (buf[5] << 8));

	return (0);
}

/*
 * Exercise the write path and the kernel's ARQ event demultiplex.
 *
 * Reads word 0x16 (the PBA Block pointer in the NVM header; documented
 * as RW in datasheet 3.4.5.3), then writes the same value back via
 * NVM_UPDATE with the Last_Command bit set. The chip schedules a bank
 * swap and posts the completion on the ARQ; the kernel demultiplexes
 * that event back to our sleeping SIOCSIFNVMCMD. Finally, read the
 * word back and verify it matches.
 *
 * Identical-value write keeps the NVM software checksum (word 0x3F)
 * valid, so there is no semantic change to the card.
 */
#define SELFTEST_WORD_OFFSET	0x16		/* PBA Block pointer */
#define SELFTEST_BYTE_OFFSET	(SELFTEST_WORD_OFFSET * 2)

static void
cmd_one(int s, const char *ifname, struct if_nvmcmd *nc, const char *what)
{
	if (ioctl(s, SIOCSIFNVMCMD, nc) == -1)
		err(1, "%s: %s", ifname, what);
	if (nc->nc_retval != 0)
		errx(1, "%s: %s AQ retval=0x%04x", ifname, what, nc->nc_retval);
}

static int
cmd_selftest(int s, const char *ifname, int argc, char **argv)
{
	struct if_nvmcmd nc;
	uint16_t before, after;
	int confirm = 0, ch;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "y")) != -1) {
		switch (ch) {
		case 'y':
			confirm = 1;
			break;
		default:
			usage();
		}
	}

	if (!confirm) {
		fprintf(stderr,
"ixlnvm selftest reads NVM word 0x%02x (the PBA Block pointer, an RW\n"
"NVM header word per datasheet 3.4.5.3), then writes the same value\n"
"back via NVM_UPDATE with Last_Command set.  The chip triggers an\n"
"NVM bank swap.  Content is semantically unchanged (identical-value\n"
"write keeps the software checksum valid), but the bank-swap *is*\n"
"a write to Flash.\n"
"\n"
"Rerun with -y to confirm.\n",
		    SELFTEST_WORD_OFFSET);
		return (1);
	}

	nvm_open(s, ifname, IFNVM_ACCESS_WRITE);

	/* read the word */
	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_READ;
	nc.nc_cmdflags = IXL_AQ_NVM_LAST_COMMAND;
	nc.nc_offset = SELFTEST_BYTE_OFFSET;
	nc.nc_aqlen = sizeof(before);
	nc.nc_buflen = sizeof(before);
	nc.nc_buf = &before;
	cmd_one(s, ifname, &nc, "NVM_READ before");
	printf("read word 0x%02x: 0x%04x\n", SELFTEST_WORD_OFFSET, before);

	/* write it back; wait for ARQ completion */
	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_UPDATE;
	nc.nc_cmdflags = IXL_AQ_NVM_LAST_COMMAND;
	nc.nc_module = 0;	/* flat Flash (first 64 KB -> shadow RAM) */
	nc.nc_offset = SELFTEST_BYTE_OFFSET;
	nc.nc_aqlen = sizeof(before);
	nc.nc_buflen = sizeof(before);
	nc.nc_buf = &before;
	nc.nc_flags = IFNVM_CMD_F_WAIT_ARQ;
	nc.nc_timeout_ms = 30000;	/* 30 s; bank swap takes ~hundreds of ms */
	cmd_one(s, ifname, &nc, "NVM_UPDATE");
	printf("NVM_UPDATE completed (ARQ retval=0x%04x)\n", nc.nc_retval);

	/* read it back */
	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_READ;
	nc.nc_cmdflags = IXL_AQ_NVM_LAST_COMMAND;
	nc.nc_offset = SELFTEST_BYTE_OFFSET;
	nc.nc_aqlen = sizeof(after);
	nc.nc_buflen = sizeof(after);
	nc.nc_buf = &after;
	cmd_one(s, ifname, &nc, "NVM_READ after");

	nvm_close(s, ifname);

	if (after != before)
		errx(1, "selftest FAILED: read-back 0x%04x != written 0x%04x",
		    after, before);
	printf("selftest PASSED: word 0x%02x = 0x%04x (unchanged)\n",
	    SELFTEST_WORD_OFFSET, after);
	return (0);
}

/*
 * Read `length` bytes from the chip NVM at byte `offset` into `buf`,
 * chunking through IXL_NVM_CHUNK-sized NVM_READ commands.  Prints a
 * per-megabyte progress line to stderr.  Caller must hold an open
 * NVM session.
 */
static void
nvm_read_full(int s, const char *ifname, uint32_t offset, size_t length,
    void *buf, const char *label)
{
	uint8_t *p = buf;
	size_t done = 0, reported = 0;

	while (done < length) {
		size_t remaining = length - done;
		uint16_t chunk = (remaining > IXL_NVM_CHUNK) ?
		    IXL_NVM_CHUNK : (uint16_t)remaining;
		int last = (done + chunk >= length);

		nvm_read(s, ifname, offset + done, chunk, p + done, last);
		done += chunk;

		if (label != NULL &&
		    (done - reported >= 1024 * 1024 || done == length)) {
			fprintf(stderr, "  %s: %zu / %zu KB\r",
			    label, done / 1024, length / 1024);
			fflush(stderr);
			reported = done;
		}
	}
	if (label != NULL)
		fprintf(stderr, "\n");
}

/*
 * Intel NVM image parser.
 *
 * For 700-series controllers the .bin files in Intel's NVM update
 * package are byte-for-byte raw Flash dumps (4, 5.8, or 8 MB,
 * matching the chip's Flash size).  Module pointers in the NVM
 * header decode two ways depending on bit 15 (datasheet 6.1.2):
 *
 *   ptr & 0x8000 = 1  ->  module is OUTSIDE shadow RAM.
 *                         Value in bits 14:0 is a 4 KB sector index;
 *                         byte_offset = (ptr & 0x7fff) * 4096.
 *   ptr & 0x8000 = 0  ->  module is INSIDE shadow RAM.
 *                         Value is a word offset;
 *                         byte_offset = ptr * 2.
 *
 * Shadow-RAM modules begin with a size word per 6.1.5.1; outside-
 * shadow modules have their own size field in the free-area
 * mechanism and are not parsed here.  See datasheet table 6-2 for
 * the full header map.
 */

enum nvm_flow {
	FLOW_SHADOW,	/* RW modules mirrored to shadow RAM (3.4.5.3) */
	FLOW_NONAUTH,	/* non-authenticated modules outside shadow (3.4.5.4) */
	FLOW_AUTH,	/* authenticated modules outside shadow (3.4.5.5) */
	FLOW_FREE,	/* free provisioning area pointer */
};

static const char *flow_names[] = {
	[FLOW_SHADOW]	= "shadow",
	[FLOW_NONAUTH]	= "non-auth",
	[FLOW_AUTH]	= "auth",
	[FLOW_FREE]	= "free-area",
};

struct nvm_module {
	const char	*name;
	uint16_t	 ptr_word;	/* word offset in NVM header */
	enum nvm_flow	 flow;
};

/*
 * Module pointers per datasheet table 6-2 (NVM header map).
 * Words 0x60-0x67 are MinRRev values (data, not pointers).
 */
static const struct nvm_module nvm_modules[] = {
	{ "PCIe Analog",		0x03, FLOW_AUTH },
	{ "PHY Analog",			0x04, FLOW_AUTH },
	{ "Option ROM",			0x05, FLOW_AUTH },
	{ "RO PCIR Auto-load",		0x06, FLOW_SHADOW },
	{ "Auto Generated Pointers",	0x07, FLOW_SHADOW },
	{ "PCIR Auto-load",		0x08, FLOW_SHADOW },
	{ "EMP Global",			0x09, FLOW_NONAUTH },
	{ "RO PCIe LCB",		0x0a, FLOW_SHADOW },
	{ "EMP Image",			0x0b, FLOW_AUTH },
	{ "Manageability",		0x0e, FLOW_NONAUTH },
	{ "EMP Settings",		0x0f, FLOW_NONAUTH },
	{ "PBA Block",			0x16, FLOW_SHADOW },
	{ "Boot Configuration",		0x17, FLOW_SHADOW },
	{ "Permanent SAN MAC",		0x28, FLOW_SHADOW },
	{ "VPD",			0x2f, FLOW_SHADOW },
	{ "PXE Setup Options",		0x30, FLOW_SHADOW },
	{ "PXE Custom Options",		0x31, FLOW_SHADOW },
	{ "VLAN Configuration",		0x37, FLOW_SHADOW },
	{ "POR Auto-load",		0x38, FLOW_SHADOW },
	{ "Reserved EMPR Auto-load",	0x3a, FLOW_SHADOW },
	{ "GLOBR Auto-load",		0x3b, FLOW_SHADOW },
	{ "CORER Auto-load",		0x3c, FLOW_SHADOW },
	{ "PHY Config Scripts",		0x3d, FLOW_NONAUTH },
	{ "PCIe ALT Auto-load",		0x3e, FLOW_SHADOW },
	{ "1st free area (1160KB)",	0x40, FLOW_FREE },
	{ "NVM Image / 4th free area",	0x42, FLOW_FREE },
	{ "3rd free area (16KB)",	0x44, FLOW_FREE },
	{ "2nd free area (8KB)",	0x46, FLOW_FREE },
	{ "EMP SR Settings",		0x48, FLOW_SHADOW },
	{ "Feature Configuration",	0x49, FLOW_SHADOW },
	{ "Core Mem Config",		0x4a, FLOW_SHADOW },
	{ "FCoE Scratch Pad",		0x4b, FLOW_NONAUTH },
	{ "Configuration Metadata",	0x4d, FLOW_NONAUTH },
	{ "Immediate Fields",		0x4e, FLOW_SHADOW },
	{ "External 25G PHY Global",	0x4f, FLOW_NONAUTH },
	{ "SW-Data-Recovery",		0x59, FLOW_NONAUTH },
	{ "PCIR-Data-Recovery",		0x5a, FLOW_SHADOW },
	{ "Preservation Rules",		0x70, FLOW_NONAUTH },
	{ "6th free area (4KB)",	0x71, FLOW_FREE },
};

static inline uint16_t
nvm_word(const uint8_t *img, uint32_t word_offset)
{
	uint32_t b = word_offset * 2;
	return (img[b] | ((uint16_t)img[b + 1] << 8));
}

/*
 * Decode a header pointer value to a byte offset in NVM.
 * Returns (uint32_t)-1 if the pointer is unset (0 or 0xffff).
 */
static inline uint32_t
nvm_ptr_to_byte(uint16_t ptr)
{
	if (ptr == 0x0000 || ptr == 0xffff)
		return ((uint32_t)-1);
	if (ptr & 0x8000)
		return ((uint32_t)(ptr & 0x7fff) * 4096);
	return ((uint32_t)ptr * 2);
}

/*
 * Compute the expected software checksum for an image, per datasheet
 * 6.1.4.1.  The covered range is the 64 KB shadow RAM area; the VPD
 * area and the PCIe ALT Auto-load module are skipped, as is the
 * checksum word itself.  Returns 0xBABA - sum (mod 0x10000).
 *
 * The buffer must be at least NVM_SR_SIZE_WORDS * 2 bytes long.
 */
static uint16_t
nvm_compute_checksum(const uint8_t *img)
{
	uint16_t sum = 0;
	uint16_t vpd_ptr = nvm_word(img, NVM_W_VPD);
	uint16_t pcie_alt_ptr = nvm_word(img, NVM_W_PCIE_ALT);
	uint32_t vpd_lo = 0, vpd_hi = 0;
	uint32_t alt_lo = 0, alt_hi = 0;
	uint32_t w;

	/* Only pointers inside shadow RAM (bit 15 clear) define a skip. */
	if (vpd_ptr != 0xffff && (vpd_ptr & 0x8000) == 0) {
		vpd_lo = vpd_ptr;
		vpd_hi = vpd_lo + NVM_CHECKSUM_VPD_SKIP_WORDS;
	}
	if (pcie_alt_ptr != 0xffff && (pcie_alt_ptr & 0x8000) == 0) {
		alt_lo = pcie_alt_ptr;
		alt_hi = alt_lo + NVM_CHECKSUM_PCIE_ALT_SKIP_WORDS;
	}

	for (w = 0; w < NVM_SR_SIZE_WORDS; w++) {
		if (w == NVM_W_SW_CHECKSUM)
			continue;
		if (vpd_hi != 0 && w >= vpd_lo && w < vpd_hi)
			continue;
		if (alt_hi != 0 && w >= alt_lo && w < alt_hi)
			continue;
		sum += nvm_word(img, w);
	}
	return ((uint16_t)(NVM_SR_CHECKSUM_BASE - sum));
}

static int
cmd_image_show(int s, const char *ifname, int argc, char **argv)
{
	const char *path;
	int fd;
	struct stat st;
	uint8_t *img;
	uint16_t ctrl1, checksum, pba_ptr;
	uint16_t expected_checksum;
	size_t i;

	(void)s;
	(void)ifname;

	if (argc != 2)
		usage();
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open %s", path);
	if (fstat(fd, &st) == -1)
		err(1, "fstat %s", path);
	if (st.st_size < 0x80 || st.st_size > 16 * 1024 * 1024)
		errx(1, "%s: implausible NVM image size %lld bytes",
		    path, (long long)st.st_size);

	img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (img == MAP_FAILED)
		err(1, "mmap %s", path);
	close(fd);

	ctrl1    = nvm_word(img, NVM_W_CONTROL1);
	checksum = nvm_word(img, NVM_W_SW_CHECKSUM);
	pba_ptr  = nvm_word(img, NVM_W_PBA_BLOCK);
	expected_checksum = nvm_compute_checksum(img);

	printf("image: %s\n", path);
	printf("  size:               %lld bytes (%lld KB)\n",
	    (long long)st.st_size, (long long)st.st_size / 1024);
	printf("  control word 1:     0x%04x\n", ctrl1);
	printf("  software checksum:  0x%04x (word 0x3f) %s\n",
	    checksum,
	    checksum == expected_checksum ? "[ok]" : "[MISMATCH]");
	if (checksum != expected_checksum)
		printf("  expected checksum:  0x%04x\n", expected_checksum);

	/* Firmware version (datasheet table 6-2 word 0x18, "Dev Starter").
	 * Encoding: bits 15:12 = major, bits 7:0 = minor (hex-displayed).
	 * So word 0x9057 prints as "9.57". */
	{
		uint16_t devstart = nvm_word(img, NVM_W_DEV_STARTER_VERSION);
		uint8_t major = (devstart >> 12) & 0xf;
		uint8_t minor = devstart & 0xff;

		printf("  firmware version:   %x.%02x (word 0x18 = 0x%04x)\n",
		    major, minor, devstart);
	}

	/* Version metadata (datasheet table 6-2, words 0x29-0x2e). */
	{
		uint16_t map_ver = nvm_word(img, 0x29);
		uint16_t nvm_img_ver = nvm_word(img, 0x2a);
		uint16_t nvm_struct_ver = nvm_word(img, 0x2b);
		uint32_t eetrack = (uint32_t)nvm_word(img, NVM_W_EETRACK_LO) |
		    ((uint32_t)nvm_word(img, NVM_W_EETRACK_HI) << 16);

		printf("  map version:        0x%04x (word 0x29)\n", map_ver);
		printf("  NVM image version:  0x%04x (word 0x2a)\n",
		    nvm_img_ver);
		printf("  NVM structure ver:  0x%04x (word 0x2b)\n",
		    nvm_struct_ver);
		printf("  EETRACK ID:         0x%08x (words 0x2d-0x2e)%s\n",
		    eetrack,
		    eetrack == 0xffffffff ? " [OEM image]" : "");
	}

	/*
	 * OEM version is two words inside the Boot Config Block at
	 * offset BOOT_CFG_OEM_VER_OFFSET.  It is only meaningful for
	 * OEM images (EETRACK ID == 0xffffffff); for retail images
	 * it stores combo image version info instead.
	 */
	{
		uint16_t boot_cfg = nvm_word(img, NVM_W_BOOT_CONFIG);
		uint32_t eetrack = (uint32_t)nvm_word(img, NVM_W_EETRACK_LO) |
		    ((uint32_t)nvm_word(img, NVM_W_EETRACK_HI) << 16);

		if (boot_cfg != 0x0000 && boot_cfg != 0xffff &&
		    (boot_cfg & 0x8000) == 0) {
			uint32_t off = (uint32_t)boot_cfg +
			    BOOT_CFG_OEM_VER_OFFSET;
			if (((uint32_t)off + 1) * 2 <= (uint32_t)st.st_size) {
				uint16_t oem_hi = nvm_word(img, off);
				uint16_t oem_lo = nvm_word(img, off + 1);
				uint32_t oem_ver =
				    ((uint32_t)oem_hi << 16) | oem_lo;
				const char *label =
				    eetrack == 0xffffffff ?
				    "OEM version (raw):" :
				    "combo image ver:   ";
				printf("  %s 0x%08x (boot-config + 0x%x)\n",
				    label, oem_ver, BOOT_CFG_OEM_VER_OFFSET);
			}
		}
	}

	/*
	 * Decode the PBA string if present.  A pointer of 0x0000 or
	 * 0xffff means "no PBA in this image" (common in OEM-generic
	 * images that aren't tied to a specific board).
	 */
	if (pba_ptr != 0xffff && pba_ptr != 0x0000) {
		uint32_t pba_off = (uint32_t)pba_ptr * 2;
		if (pba_off + 2 <= (uint32_t)st.st_size) {
			uint16_t pba_size = nvm_word(img, pba_ptr);
			uint32_t data_off = pba_off + 2;
			uint32_t data_len = (pba_size > 1 ?
			    (uint32_t)(pba_size - 1) * 2 : 0);
			char pba[64];

			if (data_len > sizeof(pba) - 1)
				data_len = sizeof(pba) - 1;
			if (data_off + data_len <= (uint32_t)st.st_size) {
				memcpy(pba, &img[data_off], data_len);
				pba[data_len] = '\0';
				printf("  PBA:                %s\n", pba);
			}
		}
	}

	printf("\n%-28s %-5s %-6s %-12s %-8s %s\n",
	    "module", "word", "ptr", "byte offset", "units", "flow");
	printf("%-28s %-5s %-6s %-12s %-8s %s\n",
	    "----------------------------",
	    "----", "----", "-----------", "-----", "--------");
	for (i = 0; i < nitems(nvm_modules); i++) {
		const struct nvm_module *m = &nvm_modules[i];
		uint16_t ptr = nvm_word(img, m->ptr_word);
		uint32_t byte_off = nvm_ptr_to_byte(ptr);
		const char *units;
		char loc[20];

		if (byte_off == (uint32_t)-1) {
			snprintf(loc, sizeof(loc), "(unset)");
			units = "";
		} else if (byte_off < (uint32_t)st.st_size) {
			snprintf(loc, sizeof(loc), "0x%08x", byte_off);
			units = (ptr & 0x8000) ? "4K sect" : "word";
		} else {
			snprintf(loc, sizeof(loc), "(out of range)");
			units = (ptr & 0x8000) ? "4K sect" : "word";
		}

		printf("%-28s 0x%02x  0x%04x %-12s %-8s %s\n",
		    m->name, m->ptr_word, ptr, loc, units,
		    flow_names[m->flow]);
	}

	munmap(img, st.st_size);
	return (0);
}

/* Look up an outside-shadow module's max size from module_table[]. */
static uint32_t
module_max_size(uint16_t ptr_word)
{
	size_t i;

	for (i = 0; i < nitems(module_table); i++) {
		if (module_table[i].update_ptr_word == ptr_word)
			return (module_table[i].max_size_bytes);
	}
	return (0);
}

/*
 * Preserved Field Area: card-identity modules that an image apply
 * deliberately leaves untouched, so they are EXPECTED to differ from
 * the image and must not be flagged as a failed update.
 */
static int
module_is_pfa(uint16_t ptr_word)
{
	switch (ptr_word) {
	case NVM_W_PBA_BLOCK:		/* 0x16 */
	case NVM_W_BOOT_CONFIG:		/* 0x17 */
	case NVM_W_PERM_SAN_MAC:	/* 0x28 */
	case NVM_W_VPD:			/* 0x2f */
	case 0x30:			/* PXE Setup Options */
	case 0x31:			/* PXE Custom Options */
	case 0x37:			/* VLAN Configuration */
		return (1);
	}
	return (0);
}

/*
 * Chip-managed modules: register auto-load tables and data-recovery
 * blocks that the EMP firmware populates with computed/runtime state
 * (register address/value snapshots, recovery validity bits).  A
 * byte-for-byte match against the static image is neither expected nor
 * required: empirically these modules differ from the .bin by the same
 * bytes after a flash by Intel's own tool as after ours -- the differ
 * signature is identical across firmware versions and flashing tools.
 * They are reported as MANAGED and excluded from the pass/fail tally.
 */
static int
module_is_managed(uint16_t ptr_word)
{
	switch (ptr_word) {
	case 0x06:	/* RO PCIR Auto-load */
	case 0x08:	/* PCIR Auto-load */
	case 0x38:	/* POR Auto-load */
	case 0x3a:	/* Reserved EMPR Auto-load */
	case 0x3b:	/* GLOBR Auto-load */
	case 0x3c:	/* CORER Auto-load */
	case 0x59:	/* SW-Data-Recovery */
	case 0x5a:	/* PCIR-Data-Recovery */
		return (1);
	}
	return (0);
}

/*
 * Module-aware verify (formerly a raw byte diff).  For each module the
 * tool knows how to update, resolve the module's location from the
 * CHIP's own header pointer (NOT the image's -- after a per-module
 * update + bank swap the chip stores the module at a different physical
 * offset than the factory image), read the module's bytes from the
 * chip, and compare them to the image's copy of that module.
 *
 * This is the correct post-update oracle: a raw whole-flash byte diff
 * is meaningless here because the dual-bank layout, free-area module
 * placement, and preserved PFA all legitimately differ between the
 * factory image and a per-module-updated chip.
 *
 * Shadow-RAM modules (bit 15 clear) live in the first 64 KB and are
 * length-prefixed (first word = length in words).  Outside-shadow
 * modules (bit 15 set) are sized from module_table[]'s max_size_bytes.
 * PFA modules are reported but not compared.
 */
static int
cmd_image_diff(int s, const char *ifname, int argc, char **argv)
{
	const size_t sr_bytes = NVM_SR_SIZE_WORDS * sizeof(uint16_t);
	const char *path;
	int fd;
	struct stat st;
	uint8_t *img;
	uint8_t shadow[NVM_SR_SIZE_WORDS * 2];
	size_t i, n_match = 0, n_differ = 0, n_pfa = 0, n_absent = 0;
	size_t n_skip = 0, n_managed = 0;

	if (argc != 2)
		usage();
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open %s", path);
	if (fstat(fd, &st) == -1)
		err(1, "fstat %s", path);
	if (st.st_size < (off_t)sr_bytes || st.st_size > 16 * 1024 * 1024)
		errx(1, "%s: implausible NVM image size %lld",
		    path, (long long)st.st_size);
	img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (img == MAP_FAILED)
		err(1, "mmap %s", path);
	close(fd);

	fprintf(stderr, "reading chip shadow RAM\n");
	nvm_open(s, ifname, IFNVM_ACCESS_READ);
	nvm_read_full(s, ifname, 0, sizeof(shadow), shadow, NULL);

	printf("image: %s\n", path);
	printf("chip:  %s\n", ifname);
	printf("\nper-module comparison (chip pointer vs image content):\n");

	for (i = 0; i < nitems(nvm_modules); i++) {
		const struct nvm_module *mod = &nvm_modules[i];
		uint16_t img_ptr, chip_ptr;
		uint32_t img_off, chip_off, len = 0;
		uint8_t *chipbuf, *imgbuf;
		uint32_t ndiff = 0, k, first = 0;
		int managed;

		if (mod->flow == FLOW_FREE)
			continue;

		if (module_is_pfa(mod->ptr_word)) {
			printf("  %-26s %-9s PRESERVED (card identity)\n",
			    mod->name, flow_names[mod->flow]);
			n_pfa++;
			continue;
		}

		managed = module_is_managed(mod->ptr_word);

		img_ptr = nvm_word(img, mod->ptr_word);
		chip_ptr = nvm_word(shadow, mod->ptr_word);

		if ((img_ptr == 0x0000 || img_ptr == 0xffff) &&
		    (chip_ptr == 0x0000 || chip_ptr == 0xffff)) {
			n_absent++;
			continue;	/* absent on both sides; stay quiet */
		}
		if (managed) {
			/*
			 * Chip-managed module: report MANAGED regardless of
			 * whether it happens to resolve/match.  Differences
			 * here are expected (firmware-populated) and do not
			 * count toward pass/fail.  Fall through to attempt
			 * the comparison only to annotate match/differ.
			 */
		}
		if (img_ptr == 0x0000 || img_ptr == 0xffff) {
			if (managed) {
				printf("  %-26s %-9s MANAGED    "
				    "(chip-populated)\n", mod->name,
				    flow_names[mod->flow]);
				n_managed++;
				continue;
			}
			printf("  %-26s %-9s ABSENT in image (chip has it)\n",
			    mod->name, flow_names[mod->flow]);
			n_absent++;
			continue;
		}
		if (chip_ptr == 0x0000 || chip_ptr == 0xffff) {
			if (managed) {
				printf("  %-26s %-9s MANAGED    "
				    "(chip-populated)\n", mod->name,
				    flow_names[mod->flow]);
				n_managed++;
				continue;
			}
			printf("  %-26s %-9s ABSENT on chip (image has it)\n",
			    mod->name, flow_names[mod->flow]);
			n_differ++;
			continue;
		}

		/* Determine the module length. */
		if ((img_ptr & 0x8000) == 0) {
			/* shadow-RAM module: first word = length in words */
			uint16_t lw = nvm_word(img, img_ptr);
			if (lw == 0 || lw == 0xffff) {
				if (managed) {
					printf("  %-26s %-9s MANAGED    "
					    "(chip-populated)\n", mod->name,
					    flow_names[mod->flow]);
					n_managed++;
					continue;
				}
				printf("  %-26s %-9s SKIP (no length in "
				    "image)\n", mod->name,
				    flow_names[mod->flow]);
				n_skip++;
				continue;
			}
			len = ((uint32_t)lw + 1) * 2;
		} else {
			/* outside-shadow: size from module_table[] */
			len = module_max_size(mod->ptr_word);
			if (len == 0) {
				if (managed) {
					printf("  %-26s %-9s MANAGED    "
					    "(chip-populated)\n", mod->name,
					    flow_names[mod->flow]);
					n_managed++;
					continue;
				}
				printf("  %-26s %-9s SKIP (size unknown)\n",
				    mod->name, flow_names[mod->flow]);
				n_skip++;
				continue;
			}
		}

		img_off = nvm_ptr_to_byte(img_ptr);
		chip_off = nvm_ptr_to_byte(chip_ptr);
		if (img_off == (uint32_t)-1 ||
		    (uint64_t)img_off + len > (uint64_t)st.st_size) {
			if (managed) {
				printf("  %-26s %-9s MANAGED    "
				    "(chip-populated)\n", mod->name,
				    flow_names[mod->flow]);
				n_managed++;
				continue;
			}
			printf("  %-26s %-9s SKIP (image range out of "
			    "bounds)\n", mod->name, flow_names[mod->flow]);
			n_skip++;
			continue;
		}

		/* Read the chip's copy from its own pointer location. */
		chipbuf = malloc(len);
		if (chipbuf == NULL)
			err(1, "malloc %u", len);
		if ((img_ptr & 0x8000) == 0 &&
		    (uint64_t)chip_off + len <= sizeof(shadow)) {
			/* shadow module already in our 64 KB buffer */
			memcpy(chipbuf, shadow + chip_off, len);
		} else {
			nvm_read_full(s, ifname, chip_off, len, chipbuf,
			    len > 65536 ? mod->name : NULL);
		}

		imgbuf = img + img_off;
		for (k = 0; k < len; k++) {
			if (chipbuf[k] != imgbuf[k]) {
				if (ndiff == 0)
					first = k;
				ndiff++;
			}
		}
		free(chipbuf);

		if (managed) {
			if (ndiff == 0)
				printf("  %-26s %-9s MANAGED    "
				    "(%u bytes, matches)\n", mod->name,
				    flow_names[mod->flow], len);
			else
				printf("  %-26s %-9s MANAGED    "
				    "(%u bytes, %u differ, chip-populated)\n",
				    mod->name, flow_names[mod->flow], len,
				    ndiff);
			n_managed++;
		} else if (ndiff == 0) {
			printf("  %-26s %-9s MATCH      (%u bytes)\n",
			    mod->name, flow_names[mod->flow], len);
			n_match++;
		} else {
			printf("  %-26s %-9s DIFFER     (%u bytes, %u "
			    "differ, first +0x%x)\n", mod->name,
			    flow_names[mod->flow], len, ndiff, first);
			n_differ++;
		}
	}

	nvm_close(s, ifname);

	printf("\nsummary: %zu match, %zu differ, %zu managed, "
	    "%zu preserved, %zu absent, %zu skipped\n",
	    n_match, n_differ, n_managed, n_pfa, n_absent, n_skip);
	printf("note: 'managed' modules are chip-populated register/recovery\n");
	printf("  state; they differ from the static image by design and are\n");
	printf("  not a sign of an incomplete update.\n");
	if (n_differ > 0)
		printf("note: 'differ' on a module the image carries means "
		    "that module is not yet updated on the chip.\n");

	munmap(img, st.st_size);
	return (n_differ > 0 ? 1 : 0);
}

/*
 * Parser for Intel's nvmupdate.cfg manifest.  The file is plain
 * text, one device record per BEGIN DEVICE / END DEVICE block,
 * with KEY: value lines inside.  We capture the fields we need
 * for image matching: vendor/device IDs, the .bin image filename,
 * the EEPID (= EETRACK ID this image upgrades TO), and the
 * REPLACES list (EETRACK IDs this image can upgrade FROM).
 */

struct nvmcfg_entry {
	char		 devicename[64];
	uint16_t	 vendor;
	uint16_t	 device;
	char		 nvm_image[256];
	char		 orom_image[256];
	uint32_t	 eepid;
	uint32_t	*replaces;
	size_t		 nreplaces;
	int		 reset_power;	/* 1 = POWER, 0 = REBOOT/unset */
};

struct nvmcfg {
	struct nvmcfg_entry	*entries;
	size_t			 nentries;
	size_t			 capacity;
};

static void
nvmcfg_free(struct nvmcfg *cfg)
{
	size_t i;

	if (cfg == NULL)
		return;
	for (i = 0; i < cfg->nentries; i++)
		free(cfg->entries[i].replaces);
	free(cfg->entries);
	free(cfg);
}

/* Trim leading whitespace; return start of trimmed string. */
static char *
ltrim(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return (s);
}

/* Trim trailing whitespace + \r\n in place. */
static void
rtrim(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
	    s[n - 1] == '\r' || s[n - 1] == '\n'))
		s[--n] = '\0';
}

/* Match "KEY:" at start of line; returns pointer to value (trimmed) or NULL. */
static char *
keyval(char *line, const char *key)
{
	size_t klen = strlen(key);

	if (strncmp(line, key, klen) != 0)
		return (NULL);
	if (line[klen] != ':')
		return (NULL);
	return (ltrim(line + klen + 1));
}

static void
nvmcfg_parse_replaces(struct nvmcfg_entry *e, char *value)
{
	char *tok, *save;
	size_t cap = 4;

	e->replaces = malloc(cap * sizeof(uint32_t));
	if (e->replaces == NULL)
		err(1, "malloc");

	for (tok = strtok_r(value, " \t", &save); tok != NULL;
	    tok = strtok_r(NULL, " \t", &save)) {
		uint32_t v;
		char *end;

		errno = 0;
		v = (uint32_t)strtoul(tok, &end, 16);
		if (errno != 0 || *end != '\0')
			continue;
		if (e->nreplaces == cap) {
			cap *= 2;
			e->replaces = reallocarray(e->replaces, cap,
			    sizeof(uint32_t));
			if (e->replaces == NULL)
				err(1, "reallocarray");
		}
		e->replaces[e->nreplaces++] = v;
	}
}

static struct nvmcfg *
nvmcfg_load(const char *path)
{
	FILE *fp;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	struct nvmcfg *cfg;
	struct nvmcfg_entry *e = NULL;
	int in_block = 0;

	fp = fopen(path, "r");
	if (fp == NULL)
		err(1, "open %s", path);

	cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL)
		err(1, "calloc");

	while ((len = getline(&line, &cap, fp)) != -1) {
		char *p = ltrim(line);
		char *v;

		rtrim(p);
		if (*p == '\0' || *p == ';')
			continue;

		if (strcmp(p, "BEGIN DEVICE") == 0) {
			if (cfg->nentries == cfg->capacity) {
				size_t newcap = cfg->capacity ?
				    cfg->capacity * 2 : 16;
				cfg->entries = reallocarray(cfg->entries,
				    newcap, sizeof(*cfg->entries));
				if (cfg->entries == NULL)
					err(1, "reallocarray");
				cfg->capacity = newcap;
			}
			e = &cfg->entries[cfg->nentries];
			memset(e, 0, sizeof(*e));
			in_block = 1;
			continue;
		}
		if (strcmp(p, "END DEVICE") == 0) {
			if (in_block && e != NULL)
				cfg->nentries++;
			in_block = 0;
			e = NULL;
			continue;
		}
		if (!in_block || e == NULL)
			continue;

		if ((v = keyval(p, "DEVICENAME")) != NULL)
			strlcpy(e->devicename, v, sizeof(e->devicename));
		else if ((v = keyval(p, "VENDOR")) != NULL)
			e->vendor = (uint16_t)strtoul(v, NULL, 16);
		else if ((v = keyval(p, "DEVICE")) != NULL)
			e->device = (uint16_t)strtoul(v, NULL, 16);
		else if ((v = keyval(p, "NVM IMAGE")) != NULL)
			strlcpy(e->nvm_image, v, sizeof(e->nvm_image));
		else if ((v = keyval(p, "OROM IMAGE")) != NULL)
			strlcpy(e->orom_image, v, sizeof(e->orom_image));
		else if ((v = keyval(p, "EEPID")) != NULL)
			e->eepid = (uint32_t)strtoul(v, NULL, 16);
		else if ((v = keyval(p, "REPLACES")) != NULL)
			nvmcfg_parse_replaces(e, v);
		else if ((v = keyval(p, "RESET TYPE")) != NULL)
			e->reset_power = (strcmp(v, "POWER") == 0);
	}

	free(line);
	fclose(fp);
	return (cfg);
}

/*
 * Search the cfg for an entry whose EEPID equals the chip's EETRACK ID
 * (meaning the chip is already at that image), or whose REPLACES list
 * contains it (meaning this image can upgrade the chip).  Returns NULL
 * if no match.  Direct EEPID match takes precedence.
 */
static const struct nvmcfg_entry *
nvmcfg_find(const struct nvmcfg *cfg, uint32_t eepid, int *via_replaces)
{
	size_t i, j;

	*via_replaces = 0;
	/* Exact match first */
	for (i = 0; i < cfg->nentries; i++) {
		if (cfg->entries[i].eepid == eepid)
			return (&cfg->entries[i]);
	}
	/* Then REPLACES */
	for (i = 0; i < cfg->nentries; i++) {
		for (j = 0; j < cfg->entries[i].nreplaces; j++) {
			if (cfg->entries[i].replaces[j] == eepid) {
				*via_replaces = 1;
				return (&cfg->entries[i]);
			}
		}
	}
	return (NULL);
}

/*
 * Read the chip's EETRACK ID via a short NVM read (4 bytes from
 * byte offset 0x5a = word 0x2d).  Holds an open NVM session.
 */
static uint32_t
chip_read_eetrack(int s, const char *ifname)
{
	uint16_t words[2];

	nvm_open(s, ifname, IFNVM_ACCESS_READ);
	nvm_read(s, ifname, NVM_W_EETRACK_LO * 2, sizeof(words), words, 1);
	nvm_close(s, ifname);
	return ((uint32_t)words[0] | ((uint32_t)words[1] << 16));
}

static int
cmd_match(int s, const char *ifname, int argc, char **argv)
{
	const char *cfgpath = NULL;
	const char *eepid_str = NULL;
	uint32_t eepid;
	const struct nvmcfg_entry *e;
	struct nvmcfg *cfg;
	int via_replaces, ch;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "c:e:")) != -1) {
		switch (ch) {
		case 'c':
			cfgpath = optarg;
			break;
		case 'e':
			eepid_str = optarg;
			break;
		default:
			usage();
		}
	}

	if (cfgpath == NULL)
		usage();
	if (eepid_str == NULL && ifname == NULL) {
		warnx("specify -e <eepid> or -i <ifname>");
		usage();
	}

	if (eepid_str != NULL) {
		char *end;
		errno = 0;
		eepid = (uint32_t)strtoul(eepid_str, &end, 16);
		if (errno != 0 || *end != '\0')
			errx(1, "invalid EEPID: %s", eepid_str);
	} else {
		eepid = chip_read_eetrack(s, ifname);
		printf("%s EETRACK ID: 0x%08x\n", ifname, eepid);
	}

	cfg = nvmcfg_load(cfgpath);
	if (cfg->nentries == 0)
		errx(1, "%s: no devices parsed", cfgpath);

	e = nvmcfg_find(cfg, eepid, &via_replaces);
	if (e == NULL) {
		printf("No match for EEPID 0x%08x in %s (%zu entries scanned)\n",
		    eepid, cfgpath, cfg->nentries);
		nvmcfg_free(cfg);
		return (1);
	}

	printf("matched: %s (%04x:%04x)\n",
	    e->devicename, e->vendor, e->device);
	printf("  NVM image:   %s\n", e->nvm_image);
	if (e->orom_image[0] != '\0')
		printf("  OROM image:  %s\n", e->orom_image);
	printf("  EEPID:       0x%08x%s\n", e->eepid,
	    via_replaces ? " (chip needs upgrade to this)" :
	    " (chip is already at this image)");
	printf("  reset type:  %s\n", e->reset_power ? "POWER" : "REBOOT");
	if (e->nreplaces > 0) {
		size_t i;
		printf("  replaces:   ");
		for (i = 0; i < e->nreplaces; i++)
			printf(" 0x%08x", e->replaces[i]);
		printf("\n");
	}

	nvmcfg_free(cfg);
	return (0);
}

/*
 * Enumerate ixl(4) interfaces via getifaddrs(3), deduplicate, and
 * return a malloc'd array of strdup'd names.  Caller frees with
 * free_ixl_interfaces().
 */
static int
list_ixl_interfaces(char ***out_names, size_t *out_n)
{
	struct ifaddrs *ifap = NULL, *ifa;
	char **names = NULL;
	size_t n = 0, cap = 0;

	if (getifaddrs(&ifap) != 0)
		return (-1);
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		size_t i;

		if (strncmp(ifa->ifa_name, "ixl", 3) != 0)
			continue;
		if (!isdigit((unsigned char)ifa->ifa_name[3]))
			continue;
		for (i = 0; i < n; i++) {
			if (strcmp(names[i], ifa->ifa_name) == 0)
				break;
		}
		if (i < n)
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 8;
			names = reallocarray(names, cap, sizeof(*names));
			if (names == NULL)
				err(1, "reallocarray");
		}
		names[n] = strdup(ifa->ifa_name);
		if (names[n] == NULL)
			err(1, "strdup");
		n++;
	}
	freeifaddrs(ifap);

	/* simple insertion sort so output is deterministic */
	{
		size_t i, j;
		for (i = 1; i < n; i++) {
			char *cur = names[i];
			for (j = i; j > 0 &&
			    strcmp(names[j - 1], cur) > 0; j--)
				names[j] = names[j - 1];
			names[j] = cur;
		}
	}
	*out_names = names;
	*out_n = n;
	return (0);
}

static void
free_ixl_interfaces(char **names, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(names[i]);
	free(names);
}

/*
 * Tolerant NVM session open: returns 0 on success, -errno on failure.
 * Used by scan paths that need to skip interfaces that fail to open
 * (e.g. another process already holds the session).
 */
static int
nvm_try_open(int s, const char *ifname, uint8_t access)
{
	struct if_nvmsess ns;

	memset(&ns, 0, sizeof(ns));
	if (strlcpy(ns.ns_ifname, ifname, sizeof(ns.ns_ifname)) >=
	    sizeof(ns.ns_ifname))
		return (-ENAMETOOLONG);
	ns.ns_access = access;
	if (ioctl(s, SIOCSIFNVMOPEN, &ns) == -1)
		return (-errno);
	return (0);
}

/*
 * Read the NVM image version word (0x18) and EETRACK ID (0x2d / 0x2e)
 * from the chip's NVM, and the running EMP firmware version via the
 * SIOCGIFFWVER ioctl (cached at driver attach from AQ Get Version).
 * Holds its own short-lived read session for the NVM reads.  Returns
 * 0 on success or -errno on failure.
 */
static int
read_chip_versions(int s, const char *ifname, uint16_t *devstart,
    uint32_t *eetrack, struct if_fwver *fwver)
{
	uint16_t buf[2];
	int rv;

	rv = nvm_try_open(s, ifname, IFNVM_ACCESS_READ);
	if (rv != 0)
		return (rv);

	nvm_read(s, ifname, NVM_W_DEV_STARTER_VERSION * 2,
	    sizeof(*devstart), devstart, 0);
	nvm_read(s, ifname, NVM_W_EETRACK_LO * 2, sizeof(buf), buf, 1);
	nvm_close(s, ifname);

	*eetrack = (uint32_t)buf[0] | ((uint32_t)buf[1] << 16);

	memset(fwver, 0, sizeof(*fwver));
	if (strlcpy(fwver->fv_ifname, ifname, sizeof(fwver->fv_ifname)) >=
	    sizeof(fwver->fv_ifname))
		return (-ENAMETOOLONG);
	if (ioctl(s, SIOCGIFFWVER, fwver) == -1)
		return (-errno);
	return (0);
}

/*
 * Per-card record (one entry per physical PCIe controller).  Multiple
 * port interfaces of the same chip share one entry, with ports[]
 * holding the interface names (sorted).
 */
struct card_entry {
	uint16_t	 pci_bus;
	uint16_t	 pci_dev;	/* function differs per port */
	uint16_t	 devstart;	/* NVM image version word */
	uint32_t	 eetrack;
	struct if_fwver fwver;		/* from first port read */
	char		**ports;
	size_t		 nports;
	size_t		 ports_cap;
	int		 err;		/* -errno from version read; 0 OK */
	const struct nvmcfg_entry *match;
	int		 via_replaces;
	const char	*status;
	const char	*bin;
	const char	*reset;
};

static void
card_add_port(struct card_entry *c, const char *ifname)
{
	if (c->nports == c->ports_cap) {
		c->ports_cap = c->ports_cap ? c->ports_cap * 2 : 4;
		c->ports = reallocarray(c->ports, c->ports_cap,
		    sizeof(*c->ports));
		if (c->ports == NULL)
			err(1, "reallocarray");
	}
	c->ports[c->nports] = strdup(ifname);
	if (c->ports[c->nports] == NULL)
		err(1, "strdup");
	c->nports++;
}

/*
 * scan / default subcommand: walk every ixl(4) interface, read its
 * firmware + EETRACK + PCIe location, group ports of the same physical
 * card together (matching on PCIe bus:dev; function differs per port),
 * and (if a nvmupdate.cfg is found in the working directory or supplied
 * via -c) match each card against the manifest.  Per card we print a
 * single status block listing all of its ports and, where an upgrade is
 * possible and the .bin file exists, the exact command to apply.
 *
 * Output is human-readable by default; -q switches to a stable
 * one-line-per-card machine format with comma-separated port names:
 *
 *   ports  nvm-ver  fw-ver  eetrack  status  bin  reset
 *
 * Status values: CURRENT, UPGRADE, NO_MATCH, MISSING_BIN, NO_CFG, ERROR.
 */
static int
cmd_scan(int argc, char **argv)
{
	const char *cfgpath = "nvmupdate.cfg";
	int quiet = 0, ch, s;
	char **ifs = NULL;
	size_t nifs = 0, i, j;
	struct nvmcfg *cfg = NULL;
	struct stat st;
	int n_upgrade = 0, n_current = 0, n_nomatch = 0;
	int n_missing = 0, n_error = 0;
	struct card_entry *cards = NULL;
	size_t ncards = 0, cards_cap = 0;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "c:q")) != -1) {
		switch (ch) {
		case 'c':
			cfgpath = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage();
		}
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");

	if (list_ixl_interfaces(&ifs, &nifs) != 0)
		err(1, "getifaddrs");

	if (stat(cfgpath, &st) == 0)
		cfg = nvmcfg_load(cfgpath);

	if (!quiet) {
		printf("scanning ixl(4) interfaces");
		if (cfg != NULL)
			printf(" against %s (%zu entries)",
			    cfgpath, cfg->nentries);
		else
			printf("; %s not found, inventory only",
			    cfgpath);
		printf("\n\n");
	}

	if (nifs == 0) {
		if (!quiet)
			printf("no ixl(4) interfaces found.\n");
		goto out;
	}

	/*
	 * First pass: read versions and PCIe location for each
	 * interface, then attach it to (or create) its card_entry.
	 */
	for (i = 0; i < nifs; i++) {
		struct if_fwver fwver;
		uint16_t devstart = 0;
		uint32_t eetrack = 0;
		struct card_entry *c = NULL;
		int rv;

		rv = read_chip_versions(s, ifs[i], &devstart, &eetrack,
		    &fwver);
		if (rv != 0) {
			/* Card entry keyed by ifname only when read fails;
			 * we can't group it. */
			if (ncards == cards_cap) {
				cards_cap = cards_cap ? cards_cap * 2 : 8;
				cards = reallocarray(cards, cards_cap,
				    sizeof(*cards));
				if (cards == NULL)
					err(1, "reallocarray");
			}
			memset(&cards[ncards], 0, sizeof(cards[ncards]));
			cards[ncards].err = rv;
			card_add_port(&cards[ncards], ifs[i]);
			ncards++;
			n_error++;
			continue;
		}

		for (j = 0; j < ncards; j++) {
			if (cards[j].err != 0)
				continue;
			if (cards[j].pci_bus == fwver.fv_pci_bus &&
			    cards[j].pci_dev == fwver.fv_pci_dev) {
				c = &cards[j];
				break;
			}
		}
		if (c != NULL) {
			card_add_port(c, ifs[i]);
			continue;
		}

		if (ncards == cards_cap) {
			cards_cap = cards_cap ? cards_cap * 2 : 8;
			cards = reallocarray(cards, cards_cap,
			    sizeof(*cards));
			if (cards == NULL)
				err(1, "reallocarray");
		}
		c = &cards[ncards++];
		memset(c, 0, sizeof(*c));
		c->pci_bus = fwver.fv_pci_bus;
		c->pci_dev = fwver.fv_pci_dev;
		c->devstart = devstart;
		c->eetrack = eetrack;
		c->fwver = fwver;
		card_add_port(c, ifs[i]);

		if (cfg != NULL)
			c->match = nvmcfg_find(cfg, eetrack,
			    &c->via_replaces);
		if (cfg == NULL) {
			c->status = "NO_CFG";
			c->bin = "-";
			c->reset = "-";
		} else if (c->match == NULL) {
			c->status = "NO_MATCH";
			c->bin = "-";
			c->reset = "-";
			n_nomatch++;
		} else if (!c->via_replaces) {
			c->status = "CURRENT";
			c->bin = c->match->nvm_image;
			c->reset = c->match->reset_power ? "POWER" :
			    "REBOOT";
			n_current++;
		} else {
			c->bin = c->match->nvm_image;
			c->reset = c->match->reset_power ? "POWER" :
			    "REBOOT";
			if (stat(c->match->nvm_image, &st) == 0) {
				c->status = "UPGRADE";
				n_upgrade++;
			} else {
				c->status = "MISSING_BIN";
				n_missing++;
			}
		}
	}

	/* Second pass: print per-card. */
	for (i = 0; i < ncards; i++) {
		struct card_entry *c = &cards[i];
		char joined[256];
		size_t off = 0;

		joined[0] = '\0';
		for (j = 0; j < c->nports; j++) {
			int n = snprintf(joined + off, sizeof(joined) - off,
			    "%s%s", j ? "," : "", c->ports[j]);
			if (n < 0 || (size_t)n >= sizeof(joined) - off)
				break;
			off += n;
		}

		if (c->err != 0) {
			if (quiet) {
				printf("%s -.-- -.-.----- ---------- "
				    "ERROR - -\n", joined);
			} else {
				printf("%s  ERROR  could not read NVM (%s)\n",
				    joined, strerror(-c->err));
			}
			continue;
		}

		if (quiet) {
			printf("%s %x.%02x %u.%u.%05u 0x%08x %s %s %s\n",
			    joined,
			    (c->devstart >> 12) & 0xf, c->devstart & 0xff,
			    c->fwver.fv_fw_major, c->fwver.fv_fw_minor,
			    c->fwver.fv_fw_build, c->eetrack, c->status,
			    c->bin, c->reset);
			continue;
		}

		printf("%s  (pci %u:%u, %zu port%s)\n", joined,
		    c->pci_bus, c->pci_dev, c->nports,
		    c->nports == 1 ? "" : "s");
		printf("           nvm %x.%02x  fw %u.%u.%05u  "
		    "eetrack 0x%08x  %s\n",
		    (c->devstart >> 12) & 0xf, c->devstart & 0xff,
		    c->fwver.fv_fw_major, c->fwver.fv_fw_minor,
		    c->fwver.fv_fw_build, c->eetrack, c->status);
		if (strcmp(c->status, "UPGRADE") == 0) {
			printf("           upgrade to %s (reset %s)\n",
			    c->match->nvm_image, c->reset);
			printf("           apply:  ixlnvm -i %s "
			    "image-apply -f %s -y\n",
			    c->ports[0], c->match->nvm_image);
		} else if (strcmp(c->status, "MISSING_BIN") == 0) {
			printf("           upgrade to %s available but "
			    "%s not found in working directory\n",
			    c->match->nvm_image, c->match->nvm_image);
		} else if (strcmp(c->status, "CURRENT") == 0) {
			printf("           at target image %s\n",
			    c->match->nvm_image);
		}
	}

	/* free card_entry contents */
	for (i = 0; i < ncards; i++) {
		for (j = 0; j < cards[i].nports; j++)
			free(cards[i].ports[j]);
		free(cards[i].ports);
	}
	free(cards);

	if (!quiet) {
		printf("\nsummary: %d upgrade, %d current, %d no-match, "
		    "%d missing-bin, %d error\n",
		    n_upgrade, n_current, n_nomatch, n_missing, n_error);
	}

out:
	if (cfg != NULL)
		nvmcfg_free(cfg);
	free_ixl_interfaces(ifs, nifs);
	close(s);
	return (n_upgrade > 0 ? 0 : (n_error > 0 ? 2 : 0));
}

/*
 * Read the chip's shadow RAM (first 64 KB) and verify the software
 * checksum at word 0x3f against the value our nvm_compute_checksum()
 * derives from the same data.  A mismatch on a live, working card
 * would mean either the chip is in an inconsistent NVM state (unlikely
 * if the driver attaches normally) or our checksum algorithm is wrong.
 */
static int
cmd_verify_checksum(int s, const char *ifname, int argc, char **argv)
{
	const size_t bytes = NVM_SR_SIZE_WORDS * sizeof(uint16_t);
	uint8_t *buf;
	uint16_t actual, expected;
	int match;

	(void)argc;
	(void)argv;

	buf = malloc(bytes);
	if (buf == NULL)
		err(1, "malloc");

	nvm_open(s, ifname, IFNVM_ACCESS_READ);
	nvm_read_full(s, ifname, 0, bytes, buf, "shadow RAM");
	nvm_close(s, ifname);

	actual = (uint16_t)buf[NVM_W_SW_CHECKSUM * 2] |
	    ((uint16_t)buf[NVM_W_SW_CHECKSUM * 2 + 1] << 8);
	expected = nvm_compute_checksum(buf);
	match = (actual == expected);

	printf("%s shadow RAM software checksum:\n", ifname);
	printf("  stored at word 0x3f: 0x%04x\n", actual);
	printf("  computed:            0x%04x\n", expected);
	printf("  result:              %s\n", match ? "match" : "MISMATCH");

	free(buf);
	return (match ? 0 : 1);
}

/*
 * Issue an NVM_Update AQ command via the kernel tunnel, with the
 * given module_pointer, offset, length, command_flags, and buffer
 * direction (k -> chip).  The kernel auto-sets the FE flag on
 * non-LAST commands.  Returns the AQ retval the chip reported.
 *
 * If wait_arq is set, the kernel will sleep for the chip's async
 * ARQ completion event before returning.  Used for the final
 * command of an update sequence (LAST_COMMAND set).
 */
static int
nvm_update_chunk(int s, const char *ifname, uint8_t module_pointer,
    uint32_t byte_offset, uint16_t length, uint8_t cmdflags,
    const void *data, int wait_arq, uint16_t timeout_ms)
{
	struct if_nvmcmd nc;

	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_UPDATE;
	nc.nc_module = module_pointer;
	nc.nc_cmdflags = cmdflags;
	nc.nc_offset = byte_offset;
	nc.nc_aqlen = length;
	nc.nc_buflen = length;
	nc.nc_buf = (void *)(uintptr_t)data;
	if (wait_arq) {
		nc.nc_flags = IFNVM_CMD_F_WAIT_ARQ;
		nc.nc_timeout_ms = timeout_ms;
	}

	if (ioctl(s, SIOCSIFNVMCMD, &nc) == -1)
		err(1, "%s: NVM_UPDATE module=%02x offset=0x%x", ifname,
		    module_pointer, byte_offset);
	return (nc.nc_retval);
}

/*
 * Apply an Intel NVM image via the flat NVM update flow (datasheet
 * 3.4.5.6).  Stages the image's first 64 KB into the chip's NVM
 * Image area via NVM_Update commands with module_pointer=0x42,
 * then issues a final command with LAST_COMMAND | REARRANGE_TO_FLAT
 * and waits for the chip's bank-swap completion on the ARQ.
 *
 * The chip's firmware handles preservation of card identity (MAC,
 * VPD, PBA, etc.) via the PFA mechanism, and recomputes the
 * software checksum.  We do not need to compute either ourselves.
 *
 * Without -y, this command is a dry run: validates the image and
 * prints the staging plan but does not touch the chip.
 */
static int
cmd_image_apply(int s, const char *ifname, int argc, char **argv)
{
	const size_t sr_bytes = NVM_SR_SIZE_WORDS * sizeof(uint16_t);
	const char *path = NULL;
	int confirm = 0, do_shadow = 0, ch, fd;
	struct stat st;
	uint8_t *img;
	uint16_t stored_cs, expected_cs, devstart;
	uint32_t img_eetrack;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "f:sy")) != -1) {
		switch (ch) {
		case 'f':
			path = optarg;
			break;
		case 's':
			do_shadow = 1;
			break;
		case 'y':
			confirm = 1;
			break;
		default:
			usage();
		}
	}
	if (path == NULL)
		usage();

	/* load image */
	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open %s", path);
	if (fstat(fd, &st) == -1)
		err(1, "fstat %s", path);
	if (st.st_size < (off_t)sr_bytes)
		errx(1, "%s: image smaller than 64 KB shadow RAM", path);
	img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (img == MAP_FAILED)
		err(1, "mmap %s", path);
	close(fd);

	/* validate image checksum */
	stored_cs = nvm_word(img, NVM_W_SW_CHECKSUM);
	expected_cs = nvm_compute_checksum(img);
	if (stored_cs != expected_cs) {
		errx(1, "%s: software checksum invalid (stored 0x%04x, "
		    "computed 0x%04x); refusing to apply",
		    path, stored_cs, expected_cs);
	}
	devstart = nvm_word(img, NVM_W_DEV_STARTER_VERSION);
	img_eetrack = (uint32_t)nvm_word(img, NVM_W_EETRACK_LO) |
	    ((uint32_t)nvm_word(img, NVM_W_EETRACK_HI) << 16);

	printf("image:      %s\n", path);
	printf("  size:       %lld bytes\n", (long long)st.st_size);
	printf("  firmware:   %x.%02x\n",
	    (devstart >> 12) & 0xf, devstart & 0xff);
	printf("  EETRACK ID: 0x%08x\n", img_eetrack);
	printf("  checksum:   0x%04x [ok]\n", stored_cs);

	/*
	 * Read chip EETRACK ID for comparison, but only if we're going
	 * to write -- the chip may not exist for an offline dry-run.
	 */
	if (confirm) {
		uint32_t chip_eetrack = chip_read_eetrack(s, ifname);

		printf("chip:       %s\n", ifname);
		printf("  EETRACK ID: 0x%08x", chip_eetrack);
		if (chip_eetrack == img_eetrack)
			printf(" (already at this image)\n");
		else
			printf(" (different)\n");
	}

	/*
	 * Apply order:
	 *   Phase 1: FLOW_NONAUTH modules (datasheet 3.4.5.4)
	 *   Phase 2: FLOW_SHADOW modules (datasheet 3.4.5.3, batched)
	 *   Phase 3: FLOW_AUTH modules (datasheet 3.4.5.5),
	 *            EMP Image last because the chip stops servicing the
	 *            admin queue between its LAST_COMMAND and reboot.
	 *
	 * Modules with a 0xffff/0x0000 pointer in the image (or absent
	 * shadow-RAM data) are skipped rather than failing the apply --
	 * card-specific image variants typically leave slots empty.
	 */
	struct apply_step {
		const char	*cli_name;
		uint32_t	 src_byte;
		uint32_t	 total_bytes;
		const struct module_info *m;
		int		 present;
	};
	struct apply_step steps[] = {
		/* Phase 1: FLOW_NONAUTH */
		{ "emp-global",    0, 0, NULL, 0 },
		{ "manageability", 0, 0, NULL, 0 },
		{ "emp-settings",  0, 0, NULL, 0 },
		{ "phy-scripts",   0, 0, NULL, 0 },
		{ "config-meta",   0, 0, NULL, 0 },
		{ "ext-25g-phy",   0, 0, NULL, 0 },
		/* Phase 3: FLOW_AUTH (emp-image last) */
		{ "pcie-analog",   0, 0, NULL, 0 },
		{ "phy-analog",    0, 0, NULL, 0 },
		{ "option-rom",    0, 0, NULL, 0 },
		{ "emp-image",     0, 0, NULL, 0 },
	};
	const size_t nonauth_n = 6;	/* indices 0..5 = Phase 1 */
	size_t i, j, nsteps = nitems(steps);
	struct shadow_step sst[nitems(shadow_module_table)];
	size_t shadow_present;

	/* resolve each step against the module_table[] and image */
	for (i = 0; i < nsteps; i++) {
		const struct module_info *m = NULL;
		uint16_t ptr;

		for (j = 0; j < nitems(module_table); j++) {
			if (strcmp(steps[i].cli_name,
			    module_table[j].cli_name) == 0) {
				m = &module_table[j];
				break;
			}
		}
		if (m == NULL)
			errx(1, "internal: module '%s' missing from table",
			    steps[i].cli_name);
		steps[i].m = m;

		ptr = nvm_word(img, m->update_ptr_word);
		if (ptr == 0xffff || ptr == 0x0000) {
			/* module not in this image -- skip */
			continue;
		}
		if ((ptr & 0x8000) == 0) {
			errx(1, "image word 0x%02x = 0x%04x: not an "
			    "outside-shadow pointer for %s",
			    m->update_ptr_word, ptr, m->display_name);
		}
		steps[i].src_byte = (uint32_t)(ptr & 0x7fff) * 4096;
		steps[i].total_bytes = m->max_size_bytes;
		if ((uint64_t)steps[i].src_byte + steps[i].total_bytes >
		    (uint64_t)st.st_size) {
			errx(1, "%s would extend past image (need %u bytes "
			    "at 0x%x, image is %lld bytes)", m->display_name,
			    steps[i].total_bytes, steps[i].src_byte,
			    (long long)st.st_size);
		}
		steps[i].present = 1;
	}

	shadow_present = resolve_shadow_batch(img, sst, nitems(sst));

	printf("\nplan: per-module update across three phases\n");
	printf("\n  Phase 1: FLOW_NONAUTH (datasheet 3.4.5.4)\n");
	for (i = 0; i < nonauth_n; i++) {
		const struct module_info *m = steps[i].m;
		size_t n = steps[i].total_bytes / 4096;

		if (!steps[i].present) {
			printf("    %-20s  (not in image, skipped)\n",
			    m->display_name);
			continue;
		}
		printf("    %-20s  src 0x%06x  %4zu sectors "
		    "(update 0x%02x, erase 0x%02x)\n",
		    m->display_name, steps[i].src_byte, n,
		    m->update_ptr_word, m->erase_ptr_word);
	}
	printf("\n  Phase 2: FLOW_SHADOW (datasheet 3.4.5.3, batched) "
	    "[EXPERIMENTAL]\n");
	if (!do_shadow) {
		printf("    DISABLED (default).  -s enables it, but the EMP\n");
		printf("    regenerates these modules and direct writes are\n");
		printf("    fragile; the supported flow does not use -s.\n");
	} else {
		for (i = 0; i < nitems(sst); i++) {
			if (!sst[i].present) {
				printf("    %-26s (not in image, skipped)\n",
				    sst[i].sm->display_name);
				continue;
			}
			printf("    %-26s 0x%05x  %u bytes\n",
			    sst[i].sm->display_name, sst[i].byte_start,
			    sst[i].byte_len);
		}
		if (shadow_present > 0)
			printf("    + 1 checksum word write [LAST]\n");
	}
	printf("\n  Phase 2b: NVM header version words (always on)\n");
	printf("    word 0x18 (DEV_STARTER_VERSION) <- image\n");
	printf("    words 0x2d/0x2e (EETRACK ID)    <- image\n");
	printf("    word 0x3f (software checksum)   <- recomputed [LAST]\n");

	printf("\n  Phase 3: FLOW_AUTH (datasheet 3.4.5.5)\n");
	for (i = nonauth_n; i < nsteps; i++) {
		const struct module_info *m = steps[i].m;
		size_t n = steps[i].total_bytes / 4096;
		int is_emp_last = (strcmp(steps[i].cli_name,
		    "emp-image") == 0);

		if (!steps[i].present) {
			printf("    %-20s  (not in image, skipped)\n",
			    m->display_name);
			continue;
		}
		printf("    %-20s  src 0x%06x  %4zu sectors "
		    "(update 0x%02x, erase 0x%02x)%s\n",
		    m->display_name, steps[i].src_byte, n,
		    m->update_ptr_word, m->erase_ptr_word,
		    is_emp_last ? "  <- EMP last" : "");
	}
	printf("\n  FLOW_AUTH modules: chip verifies RSA-2048 signature on\n");
	printf("    LAST_COMMAND; mismatch keeps the old module active.\n");
	printf("  FLOW_NONAUTH/FLOW_SHADOW: written without signature check.\n");
	printf("  reboot required after completion.\n");

	if (!confirm) {
		printf("\n*** dry run.  Re-run with -y to actually apply.\n");
		munmap(img, st.st_size);
		return (0);
	}

	printf("\n*** writing chip NVM.  DO NOT INTERRUPT.\n");

	nvm_open(s, ifname, IFNVM_ACCESS_WRITE);

	/* Phase 1: FLOW_NONAUTH */
	for (i = 0; i < nonauth_n; i++) {
		if (!steps[i].present)
			continue;
		(void)apply_module(s, ifname, steps[i].m, img,
		    steps[i].src_byte, steps[i].total_bytes);
	}

	/* Phase 2: FLOW_SHADOW (batched, opt-in via -s) */
	if (do_shadow && shadow_present > 0)
		apply_shadow_batch(s, ifname, img, sst, nitems(sst));

	/* Phase 2b: NVM header version words (DEV_STARTER_VERSION,
	 * EETRACK, checksum).  Always on -- pure metadata. */
	apply_header_version(s, ifname, img);

	/* Phase 3: FLOW_AUTH (EMP Image last) */
	for (i = nonauth_n; i < nsteps; i++) {
		if (!steps[i].present)
			continue;
		(void)apply_module(s, ifname, steps[i].m, img,
		    steps[i].src_byte, steps[i].total_bytes);
	}

	/*
	 * EMP Image was the final step.  The chip is now in the
	 * "EMP swap pending" state and won't ack further AQ commands,
	 * so nvm_close() may warn().  That's expected.
	 */
	nvm_close(s, ifname);
	munmap(img, st.st_size);

	printf("\nImage apply completed.  Reboot the system to load the "
	    "new firmware.\n");
	return (0);
}

/*
 * Issue an NVM_Erase AQ command via the kernel tunnel.  Datasheet
 * 3.4.10.2 specifies that for NVM_Erase BOTH the length (bytes
 * 18-19) AND the offset (bytes 20-23) are in 4 KB sector units --
 * unlike NVM_Update, where the offset is in bytes.  Caller must
 * hold an open NVM session.
 */
static int
nvm_erase_chunk(int s, const char *ifname, uint8_t module_pointer,
    uint32_t sector_index, uint16_t sector_count, uint8_t cmdflags,
    int wait_arq, uint16_t timeout_ms)
{
	struct if_nvmcmd nc;

	memset(&nc, 0, sizeof(nc));
	if (strlcpy(nc.nc_ifname, ifname, sizeof(nc.nc_ifname)) >=
	    sizeof(nc.nc_ifname))
		errx(1, "interface name too long");
	nc.nc_opcode = IXL_AQ_OP_NVM_ERASE;
	nc.nc_module = module_pointer;
	nc.nc_cmdflags = cmdflags;
	nc.nc_offset = sector_index;
	nc.nc_aqlen = sector_count;
	nc.nc_buflen = 0;
	nc.nc_buf = NULL;
	if (wait_arq) {
		nc.nc_flags = IFNVM_CMD_F_WAIT_ARQ;
		nc.nc_timeout_ms = timeout_ms;
	}

	if (ioctl(s, SIOCSIFNVMCMD, &nc) == -1)
		err(1, "%s: NVM_ERASE module=%02x sector=%u", ifname,
		    module_pointer, sector_index);
	return (nc.nc_retval);
}

/*
 * Update one of the authenticated outside-shadow modules: Option ROM,
 * EMP Image, PCIe Analog, or PHY Analog (datasheet 3.4.5.5).
 *
 * The chip verifies the module's RSA-2048 signature before swapping
 * pointers; signing is Intel's job, we just push the bytes.  Per the
 * datasheet, the entire module area (1160 KB for OROM/EMP image,
 * 8 KB for the analog modules) must always be written, sector by
 * sector, with each sector erased immediately before its write.
 */
static int
cmd_module_update(int s, const char *ifname, int argc, char **argv)
{
	const char *path = NULL;
	const char *modname = NULL;
	const struct module_info *m = NULL;
	int confirm = 0, ch, fd;
	struct stat st;
	uint8_t *img;
	uint16_t ptr;
	uint32_t src_byte, total_bytes;
	size_t i, n_sectors;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "m:f:y")) != -1) {
		switch (ch) {
		case 'm':
			modname = optarg;
			break;
		case 'f':
			path = optarg;
			break;
		case 'y':
			confirm = 1;
			break;
		default:
			usage();
		}
	}
	if (path == NULL || modname == NULL)
		usage();

	/* Dispatch to the shadow-RAM update flow if the module name is
	 * a shadow-RAM module (datasheet 3.4.5.3). */
	for (i = 0; i < nitems(shadow_module_table); i++) {
		if (strcmp(modname, shadow_module_table[i].cli_name) == 0)
			return (cmd_shadow_update_single(s, ifname,
			    &shadow_module_table[i], path, confirm));
	}

	for (i = 0; i < nitems(module_table); i++) {
		if (strcmp(modname, module_table[i].cli_name) == 0) {
			m = &module_table[i];
			break;
		}
	}
	if (m == NULL)
		errx(1, "module '%s' is not supported "
		    "(try: option-rom, emp-image, pcie-analog, phy-analog, "
		    "emp-global, manageability, emp-settings, phy-scripts, "
		    "config-meta, ext-25g-phy, "
		    "auto-gen-ptrs, pcir-autoload, por-autoload, "
		    "globr-autoload, corer-autoload, emp-sr, feature-cfg, "
		    "core-mem, immediate)",
		    modname);

	/* load image */
	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open %s", path);
	if (fstat(fd, &st) == -1)
		err(1, "fstat %s", path);
	img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (img == MAP_FAILED)
		err(1, "mmap %s", path);
	close(fd);

	/* locate the source module in the image */
	ptr = nvm_word(img, m->update_ptr_word);
	if (ptr == 0xffff || ptr == 0x0000)
		errx(1, "%s is not present in this image "
		    "(word 0x%02x = 0x%04x); the image likely targets a "
		    "different card variant", m->display_name,
		    m->update_ptr_word, ptr);
	if ((ptr & 0x8000) == 0)
		errx(1, "image word 0x%02x = 0x%04x: not an outside-shadow "
		    "pointer for %s", m->update_ptr_word, ptr,
		    m->display_name);

	src_byte = (uint32_t)(ptr & 0x7fff) * 4096;
	total_bytes = m->max_size_bytes;
	if ((uint64_t)src_byte + total_bytes > (uint64_t)st.st_size)
		errx(1, "%s would extend past image (need %u bytes at 0x%x, "
		    "image is %lld bytes)", m->display_name, total_bytes,
		    src_byte, (long long)st.st_size);
	n_sectors = total_bytes / 4096;

	printf("%s update plan:\n", m->display_name);
	printf("  source:        %s offset 0x%x (%u KB)\n",
	    path, src_byte, total_bytes / 1024);
	printf("  Update target: word 0x%02x (module pointer)\n",
	    m->update_ptr_word);
	printf("  Erase target:  word 0x%02x (free provisioning area)\n",
	    m->erase_ptr_word);
	printf("  sectors:       %zu x 4 KB\n", n_sectors);
	printf("  commands:      %zu NVM_Erase + %zu NVM_Update (final has "
	    "LAST_COMMAND)\n", n_sectors, n_sectors);
	printf("  flow:          datasheet 3.4.5.5 (authenticated module "
	    "outside shadow RAM)\n");
	printf("  chip will verify RSA-2048 signature; a mismatch causes\n");
	printf("  the chip to reject the update and the old module stays\n");
	printf("  active.\n");

	if (!confirm) {
		printf("\n*** dry run.  Re-run with -y to actually apply.\n");
		munmap(img, st.st_size);
		return (0);
	}

	printf("\n*** writing chip NVM.  DO NOT INTERRUPT.\n");

	nvm_open(s, ifname, IFNVM_ACCESS_WRITE);
	(void)apply_module(s, ifname, m, img, src_byte, total_bytes);
	nvm_close(s, ifname);
	munmap(img, st.st_size);

	printf("\n%s update completed.\n", m->display_name);
	printf("Reboot the system to load the new module.\n");
	return (0);
}

/*
 * Per-sector erase+update loop for one authenticated outside-shadow
 * module (datasheet 3.4.5.5).  Caller has already opened the NVM
 * session and validated that src_byte..src_byte+total_bytes is in
 * range.  Each NVM_Erase and NVM_Update is async (datasheet 3.4.10.2 /
 * 3.4.10.3) so every command waits for the ARQ completion event.
 * On any chip-side failure this calls errx() -- callers that need to
 * release the NVM session before exiting must do so via atexit or
 * accept that the kernel will reap it when the process dies.
 */
static int
apply_module(int s, const char *ifname, const struct module_info *m,
    const uint8_t *img, uint32_t src_byte, uint32_t total_bytes)
{
	uint32_t i, n_sectors = total_bytes / 4096;

	for (i = 0; i < n_sectors; i++) {
		uint32_t off = i * 4096;
		int is_last = (i + 1 == n_sectors);
		int retval;

		fprintf(stderr, "  %s: sector %4u/%u  erase\r",
		    m->display_name, i + 1, n_sectors);
		fflush(stderr);
		retval = nvm_erase_chunk(s, ifname, m->erase_ptr_word,
		    i, 1, 0, 1 /* wait_arq */, 5000);
		if (retval != 0) {
			fprintf(stderr, "\n");
			errx(1, "%s: erase sector %u: AQ retval=0x%04x",
			    m->display_name, i, retval);
		}

		fprintf(stderr, "  %s: sector %4u/%u  write%s\r",
		    m->display_name, i + 1, n_sectors,
		    is_last ? " [LAST]" : "      ");
		fflush(stderr);
		retval = nvm_update_chunk(s, ifname, m->update_ptr_word, off,
		    4096,
		    is_last ? IXL_AQ_NVM_LAST_COMMAND : 0,
		    img + src_byte + off, 1 /* wait_arq */,
		    is_last ? 60000 : 5000);
		if (retval != 0) {
			fprintf(stderr, "\n");
			errx(1, "%s: update sector %u: AQ retval=0x%04x",
			    m->display_name, i, retval);
		}
	}
	fprintf(stderr, "\n");
	return (0);
}

/*
 * Find a shadow-RAM module's byte location and length given its
 * pointer-word index and a 64-KB shadow buffer.  The pointer word at
 * shadow[pointer_word] holds the module's word offset within shadow
 * RAM (bit 15 must be clear -- bit 15 set means outside-shadow,
 * sector units).  The first word at that location encodes the module
 * length in words exclusive of itself (datasheet 6.1.5.1 Table 6-4),
 * so the total module size in bytes is (length_word + 1) * 2.
 *
 * Returns 0 on success.  Returns 1 if the module is absent (pointer
 * 0xffff or 0x0000).  Calls errx() on malformed/out-of-bounds.
 */
static int
resolve_shadow_module(const uint8_t *shadow, uint16_t pointer_word,
    const char *display_name, uint32_t *byte_start, uint32_t *byte_len)
{
	uint16_t ptr = nvm_word(shadow, pointer_word);
	uint16_t len_words;
	uint32_t start, len_bytes;

	if (ptr == 0xffff || ptr == 0x0000)
		return (1);	/* absent */
	if (ptr & 0x8000) {
		errx(1, "%s: pointer 0x%04x at word 0x%02x has bit 15 set "
		    "(outside-shadow sector pointer, not a shadow module)",
		    display_name, ptr, pointer_word);
	}
	start = (uint32_t)ptr * 2;
	if (start + 2 > NVM_SR_SIZE_WORDS * 2) {
		errx(1, "%s: pointer 0x%04x maps to byte 0x%x, beyond "
		    "shadow RAM", display_name, ptr, start);
	}
	len_words = nvm_word(shadow, ptr);
	if (len_words == 0xffff || len_words == 0) {
		/*
		 * Pointer slot is filled, but the module's length word is
		 * the uninitialised-flash value (0xffff) or zero -- the
		 * module slot is reserved but not populated.  Treat as
		 * absent so callers can skip it.
		 */
		return (1);
	}
	len_bytes = ((uint32_t)len_words + 1) * 2;
	if (start + len_bytes > NVM_SR_SIZE_WORDS * 2) {
		errx(1, "%s: module at 0x%x length %u bytes extends past "
		    "shadow RAM (max 0x%x)", display_name, start, len_bytes,
		    NVM_SR_SIZE_WORDS * 2);
	}
	*byte_start = start;
	*byte_len = len_bytes;
	return (0);
}

/*
 * Write a shadow-RAM byte region to the chip in chunks of up to
 * IXL_NVM_CHUNK (4 KB) bytes, using NVM_Update with module_pointer=0
 * (datasheet 3.4.5.3).  No NVM_Erase is needed -- the chip stages
 * shadow writes in the inactive bank and commits on LAST_COMMAND.
 *
 * A single shadow NVM_Update command must not cross a 4 KB page
 * boundary: the chip processes shadow writes per 4 KB page and returns
 * AQ retval 0x000e (EINVAL) for a command that spans two pages (this
 * is not documented in the datasheet, found empirically).  So each
 * chunk is clipped to the next absolute 4 KB boundary of the shadow
 * RAM, NOT chunked relative to byte_start.  The start offset itself
 * need not be aligned.
 *
 * The cmdflags arg is applied only to the FINAL chunk (so callers
 * batching multiple regions can pass 0 here for all but the last,
 * and IXL_AQ_NVM_LAST_COMMAND for the very last write of the session).
 * Calls errx() on chip-side failure.
 */
static void
write_shadow_region(int s, const char *ifname, const uint8_t *buf,
    uint32_t byte_start, uint32_t byte_len, uint8_t final_cmdflags)
{
	uint32_t off = byte_start;
	uint32_t end = byte_start + byte_len;

	while (off < end) {
		uint32_t page_end = (off + IXL_NVM_CHUNK) & ~(IXL_NVM_CHUNK - 1);
		uint32_t chunk_end = (end < page_end) ? end : page_end;
		uint16_t len = (uint16_t)(chunk_end - off);
		int is_final = (chunk_end >= end);
		uint8_t flags = is_final ? final_cmdflags : 0;
		uint16_t to_ms = (flags & IXL_AQ_NVM_LAST_COMMAND) ?
		    60000 : 5000;
		int retval;

		retval = nvm_update_chunk(s, ifname, 0 /* shadow-RAM */,
		    off, len, flags, buf + off, 1 /* wait_arq */, to_ms);
		if (retval != 0) {
			errx(1, "shadow write at 0x%x: AQ retval=0x%04x",
			    off, retval);
		}
		off = chunk_end;
	}
}

/*
 * Update a single shadow-RAM module on the chip from an image file.
 * Datasheet 3.4.5.3.  Read chip's current 64 KB shadow, overlay the
 * image's bytes for this module, recompute the software checksum,
 * write the module region (non-LAST) and the checksum word (LAST).
 */
static int
cmd_shadow_update_single(int s, const char *ifname,
    const struct shadow_module_info *sm, const char *path, int confirm)
{
	const size_t sr_bytes = NVM_SR_SIZE_WORDS * sizeof(uint16_t);
	int fd;
	struct stat st;
	uint8_t *img;
	uint8_t shadow[NVM_SR_SIZE_WORDS * 2];
	uint32_t img_start = 0, img_len = 0;
	uint16_t new_cksum;
	int absent;

	/* load image */
	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open %s", path);
	if (fstat(fd, &st) == -1)
		err(1, "fstat %s", path);
	if (st.st_size < (off_t)sr_bytes)
		errx(1, "%s: image smaller than 64 KB shadow RAM", path);
	img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (img == MAP_FAILED)
		err(1, "mmap %s", path);
	close(fd);

	absent = resolve_shadow_module(img, sm->pointer_word, sm->display_name,
	    &img_start, &img_len);
	if (absent) {
		uint16_t p = nvm_word(img, sm->pointer_word);
		uint32_t off = (uint32_t)(p & 0x7fff) * 2;
		uint16_t lw = (p != 0 && p != 0xffff && (p & 0x8000) == 0) ?
		    nvm_word(img, p) : 0xffff;
		errx(1, "%s is not present in this image "
		    "(pointer word 0x%02x = 0x%04x; length word at "
		    "byte 0x%x = 0x%04x)",
		    sm->display_name, sm->pointer_word, p, off, lw);
	}

	printf("%s update plan:\n", sm->display_name);
	printf("  source:       %s\n", path);
	printf("  image bytes:  0x%05x-0x%05x (%u bytes)\n",
	    img_start, img_start + img_len - 1, img_len);
	printf("  pointer word: 0x%02x (shadow-RAM word units)\n",
	    sm->pointer_word);
	printf("  target:       shadow RAM byte 0x%x, %u bytes\n",
	    img_start, img_len);
	printf("  flow:         datasheet 3.4.5.3 (shadow-RAM module)\n");
	printf("  commands:     %u NVM_Update + 1 checksum write [LAST]\n",
	    (img_len + IXL_NVM_CHUNK - 1) / IXL_NVM_CHUNK);
	printf("  no NVM_Erase; word 0x3f (checksum) is recomputed\n");

	if (!confirm) {
		printf("\n*** dry run.  Re-run with -y to actually apply.\n");
		munmap(img, st.st_size);
		return (0);
	}

	printf("\n*** writing chip NVM.  DO NOT INTERRUPT.\n");

	nvm_open(s, ifname, IFNVM_ACCESS_WRITE);
	nvm_read_full(s, ifname, 0, sizeof(shadow), shadow, "reading shadow");
	fprintf(stderr, "\n");

	/* overlay the image's module bytes onto the chip shadow buffer */
	memcpy(shadow + img_start, img + img_start, img_len);

	/* recompute software checksum on the new state */
	new_cksum = nvm_compute_checksum(shadow);
	shadow[NVM_W_SW_CHECKSUM * 2] = (uint8_t)(new_cksum & 0xff);
	shadow[NVM_W_SW_CHECKSUM * 2 + 1] = (uint8_t)(new_cksum >> 8);

	fprintf(stderr, "  writing %s region (0x%x, %u bytes)\n",
	    sm->display_name, img_start, img_len);
	write_shadow_region(s, ifname, shadow, img_start, img_len, 0);

	fprintf(stderr, "  writing checksum 0x%04x at word 0x%02x [LAST]\n",
	    new_cksum, NVM_W_SW_CHECKSUM);
	write_shadow_region(s, ifname, shadow,
	    NVM_W_SW_CHECKSUM * 2, 2, IXL_AQ_NVM_LAST_COMMAND);

	nvm_close(s, ifname);
	munmap(img, st.st_size);

	printf("\n%s update completed.\n", sm->display_name);
	printf("Reboot the system to load the new module.\n");
	return (0);
}

/*
 * Resolve every shadow_module_table[] entry against the image, filling
 * in byte_start/byte_len/present.  Returns the number of populated
 * modules.  Pure resolution, no chip access.
 */
static size_t
resolve_shadow_batch(const uint8_t *img, struct shadow_step *sst,
    size_t n)
{
	size_t i, present = 0;

	for (i = 0; i < n; i++) {
		sst[i].sm = &shadow_module_table[i];
		sst[i].byte_start = 0;
		sst[i].byte_len = 0;
		sst[i].present = (resolve_shadow_module(img,
		    shadow_module_table[i].pointer_word,
		    shadow_module_table[i].display_name,
		    &sst[i].byte_start, &sst[i].byte_len) == 0);
		if (sst[i].present)
			present++;
	}
	return (present);
}

/*
 * Apply all populated shadow-RAM modules in one batched NVM_Update
 * sequence (datasheet 3.4.5.3): read chip's current shadow, overlay
 * each present module's bytes from the image, recompute the software
 * checksum, write each region and finally the checksum word with
 * LAST_COMMAND.  Caller must already hold an open NVM session.
 */
static void
apply_shadow_batch(int s, const char *ifname, const uint8_t *img,
    struct shadow_step *sst, size_t n)
{
	uint8_t shadow[NVM_SR_SIZE_WORDS * 2];
	size_t i, written = 0;
	uint16_t new_cksum;

	for (i = 0; i < n; i++) {
		if (sst[i].present)
			written++;
	}
	if (written == 0) {
		fprintf(stderr, "  no shadow modules populated in image\n");
		return;
	}

	nvm_read_full(s, ifname, 0, sizeof(shadow), shadow,
	    "reading shadow");
	fprintf(stderr, "\n");

	for (i = 0; i < n; i++) {
		if (!sst[i].present)
			continue;
		memcpy(shadow + sst[i].byte_start,
		    img + sst[i].byte_start, sst[i].byte_len);
	}

	new_cksum = nvm_compute_checksum(shadow);
	shadow[NVM_W_SW_CHECKSUM * 2] = (uint8_t)(new_cksum & 0xff);
	shadow[NVM_W_SW_CHECKSUM * 2 + 1] = (uint8_t)(new_cksum >> 8);

	for (i = 0; i < n; i++) {
		if (!sst[i].present)
			continue;
		fprintf(stderr, "  shadow: %-26s 0x%05x  %u bytes\n",
		    sst[i].sm->display_name, sst[i].byte_start,
		    sst[i].byte_len);
		write_shadow_region(s, ifname, shadow,
		    sst[i].byte_start, sst[i].byte_len, 0);
	}
	fprintf(stderr, "  shadow: %-26s 0x%05x  2 bytes [LAST]\n",
	    "checksum word 0x3f", NVM_W_SW_CHECKSUM * 2);
	write_shadow_region(s, ifname, shadow,
	    NVM_W_SW_CHECKSUM * 2, 2, IXL_AQ_NVM_LAST_COMMAND);
}

/*
 * Update the NVM header version metadata to match the new image:
 *   word 0x18  DEV_STARTER_VERSION    (e.g. 0x9055 = "9.55")
 *   words 0x2d-0x2e  EETRACK_LO/HI    (canonical match key for cfg)
 * Then recompute and write the software checksum at word 0x3f with
 * LAST_COMMAND.  These are pure metadata fields -- not card identity,
 * not chip-managed -- so it is safe to overwrite from the image.
 *
 * Without this step the chip's running EMP is upgraded (FLOW_AUTH
 * swaps the EMP image, dmesg's "FW" reflects the new build) but the
 * NVM header still labels the chip as the previous image version,
 * which makes the next scan show a mismatched nvm/fw pairing and the
 * nvmupdate.cfg match against the old EETRACK ID.
 */
static void
apply_header_version(int s, const char *ifname, const uint8_t *img)
{
	uint8_t shadow[NVM_SR_SIZE_WORDS * 2];
	uint16_t new_cksum;

	nvm_read_full(s, ifname, 0, sizeof(shadow), shadow,
	    "reading shadow");
	fprintf(stderr, "\n");

	memcpy(shadow + NVM_W_DEV_STARTER_VERSION * 2,
	    img + NVM_W_DEV_STARTER_VERSION * 2, 2);
	memcpy(shadow + NVM_W_EETRACK_LO * 2,
	    img + NVM_W_EETRACK_LO * 2, 4);

	new_cksum = nvm_compute_checksum(shadow);
	shadow[NVM_W_SW_CHECKSUM * 2] = (uint8_t)(new_cksum & 0xff);
	shadow[NVM_W_SW_CHECKSUM * 2 + 1] = (uint8_t)(new_cksum >> 8);

	fprintf(stderr, "  header: nvm version 0x%04x (word 0x18)\n",
	    nvm_word(shadow, NVM_W_DEV_STARTER_VERSION));
	write_shadow_region(s, ifname, shadow,
	    NVM_W_DEV_STARTER_VERSION * 2, 2, 0);

	fprintf(stderr, "  header: EETRACK 0x%08x (words 0x2d/0x2e)\n",
	    (uint32_t)nvm_word(shadow, NVM_W_EETRACK_LO) |
	    ((uint32_t)nvm_word(shadow, NVM_W_EETRACK_HI) << 16));
	write_shadow_region(s, ifname, shadow,
	    NVM_W_EETRACK_LO * 2, 4, 0);

	fprintf(stderr, "  header: checksum 0x%04x at word 0x3f [LAST]\n",
	    new_cksum);
	write_shadow_region(s, ifname, shadow,
	    NVM_W_SW_CHECKSUM * 2, 2, IXL_AQ_NVM_LAST_COMMAND);
}
