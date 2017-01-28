/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: pt_dump.h 
 *	Defines the data structures used to decode the binary PT dump
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once
#include <stdint.h>
#include "decoder\pt_last_ip.h"
#include "decoder\pt_time.h"
#include "decoder\intel-pt.h"

struct ptdump_options {
	/* Show the current offset in the trace stream. */
	uint32_t show_offset : 1;
	/* Show raw packet bytes. */
	uint32_t show_raw_bytes : 1;
	/* Show last IP for packets with IP payloads. */
	uint32_t show_last_ip : 1;
	/* Show the execution mode on mode.exec. */
	uint32_t show_exec_mode : 1;
	/* Keep track of time. */
	uint32_t track_time : 1;
	/* Show the estimated TSC for timing related packets. */
	uint32_t show_time : 1;
	/* Show time calibration. */
	uint32_t show_tcal : 1;
	/* Show timing information as delta to the previous value. */
	uint32_t show_time_as_delta : 1;
	/* Quiet mode: Don't print anything but errors. */
	uint32_t quiet : 1;
	/* Don't show PAD packets. */
	uint32_t no_pad : 1;
	/* Do not try to sync the decoder. */
	uint32_t no_sync : 1;
	/* Do not calibrate timing. */
	uint32_t no_tcal : 1;
	/* Do not expect wall-clock time. */
	uint32_t no_wall_clock : 1;
	/* Don't show timing packets. */
	uint32_t no_timing : 1;
	/* Don't show CYC packets and ignore them when tracking time. */
	uint32_t no_cyc : 1;
	/* Don't PGE PGD packets. */
	uint32_t no_pge_pgd : 1;
	/* Don't show Paging Information Packets */
	uint32_t no_pip : 1;
	/* The offset DELTA value */
	uint64_t offset_delta;
	/* HANDLE to the target text file (if one)*/
	HANDLE hTargetFile;
};

struct ptdump_buffer {
	/* The trace offset. */
	char offset[17];
	/* The raw packet bytes. */
	char raw[33];
	/* The packet opcode. */
	char opcode[10];
	union {
		/* The standard packet payload. */
		char standard[25];

		/* An extended packet payload. */
		char extended[48];
	} payload;

	/* The tracking information. */
	struct {
		/* The tracking identifier. */
		char id[5];

		/* The tracking information. */
		char payload[17];
	} tracking;
	/* A flag telling whether an extended payload is used. */
	uint32_t use_ext_payload : 1;
	/* A flag telling whether to skip printing this buffer. */
	uint32_t skip : 1;
	/* A flag telling whether to skip printing the time. */
	uint32_t skip_time : 1;
	/* A flag telling whether to skip printing the calibration. */
	uint32_t skip_tcal : 1;
};

struct ptdump_tracking {
	/* Track last-ip. */
	struct pt_last_ip last_ip;
	/* Track time calibration. */
	struct pt_time_cal tcal;
	/* Track time. */
	struct pt_time time;
	/* The last estimated TSC. */
	uint64_t tsc;
	/* The last calibration value. */
	uint64_t fcr;
	/* Header vs. normal decode.  Set if decoding PSB+. */
	uint32_t in_header : 1;
};

struct ptdump_global {
	HANDLE hInFile = 0;					// The input file handle
	HANDLE hInSection = 0;				// The input file SECTION object
	LPCVOID lpFileContent = 0;			// The mapped file content
};

// Load a PT binary file
int load_pt(struct pt_config *config, char *arg, const char *prog);

// Dump all the PT packets
int pt_dump(const struct pt_config *config, const struct ptdump_options *options);


// binary dump 
BOOL pt_dump_file(LPTSTR lpInputFile, LPTSTR lpOutFile, DWORD dwMaxSize = 0);
BOOL pt_dumpW(LPBYTE lpBuff, DWORD dwBuffSize, HANDLE hOutFile, QWORD delta = 0ull, BOOLEAN bTraceOnlyKernel = FALSE);
