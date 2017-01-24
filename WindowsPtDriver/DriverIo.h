/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: DriverIo.h
 *  Define the I/O communication between the Driver and the User App
 *  Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#pragma once
#define INTEL_PT_PMI_EVENT_NAME L"IntelPtPmiEvt"			// The name of the synchronization event
#define _KERNEL_TRACE_FROM_USER_MODE_ENABLED 1				// Enable kernel mode tracing from user mode

#define PT_TRACE_CYC_PCKS_MASK				(1 << 0)		// CYC Packets
#define PT_TRACE_MTC_PCKS_MASK				(1 << 1)		// MTC Packets
#define PT_TRACE_TSC_PCKS_MASK				(1 << 2)		// TSC Packets
#define PT_TRACE_BRANCH_PCKS_MASK			(1 << 3)		// COFI-based packets: FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec, MODE.TSX.
#define PT_ENABLE_TOPA_MASK					(1 << 4)		// Table of Physical Addresses
#define PT_ENABLE_RET_COMPRESSION_MASK		(1 << 5)		// RET compression

struct PT_TRACE_IP_FILTERING {
	DWORD dwNumOfRanges;
	struct {
		LPVOID lpStartVa;
		LPVOID lpEndVa;
		BOOLEAN bStopTrace;
	} Ranges[4];
};

typedef struct _PT_USER_REQ {
	KAFFINITY kCpuAffinity;					// The target CPUs affinity mask
	DWORD dwTraceSize;						// Trace buffer size 
	DWORD dwOptsMask;						// The trace options bitmask
	DWORD dwProcessId;						// The target process ID (0 means ALL)
	PT_TRACE_IP_FILTERING IpFiltering;		// The IP ranges that we would like to trace (if any)
	BOOLEAN bTraceUser;						// TRUE if tracing User mode 
	BOOLEAN bTraceKernel;					// TRUE if tracing Kernel mode 
} PT_USER_REQ, * PPT_USER_REQ;

enum PT_TRACE_STATE {
	PT_TRACE_STATE_ERROR = -1,
	PT_TRACE_STATE_STOPPED,
	PT_TRACE_STATE_PAUSED,
	PT_TRACE_STATE_RUNNING
};

// The structure used to retrieve the details of a TRACE
typedef struct _PT_TRACE_DETAILS {
	DWORD dwTargetProcId;					// The target process to trace
	DWORD dwCpuId;							// Target processor ID
	DWORD dwTraceBuffSize;					// The Trace buffer size
	QWORD qwTotalNumberOfPackets;			// The total number of packets acquired until now
	PT_TRACE_IP_FILTERING IpFiltering;		// The IP ranges that we would like to trace (if any)
	PT_TRACE_STATE dwCurrentTraceState;		// The current tracing state
} PT_TRACE_DETAILS, *PPT_TRACE_DETAILS;

// The PMI User-mode callback routine
typedef VOID(*PMI_USER_CALLBACK_ROUTINE) (DWORD dwCpuId, PVOID lpBuffer, QWORD qwBufferSize);

// The PMI user-mode callback data structure
typedef struct _PT_PMI_USER_CALLBACK {
	KAFFINITY kCpuAffinity;					// The CPU affinity mask in which to execute this Callback
	PMI_USER_CALLBACK_ROUTINE lpAddress;	// User-mode address
	DWORD dwThrId;							// Thread ID in which to execute this callback
}PT_PMI_USER_CALLBACK, *PPT_PMI_USER_CALLBACK;

#ifndef WIN32
// Driver generic pass-through routine
NTSTATUS DevicePassThrough(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver Device IO Control dispatch routine
NTSTATUS DeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver create and close routine
NTSTATUS DeviceCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DeviceClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver unsupported routine
NTSTATUS DeviceUnsupported(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Allocate the PT buffer for one or more CPUs and map to the current process
NTSTATUS AllocateCpuUserBuffers(KAFFINITY cpuAffinity, DWORD dwSize, LPVOID * lppBuffArray, DWORD * lpdwArraySize, BOOLEAN bUseToPA);

// Free the PT buffer of the specified CPUs
NTSTATUS FreeCpuUserBuffers(KAFFINITY cpuAffinity);

// Search a PMI User-mode Callback entry and optionally remove it
PMI_USER_CALLBACK_DESC * SearchCallbackEntry(LPVOID lpAddress, DWORD dwThrId, BOOLEAN bRemove = FALSE);

#else
#include <WinIoCtl.h>
/*
*   IOCTL's are defined by the following bit layout.
* [Common |Device Type|Required Access|Custom|Function Code|Transfer Type]
*   31     30       16 15          14  13   12           2  1            0
*
*   Common          - 1 bit.  This is set for user-defined device types.
*   Device Type     - This is the type of device the IOCTL belongs to.
*					   This can be user defined (Common bit set).
*					   This must match the device type of the device object.
*   Required Access - FILE_READ_DATA, FILE_WRITE_DATA, etc.
*                     This is the required access for the  device.
*   Custom          - 1 bit.  This is set for user-defined IOCTL's.
*					   This is used in the same manner as "WM_USER".
*   Function Code   - This is the function code that the system or the
*					   user defined (custom bit set)
*   Transfer Type   - METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER,
*					   METHOD_BUFFERED, This the data transfer method to be used.
*/

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#endif

// Check the support for current processor and get the capabilities list
#define IOCTL_PTDRV_CHECKSUPPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_READ_DATA)

// Allocate and return the buffer for one or more processors
#define IOCTL_PTDRV_ALLOC_BUFFERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0D, METHOD_BUFFERED, FILE_EXECUTE)
// Free and cleanup the PT buffer for one or more processors
#define IOCTL_PTDRV_FREE_BUFFERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0F, METHOD_BUFFERED, FILE_EXECUTE)

// Start a particular process trace
#define IOCTL_PTDRV_START_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_EXECUTE)
// Pause a process trace (needed to reliably read a TRACE)
#define IOCTL_PTDRV_PAUSE_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_EXECUTE)
// Resume a process trace (needed to reliably read a TRACE)
#define IOCTL_PTDRV_RESUME_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA07, METHOD_BUFFERED, FILE_EXECUTE)
// Stop, cleanup a process trace and free the resource
#define IOCTL_PTDRV_CLEAR_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA09, METHOD_BUFFERED, FILE_EXECUTE)
// Get the TRACE details (like total number of packets and so on)
#define IOCTL_PTDR_GET_TRACE_DETAILS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0B, METHOD_BUFFERED, FILE_READ_DATA | FILE_EXECUTE)

// Register a user-mode Callback routine for the PMI interrupt
#define IOCTL_PTDRV_REGISTER_PMI_ROUTINE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_WRITE_DATA)
// Remove a user-mode callback routine for the PMI interrupt
#define IOCTL_PTDRV_FREE_PMI_ROUTINE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA14, METHOD_BUFFERED, FILE_WRITE_DATA)

