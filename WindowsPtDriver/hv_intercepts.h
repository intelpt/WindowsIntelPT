/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver
*  Filename: hv_intercepts.h
*  Defines all the HyperV data structures and functions for Intercepts
*  Last revision: xx/xx/2017
*
*  Copyright© 2017 Andrea Allievi, Richard Johnson
*  Microsoft Ltd and TALOS Research and Intelligence Group
*  All right reserved
**********************************************************************/

#pragma once

// Define partition identifier type.
typedef UINT64 HV_PARTITION_ID, *PHV_PARTITION_ID;

// Define port type.
typedef enum _HV_PORT_TYPE
{
	HvPortTypeMessage = 1,
	HvPortTypeEvent = 2,
	HvPortTypeMonitor = 3
} HV_PORT_TYPE, *PHV_PORT_TYPE;

// Define the intercept access types.
typedef UINT8 HV_INTERCEPT_ACCESS_TYPE;

#define HV_INTERCEPT_ACCESS_READ    0
#define HV_INTERCEPT_ACCESS_WRITE   1
#define HV_INTERCEPT_ACCESS_EXECUTE 2

typedef UINT32 HV_INTERCEPT_ACCESS_TYPE_MASK;

#define HV_INTERCEPT_ACCESS_MASK_NONE       0x00
#define HV_INTERCEPT_ACCESS_MASK_READ       0X01
#define HV_INTERCEPT_ACCESS_MASK_WRITE      0x02
#define HV_INTERCEPT_ACCESS_MASK_EXECUTE    0x04

#define HV_CALL_ATTRIBUTES DECLSPEC_ALIGN(8)

// Define intercept types.
typedef enum _HV_INTERCEPT_TYPE
{
	HvInterceptTypeX64IoPort = 0x00000000,
	HvInterceptTypeX64Msr = 0x00000001,
	HvInterceptTypeX64Cpuid = 0x00000002,
	HvInterceptTypeException = 0x00000003,
	HvInterceptTypeRegister = 0x00000004,
} HV_INTERCEPT_TYPE, *PHV_INTERCEPT_TYPE;
typedef UINT16 HV_X64_IO_PORT, *PHV_X64_IO_PORT;

// Define intercept parameters.
typedef union _HV_INTERCEPT_PARAMETERS
{
	UINT64 AsUINT64;
	// HvInterceptTypeX64IoPort.
	HV_X64_IO_PORT IoPort;
	// HvInterceptTypeX64Cpuid.
	UINT32 CpuidIndex;
	// HvInterceptTypeException.
	UINT16 ExceptionVector;
	// Other intercept paramaters.....
} HV_INTERCEPT_PARAMETERS, *PHV_INTERCEPT_PARAMETERS;
// Define intercept descriptor structure.
typedef struct  _HV_INTERCEPT_DESCRIPTOR
{
	HV_INTERCEPT_TYPE Type;
	HV_INTERCEPT_PARAMETERS Parameters;
} HV_INTERCEPT_DESCRIPTOR, *PHV_INTERCEPT_DESCRIPTOR;
typedef const HV_INTERCEPT_DESCRIPTOR *PCHV_INTERCEPT_DESCRIPTOR;

// Definition of the HvCallRegisterInterceptResult hypercall input structure.
typedef struct HV_CALL_ATTRIBUTES _HV_REGISTER_X64_CPUID_RESULT_PARAMETERS
{
	struct
	{
		UINT32 Eax;
		UINT32 Ecx;
		BOOLEAN SubleafSpecific;
		BOOLEAN AlwaysOverride;
	} Input;

	struct
	{
		UINT32 Eax;
		UINT32 EaxMask;
		UINT32 Ebx;
		UINT32 EbxMask;
		UINT32 Ecx;
		UINT32 EcxMask;
		UINT32 Edx;
		UINT32 EdxMask;
	} Result;
} HV_REGISTER_X64_CPUID_RESULT_PARAMETERS, *PHV_REGISTER_X64_CPUID_RESULT_PARAMETERS;

// Definition of the HvCallUnregisterInterceptResult hypercall input structure.
typedef struct HV_CALL_ATTRIBUTES _HV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS
{
	UINT32 Eax;
	UINT32 Ecx;
	BOOLEAN SubleafSpecific;
} HV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS, *PHV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS;

#define HV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS HV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS
#define PHV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS PHV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS

typedef union HV_CALL_ATTRIBUTES _HV_REGISTER_INTERCEPT_RESULT_PARAMETERS
{
	HV_REGISTER_X64_CPUID_RESULT_PARAMETERS Cpuid;
} HV_REGISTER_INTERCEPT_RESULT_PARAMETERS, *PHV_REGISTER_INTERCEPT_RESULT_PARAMETERS;

typedef union HV_CALL_ATTRIBUTES _HV_UNREGISTER_INTERCEPT_RESULT_PARAMETERS
{
	HV_UNREGISTER_X64_CPUID_RESULT_PARAMETERS Cpuid;
} HV_UNREGISTER_INTERCEPT_RESULT_PARAMETERS, *PHV_UNREGISTER_INTERCEPT_RESULT_PARAMETERS;


#define WINHVAPI

extern "C" {
	WINHVAPI KIRQL NTAPI WinHvQueryInterceptIrql(VOID);

	// Interception Interfaces
	NTSTATUS NTAPI WinHvInstallIntercept(HV_PARTITION_ID PartitionId, HV_INTERCEPT_ACCESS_TYPE_MASK AccessType, PCHV_INTERCEPT_DESCRIPTOR Descriptor);
	NTSTATUS NTAPI WinHvRegisterInterceptResult(HV_PARTITION_ID PartitionId, HV_INTERCEPT_TYPE InterceptType, const PHV_REGISTER_INTERCEPT_RESULT_PARAMETERS Parameters);
	NTSTATUS NTAPI WinHvUnregisterInterceptResult(HV_PARTITION_ID PartitionId, HV_INTERCEPT_TYPE InterceptType, const PHV_UNREGISTER_INTERCEPT_RESULT_PARAMETERS Parameters);
	//NTSTATUS NTAPI WinHvCheckForIoIntercept(HV_PARTITION_ID PartitionId, HV_VP_INDEX VpIndex, HV_INPUT_VTL TargetVtl, HV_IO_PORT Port, UINT8 Size, BOOLEAN IsWrite, PBOOLEAN Intercept);
}