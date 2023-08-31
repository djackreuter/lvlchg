#pragma once

#define LVL_CHG_DEVICE 0x8000

#define IOCTL_LVL_CHG_PROC		CTL_CODE(LVL_CHG_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

struct ProcessIDs
{
	ULONG currentProcessID;
	ULONG targetProcessID;
};


typedef enum _WINDOWS_VERSION
{
	WINDOWS_UNSUPPORTED  = 0,
	WINDOWS_THRESHOLD	 = 0,
	WINDOWS_THRESHOLD_2	 = 0x6b0,
	WINDOWS_REDSTONE	 = 0x6c0,
	WINDOWS_REDSTONE_2	 = 0x6c8,
	WINDOWS_REDSTONE_3	 = 0x6c8,
	WINDOWS_REDSTONE_4	 = 0x6c8,
	WINDOWS_REDSTONE_5	 = 0x6c8,
	WINDOWS_19H1		 = 0x6F8,
	WINDOWS_19H2		 = 0x878,
	WINDOWS_20H1		 = 0x878,
	WINDOWS_20H2		 = 0x878,
	WINDOWS_21H1		 = 0x878,
	WINDOWS_21H2		 = 0x878,
	WINDOWS_22H2		 = 0x878,
	WINDOWS_SUN_VALLEY   = 0x878,
	WINDOWS_SUN_VALLEY_2 = 0x878,
	WINDOWS_SUN_VALLEY_3 = 0
} WINDOWS_VERSION, *PWINDOWS_VERSION;
