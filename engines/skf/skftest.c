#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "skf.h"

int main(int argc, char **argv)
{
	ULONG rv;
	ULONG len;

	BOOL bPresent = TRUE;
	CHAR devNameList[256];
	LPSTR devName;
	DEVHANDLE hDev;
	ULONG devState;
	DEVINFO devInfo;
	BYTE authData[16];
	
	CHAR appNameList[256];
	LPSTR appName;
	HAPPLICATION hApp;

	CHAR containerNameList[256];
	LPSTR containerName; 
	HCONTAINER hContainer;
	ULONG containerType;

	len = sizeof(devNameList);
	rv = SKF_EnumDev(bPresent, devNameList, &len);
	assert(rv == SAR_OK);

	devName = devNameList;
	printf(" Device Name : %s\n", devName);

	rv = SKF_GetDevState(devName, &devState);
	assert(rv == SAR_OK);
	printf(" Device State: %ld\n", devState);
	
	rv = SKF_ConnectDev(devName, &hDev);
	assert(rv == SAR_OK);

	rv = SKF_GetDevInfo(hDev, &devInfo);
	assert(rv == SAR_OK);
	
	printf(" Device Version   : %d.%d\n", devInfo.Version.major, devInfo.Version.minor);
	printf(" Manufacturer     : %s\n", devInfo.Manufacturer);
	printf(" Issuer           : %s\n", devInfo.Issuer);
	printf(" Label            : %s\n", devInfo.Label);
	printf(" Serial Number    : %s\n", devInfo.SerialNumber);
	printf(" Hardware Version : %d.%d\n", devInfo.HWVersion.major, devInfo.HWVersion.minor);
	printf(" Firmware Version : %d.%d\n", devInfo.FirmwareVersion.major, devInfo.FirmwareVersion.minor);
	printf(" AlgSymCap        : 0x%08x\n", devInfo.AlgSymCap);
	printf(" AlgAsymCap       : 0x%08x\n", devInfo.AlgAsymCap);
	printf(" AlgHashCap       : 0x%08x\n", devInfo.AlgHashCap);
	printf(" AlgHashCap       : 0x%08x\n", devInfo.DevAuthAlgId);
	printf(" Total Space      : %ld\n", devInfo.TotalSpace);
	printf(" Free Space       : %ld\n", devInfo.FreeSpace);
	printf(" MaxECCBuffer     : %ld\n", devInfo.MaxECCBufferSize);
	printf(" MaxBuffer        : %ld\n", devInfo.MaxBufferSize);

	rv = SKF_DevAuth(hDev, authData, sizeof(authData));
	assert(rv == SAR_OK);


	len = sizeof(appNameList);		
	rv = SKF_EnumApplication(hDev, appNameList, &len);
	assert(rv == SAR_OK);

	appName = appNameList;
	printf("Application Name : %s\n", appName);

	rv = SKF_OpenApplication(hDev, appName, &hApp);
	assert(rv == SAR_OK);
	
	len = sizeof(containerNameList);
	rv = SKF_EnumContainer(hApp, containerNameList, &len);
	assert(rv == SAR_OK);

	containerName = containerNameList;
	printf("Container Name: %s\n", containerName);

	rv = SKF_OpenContainer(hApp, containerName, &hContainer);
	assert(rv == SAR_OK);

	rv = SKF_GetContainerType(hContainer, &containerType);
	assert(rv == SAR_OK);

	printf("Container Type: %ld\n", containerType);


	rv = SKF_CloseContainer(hContainer);
	assert(rv == SAR_OK);

	rv = SKF_CloseApplication(hApp);
	assert(rv == SAR_OK);

	return 0;
}

