

#include <vector>
#include <string>
#include <map>
#include <iostream>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>


namespace osquery {
	namespace tables {
		QueryData genACPITables(QueryContext& context);
		QueryData genAppArmorProfiles(QueryContext& context);
		QueryData genAptSrcs(QueryContext& context);
		QueryData genArpCache(QueryContext& context);
		QueryData genAugeas(QueryContext& context);
		QueryData genAzureMetadata(QueryContext& context);
		QueryData genAzureTags(QueryContext& context);
		QueryData genBlockDevs(QueryContext& context);
		QueryData genCarbonBlackInfo(QueryContext& context);
		QueryData genCarves(QueryContext& context);
		QueryData genCerts(QueryContext& context);
		QueryData genChromeExtensionContentScripts(QueryContext& context);
		QueryData genChromeExtensions(QueryContext& context);
		QueryData genContainerEnvs(QueryContext& context);
		QueryData genContainerFsChanges(QueryContext& context);
		QueryData genContainerLabels(QueryContext& context);
		QueryData genContainerMounts(QueryContext& context);
		QueryData genContainerNetworks(QueryContext& context);
		QueryData genContainerPorts(QueryContext& context);
		QueryData genContainerProcesses(QueryContext& context);
		QueryData genContainers(QueryContext& context);
		QueryData genContainerStats(QueryContext& context);
		QueryData genCPUID(QueryContext& context);
		QueryData genCpuInfo(QueryContext& context);
		QueryData genCpuTime(QueryContext& context);
		QueryData genCronTab(QueryContext& context);
		QueryData genCurl(QueryContext& context);
		QueryData genDebPackages(QueryContext& context);
		QueryData genDNSResolvers(QueryContext& context);
		QueryData genEc2InstanceTags(QueryContext& context);
		QueryData genEc2Metadata(QueryContext& context);
		QueryData genEtcHosts(QueryContext& context);
		QueryData genEtcProtocols(QueryContext& context);
		QueryData genEtcServices(QueryContext& context);
		//QueryData genExample(QueryContext& context);
		QueryData genFDEStatus(QueryContext& context);
		QueryData genFile(QueryContext& context);
		QueryData genFirefoxAddons(QueryContext& context);
		//QueryData gengetAuthorizedKeys(QueryContext& context);
		//QueryData gengetIntelMEInfo(QueryContext& context);
		//QueryData gengetKnownHostsKeys(QueryContext& context);
		//QueryData gengetMemoryInfo(QueryContext& context);
		//QueryData gengetSshConfigs(QueryContext& context);
		//QueryData gengetUserSshKeys(QueryContext& context);
		QueryData genGroups(QueryContext& context);
		QueryData genHash(QueryContext& context);
		QueryData genImageHistory(QueryContext& context);
		QueryData genImageLabels(QueryContext& context);
		QueryData genImageLayers(QueryContext& context);
		QueryData genImages(QueryContext& context);
		QueryData genInfo(QueryContext& context);
		QueryData genInterfaceAddresses(QueryContext& context);
		QueryData genInterfaceDetails(QueryContext& context);
		QueryData genInterfaceIpv6(QueryContext& context);
		QueryData genIptables(QueryContext& context);
		QueryData genKernelInfo(QueryContext& context);
		QueryData genKernelKeys(QueryContext& context);
		QueryData genKernelModules(QueryContext& context);
		QueryData genLastAccess(QueryContext& context);
		QueryData genListeningPorts(QueryContext& context);
		QueryData genLoadAverage(QueryContext& context);
		QueryData genLoggedInUsers(QueryContext& context);
		QueryData genLxdCerts(QueryContext& context);
		QueryData genLxdCluster(QueryContext& context);
		QueryData genLxdClusterMembers(QueryContext& context);
		QueryData genLxdImages(QueryContext& context);
		QueryData genLxdInstanceConfig(QueryContext& context);
		QueryData genLxdInstanceDevices(QueryContext& context);
		QueryData genLxdInstances(QueryContext& context);
		QueryData genLxdNetworks(QueryContext& context);
		QueryData genLxdStoragePools(QueryContext& context);
		QueryData genMagicData(QueryContext& context);
		QueryData genMDDevices(QueryContext& context);
		QueryData genMDDrives(QueryContext& context);
		QueryData genMDPersonalities(QueryContext& context);
		QueryData genMemoryArrayMappedAddresses(QueryContext& context);
		QueryData genMemoryArrays(QueryContext& context);
		QueryData genMemoryDeviceMappedAddresses(QueryContext& context);
		QueryData genMemoryDevices(QueryContext& context);
		QueryData genMemoryErrorInfo(QueryContext& context);
		QueryData genMemoryMap(QueryContext& context);
		QueryData genModelSpecificRegister(QueryContext& context);
		QueryData genMounts(QueryContext& context);
		QueryData genNetworkLabels(QueryContext& context);
		QueryData genNetworks(QueryContext& context);
		QueryData genNodePackages(QueryContext& context);
		QueryData genOEMStrings(QueryContext& context);
		QueryData genOpenFiles(QueryContext& context);
		QueryData genOpenSockets(QueryContext& context);
		QueryData genOsqueryEvents(QueryContext& context);
		QueryData genOsqueryExtensions(QueryContext& context);
		QueryData genOsqueryFlags(QueryContext& context);
		QueryData genOsqueryInfo(QueryContext& context);
		QueryData genOsqueryPacks(QueryContext& context);
		QueryData genOsqueryRegistry(QueryContext& context);
		QueryData genOsquerySchedule(QueryContext& context);
		QueryData genOSVersion(QueryContext& context);
		QueryData genPCIDevices(QueryContext& context);
		QueryData genPipes(QueryContext& context);
		QueryData genPlatformInfo(QueryContext& context);
		QueryData genPortageKeywordSummary(QueryContext& context);
		//QueryData genportagePackages(QueryContext& context);
		QueryData genPortageUse(QueryContext& context);
		QueryData genProcessEnvs(QueryContext& context);
		QueryData genProcessMemoryMap(QueryContext& context);
		QueryData genProcessNamespaces(QueryContext& context);
		QueryData genPrometheusMetrics(QueryContext& context);
		QueryData genPythonPackages(QueryContext& context);
		QueryData genRoutes(QueryContext& context);
		//QueryData genRpmPackageFiles(QueryContext& context);
		QueryData genRpmPackages(QueryContext& context);
		QueryData genSecureBoot(QueryContext& context);
		QueryData genSELinuxSettings(QueryContext& context);
		QueryData genShadow(QueryContext& context);
		QueryData genSharedMemory(QueryContext& context);
		//QueryData genShellHistory(QueryContext& context);
		QueryData genSMBIOSTables(QueryContext& context);
		QueryData genStartupItems(QueryContext& context);
		QueryData genSudoers(QueryContext& context);
		QueryData genSuidBin(QueryContext& context);
		QueryData genSystemControls(QueryContext& context);
		QueryData genSystemdUnits(QueryContext& context);
		QueryData genSystemInfo(QueryContext& context);
		QueryData genTime(QueryContext& context);
		QueryData genTLSCertificate(QueryContext& context);
		QueryData genUlimitInfo(QueryContext& context);
		QueryData genUptime(QueryContext& context);
		QueryData genUSBDevices(QueryContext& context);
		QueryData genUserGroups(QueryContext& context);
		QueryData genUsers(QueryContext& context);
		QueryData genVersion(QueryContext& context);
		QueryData genVolumeLabels(QueryContext& context);
		QueryData genVolumes(QueryContext& context);
		QueryData genVSCodeExtensions(QueryContext& context);
		QueryData genXattr(QueryContext& context);
		QueryData genYara(QueryContext& context);
		QueryData genYCloudMetadata(QueryContext& context);
		QueryData genYumSrcs(QueryContext& context);
	}
}


namespace osquery
{
    namespace tables
    {
      TableRows genProcesses(QueryContext& context);
    }
}

struct AdaConstraint
{
  unsigned char op;
  std::string expr;
};


using genDataFuncPtr = osquery::QueryData(*)(osquery::QueryContext&);

genDataFuncPtr virtualTables[] = 
{
	osquery::tables::genACPITables, /*0*/
	osquery::tables::genAppArmorProfiles, /*1*/
	osquery::tables::genAptSrcs, /*2*/
	osquery::tables::genArpCache, /*3*/
	osquery::tables::genAugeas, /*4*/
	osquery::tables::genAzureMetadata, /*5*/
	osquery::tables::genAzureTags, /*6*/
	osquery::tables::genBlockDevs, /*7*/
	osquery::tables::genCarbonBlackInfo, /*8*/
	osquery::tables::genCarves, /*9*/
	osquery::tables::genCerts, /*10*/
	osquery::tables::genChromeExtensionContentScripts, /*11*/
	osquery::tables::genChromeExtensions, /*12*/
	osquery::tables::genContainerEnvs, /*13*/
	osquery::tables::genContainerFsChanges, /*14*/
	osquery::tables::genContainerLabels, /*15*/
	osquery::tables::genContainerMounts, /*16*/
	osquery::tables::genContainerNetworks, /*17*/
	osquery::tables::genContainerPorts, /*18*/
	osquery::tables::genContainerProcesses, /*19*/
	osquery::tables::genContainers, /*20*/
	osquery::tables::genContainerStats, /*21*/
	osquery::tables::genCPUID, /*22*/
	osquery::tables::genCpuInfo, /*23*/
	osquery::tables::genCpuTime, /*24*/
	osquery::tables::genCronTab, /*25*/
	osquery::tables::genCurl, /*26*/
	osquery::tables::genDebPackages, /*27*/
	osquery::tables::genDNSResolvers, /*28*/
	osquery::tables::genEc2InstanceTags, /*29*/
	osquery::tables::genEc2Metadata, /*30*/
	osquery::tables::genEtcHosts, /*31*/
	osquery::tables::genEtcProtocols, /*32*/
	osquery::tables::genEtcServices, /*33*/
	//osquery::tables::genExample, /*34*/
	osquery::tables::genFDEStatus, /*35*/
	osquery::tables::genFile, /*36*/
	osquery::tables::genFirefoxAddons, /*37*/
	//osquery::tables::gengetAuthorizedKeys, /*38*/
	//osquery::tables::gengetIntelMEInfo, /*39*/
	//osquery::tables::gengetKnownHostsKeys, /*40*/
	//osquery::tables::gengetMemoryInfo, /*41*/
	//osquery::tables::gengetSshConfigs, /*42*/
	//osquery::tables::gengetUserSshKeys, /*43*/
	osquery::tables::genGroups, /*44*/
	osquery::tables::genHash, /*45*/
	osquery::tables::genImageHistory, /*46*/
	osquery::tables::genImageLabels, /*47*/
	osquery::tables::genImageLayers, /*48*/
	osquery::tables::genImages, /*49*/
	osquery::tables::genInfo, /*50*/
	osquery::tables::genInterfaceAddresses, /*51*/
	osquery::tables::genInterfaceDetails, /*52*/
	osquery::tables::genInterfaceIpv6, /*53*/
	osquery::tables::genIptables, /*54*/
	osquery::tables::genKernelInfo, /*55*/
	osquery::tables::genKernelKeys, /*56*/
	osquery::tables::genKernelModules, /*57*/
	osquery::tables::genLastAccess, /*58*/
	osquery::tables::genListeningPorts, /*59*/
	osquery::tables::genLoadAverage, /*60*/
	osquery::tables::genLoggedInUsers, /*61*/
	osquery::tables::genLxdCerts, /*62*/
	osquery::tables::genLxdCluster, /*63*/
	osquery::tables::genLxdClusterMembers, /*64*/
	osquery::tables::genLxdImages, /*65*/
	osquery::tables::genLxdInstanceConfig, /*66*/
	osquery::tables::genLxdInstanceDevices, /*67*/
	osquery::tables::genLxdInstances, /*68*/
	osquery::tables::genLxdNetworks, /*69*/
	osquery::tables::genLxdStoragePools, /*70*/
	osquery::tables::genMagicData, /*71*/
	osquery::tables::genMDDevices, /*72*/
	osquery::tables::genMDDrives, /*73*/
	osquery::tables::genMDPersonalities, /*74*/
	osquery::tables::genMemoryArrayMappedAddresses, /*75*/
	osquery::tables::genMemoryArrays, /*76*/
	osquery::tables::genMemoryDeviceMappedAddresses, /*77*/
	osquery::tables::genMemoryDevices, /*78*/
	osquery::tables::genMemoryErrorInfo, /*79*/
	osquery::tables::genMemoryMap, /*80*/
	osquery::tables::genModelSpecificRegister, /*81*/
	osquery::tables::genMounts, /*82*/
	osquery::tables::genNetworkLabels, /*83*/
	osquery::tables::genNetworks, /*84*/
	osquery::tables::genNodePackages, /*85*/
	osquery::tables::genOEMStrings, /*86*/
	osquery::tables::genOpenFiles, /*87*/
	osquery::tables::genOpenSockets, /*88*/
	osquery::tables::genOsqueryEvents, /*89*/
	osquery::tables::genOsqueryExtensions, /*90*/
	osquery::tables::genOsqueryFlags, /*91*/
	osquery::tables::genOsqueryInfo, /*92*/
	osquery::tables::genOsqueryPacks, /*93*/
	osquery::tables::genOsqueryRegistry, /*94*/
	osquery::tables::genOsquerySchedule, /*95*/
	osquery::tables::genOSVersion, /*96*/
	osquery::tables::genPCIDevices, /*97*/
	osquery::tables::genPipes, /*98*/
	osquery::tables::genPlatformInfo, /*99*/
	osquery::tables::genPortageKeywordSummary, /*100*/
	//osquery::tables::genportagePackages, /*101*/
	osquery::tables::genPortageUse, /*102*/
	osquery::tables::genProcessEnvs, /*103*/
	osquery::tables::genProcessMemoryMap, /*105*/
	osquery::tables::genProcessNamespaces, /*106*/
	osquery::tables::genPrometheusMetrics, /*107*/
	osquery::tables::genPythonPackages, /*108*/
	osquery::tables::genRoutes, /*109*/
	//osquery::tables::genRpmPackageFiles, /*110*/
	osquery::tables::genRpmPackages, /*111*/
	osquery::tables::genSecureBoot, /*112*/
	osquery::tables::genSELinuxSettings, /*113*/
	osquery::tables::genShadow, /*114*/
	osquery::tables::genSharedMemory, /*115*/
	//osquery::tables::genShellHistory, /*116*/
	osquery::tables::genSMBIOSTables, /*117*/
	osquery::tables::genStartupItems, /*118*/
	osquery::tables::genSudoers, /*119*/
	osquery::tables::genSuidBin, /*120*/
	osquery::tables::genSystemControls, /*121*/
	osquery::tables::genSystemdUnits, /*122*/
	osquery::tables::genSystemInfo, /*123*/

	osquery::tables::genTime, /*137*/
	osquery::tables::genTLSCertificate, /*138*/
	osquery::tables::genUlimitInfo, /*139*/
	osquery::tables::genUptime, /*140*/
	osquery::tables::genUSBDevices, /*141*/
	osquery::tables::genUserGroups, /*142*/
	osquery::tables::genUsers, /*143*/
	osquery::tables::genVersion, /*144*/
	osquery::tables::genVolumeLabels, /*145*/
	osquery::tables::genVolumes, /*146*/
	osquery::tables::genVSCodeExtensions, /*147*/
	osquery::tables::genXattr, /*148*/
	osquery::tables::genYara, /*149*/
	osquery::tables::genYCloudMetadata, /*150*/
	osquery::tables::genYumSrcs /*151*/
};

// std::map<std::string, std::vector<AdaConstraint>>const & constraints

using osquery::QueryData;
using osquery::QueryContext;

class AQueryData
{
private:
    QueryData data;
public:
	AQueryData() : data() {}

    AQueryData(QueryData const & qd): data(qd)
    {}
    
	AQueryData(QueryData&& qd): data(std::move(qd))
    {}

	AQueryData(const AQueryData& rhs) = delete;
	AQueryData(AQueryData&& rhs) = delete;
	AQueryData& operator=(const AQueryData& rhs) = delete;
	AQueryData& operator=(AQueryData&& rhs) = delete;
	~AQueryData() = default;

    size_t getRowCount()
    {
        return data.size();
    }

    size_t getColumnCount()
    {
		if (data.size() > 0)
		{
        	return data[0].size();
		}
		else
		{
			return 0;
		}
    }

    const char* getNextKey()
    {
		if (data.size() == 0)
		{
			return nullptr;
		}
		std::map<std::string, std::string>& column = data[0];
		static std::map<std::string, std::string>::const_iterator it = column.cbegin();
        static std::string temp;
        
        if (it != column.cend())
        {
            temp = it->first;
			
			it = std::next(it);
            return temp.c_str();
        }
		else
		{
			return nullptr;
		}
    }

    const char* getValue(size_t row, const char* key)
    {
        static std::string temp;
        std::map<std::string, std::string>& column = data[row];
        temp = column[key];
        return temp.c_str();
    }

	QueryData& getQd()
	{
		return data;
	}
};

class AQueryConstraint
{
	private:
	QueryContext qc;

	public:
	AQueryConstraint():qc(){}
	void add(const char* key, unsigned char op, const char* expr)
	{
		osquery::Constraint con{op, expr};
		qc.constraints[key].add(con);
	}
	QueryContext& getCtx()
	{
		return qc;
	}
};

extern "C" __attribute__((visibility("default")))
void* getConstraintHandle()
{
	AQueryConstraint* aqc = new AQueryConstraint();
	return aqc;
}

extern "C" __attribute__((visibility("default")))
void destroyConstraint(void* constraintHandle)
{
	AQueryConstraint* aqc = static_cast<AQueryConstraint*>(constraintHandle);
	delete aqc;
}

extern "C" __attribute__((visibility("default")))
void destroyQueryData(void* dataHandle)
{
	AQueryData* aqd = static_cast<AQueryData*>(dataHandle);
	delete aqd;
}

extern "C" __attribute__((visibility("default")))
void addQueryConstraint(void* handle, const char* key, unsigned char op, const char* expr)
{
	AQueryConstraint* aqc = static_cast<AQueryConstraint*>(handle);
	aqc->add(key, op, expr);
}

extern "C" __attribute__((visibility("default")))
void* genDispatch(int tableId, void* constraintHandle)
{
  
  AQueryConstraint* aqc = static_cast<AQueryConstraint*>(constraintHandle);

  if (tableId == 500)
  {
    osquery::TableRows results = osquery::tables::genProcesses(aqc->getCtx());
    
	AQueryData* aqd = new AQueryData();

    for (auto const& tr : results)
    {
      aqd->getQd().emplace_back(tr->operator osquery::Row());
    }
    return aqd;
  }

  return new AQueryData((virtualTables[tableId])(aqc->getCtx()));
}

extern "C" __attribute__((visibility("default")))
size_t getRowCount(void* dataHandle)
{
	AQueryData* aqd = static_cast<AQueryData*>(dataHandle);
	return aqd->getRowCount();
}

extern "C" __attribute__((visibility("default")))
size_t getColumnCount(void* dataHandle)
{
	AQueryData* aqd = static_cast<AQueryData*>(dataHandle);
	return aqd->getColumnCount();
}

extern "C" __attribute__((visibility("default")))
const char* getNextKey(void* dataHandle)
{
	AQueryData* aqd = static_cast<AQueryData*>(dataHandle);
	return aqd->getNextKey();
}

extern "C" __attribute__((visibility("default")))
const char* getValue(void* dataHandle, size_t row, const char* key)
{
	AQueryData* aqd = static_cast<AQueryData*>(dataHandle);
	return aqd->getValue(row, key);
}