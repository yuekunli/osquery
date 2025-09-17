#include <vector>
#include <string>
#include <map>
#include <optional>
#include <iostream>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

static const int GEN_PROCESSES_TABLE_ID = 193;
static const int GEN_SYSTEMD_UNITS_TABLE_ID = 234;

namespace osquery
{
    namespace tables
    {
      TableRows genProcesses(QueryContext& context);
	  TableRows genSystemdUnits(QueryContext& context);
    }
}

namespace osquery {
	namespace tables {
		QueryData genACPITables(QueryContext& context);
		QueryData genAppArmorProfiles(QueryContext& context);
		QueryData genAptSrcs(QueryContext& context);
		QueryData genArpCache(QueryContext& context);
		QueryData genAugeas(QueryContext& context);
		QueryData getAuthorizedKeys(QueryContext& context);
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
		QueryData genDeviceFile(QueryContext& context);
		QueryData genDeviceHash(QueryContext& context);
		QueryData genDevicePartitions(QueryContext& context);
		QueryData genDNSResolvers(QueryContext& context);
		QueryData genEc2InstanceTags(QueryContext& context);
		QueryData genEc2Metadata(QueryContext& context);
		QueryData genEtcHosts(QueryContext& context);
		QueryData genEtcProtocols(QueryContext& context);
		QueryData genEtcServices(QueryContext& context);
		QueryData genFDEStatus(QueryContext& context);
		QueryData genFile(QueryContext& context);
		QueryData genFirefoxAddons(QueryContext& context);
		QueryData genGroups(QueryContext& context);
		QueryData genHash(QueryContext& context);
		QueryData genImageHistory(QueryContext& context);
		QueryData genImageLabels(QueryContext& context);
		QueryData genImageLayers(QueryContext& context);
		QueryData genImages(QueryContext& context);
		QueryData genInfo(QueryContext& context);
		QueryData getIntelMEInfo(QueryContext& context);
		QueryData genInterfaceAddresses(QueryContext& context);
		QueryData genInterfaceDetails(QueryContext& context);
		QueryData genInterfaceIpv6(QueryContext& context);
		QueryData genIptables(QueryContext& context);
		QueryData genKernelInfo(QueryContext& context);
		QueryData genKernelKeys(QueryContext& context);
		QueryData genKernelModules(QueryContext& context);
		QueryData getKnownHostsKeys(QueryContext& context);
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
		QueryData getMemoryInfo(QueryContext& context);
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
		QueryData portagePackages(QueryContext& context);
		QueryData genPortageUse(QueryContext& context);
		QueryData genProcessEnvs(QueryContext& context);
		QueryData genProcessMemoryMap(QueryContext& context);
		QueryData genProcessNamespaces(QueryContext& context);
		QueryData genPrometheusMetrics(QueryContext& context);
		QueryData genPythonPackages(QueryContext& context);
		QueryData genRoutes(QueryContext& context);
		QueryData genRpmPackages(QueryContext& context);
		QueryData genSecureBoot(QueryContext& context);
		QueryData genSELinuxSettings(QueryContext& context);
		QueryData genShadow(QueryContext& context);
		QueryData genSharedMemory(QueryContext& context);
		QueryData genSMBIOSTables(QueryContext& context);
		QueryData getSshConfigs(QueryContext& context);
		QueryData genStartupItems(QueryContext& context);
		QueryData genSudoers(QueryContext& context);
		QueryData genSuidBin(QueryContext& context);
		QueryData genSystemControls(QueryContext& context);
		//QueryData genSystemdUnits(QueryContext& context);
		QueryData genSystemInfo(QueryContext& context);
		QueryData genTime(QueryContext& context);
		QueryData genTLSCertificate(QueryContext& context);
		QueryData genUlimitInfo(QueryContext& context);
		QueryData genUptime(QueryContext& context);
		QueryData genUSBDevices(QueryContext& context);
		QueryData genUserGroups(QueryContext& context);
		QueryData getUserSshKeys(QueryContext& context);
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

struct AdaConstraint
{
  unsigned char op;
  std::string expr;
};

using genDataFuncPtr = osquery::QueryData(*)(osquery::QueryContext&);

genDataFuncPtr virtualTables[] = 
{
	nullptr /*osquery::tables::genAccountpolicydata*/ /* 0 */,
	osquery::tables::genACPITables, /*1*/
	nullptr /*osquery::tables::genAdconfig*/ /* 2 */,
	nullptr /*osquery::tables::genAlf*/ /* 3 */,
	nullptr /*osquery::tables::genAlfexceptions*/ /* 4 */,
	nullptr /*osquery::tables::genAlfexplicitauths*/ /* 5 */,
	nullptr /*osquery::tables::genAppschemes*/ /* 6 */,
	nullptr /*apparmor_events::genTable*/ /* 7 */,
	osquery::tables::genAppArmorProfiles, /*8*/
	nullptr /*osquery::tables::genShims*/ /* 9 */,
	nullptr /*osquery::tables::genApps*/ /* 10 */,
	osquery::tables::genAptSrcs, /*11*/
	osquery::tables::genArpCache, /*12*/
	nullptr /*osquery::tables::genAsl*/ /* 13 */,
	osquery::tables::genAugeas, /*14*/
	nullptr /*osquery::tables::genAuthenticode*/ /* 15 */,
	nullptr /*osquery::tables::genAuthorizationmechanisms*/ /* 16 */,
	nullptr /*osquery::tables::genAuthorizations*/ /* 17 */,
	osquery::tables::getAuthorizedKeys /* 18 */,
	nullptr /*osquery::tables::genAutoexec*/ /* 19 */,
	osquery::tables::genAzureMetadata, /*20*/
	osquery::tables::genAzureTags, /*21*/
	nullptr /*osquery::tables::genBackgroundactivitiesmoderator*/ /* 22 */,
	nullptr /*osquery::tables::genBatteryinfo*/ /* 23 */,
	nullptr /*osquery::tables::genBitlockerinfo*/ /* 24 */,
	osquery::tables::genBlockDevs, /*25*/
	nullptr /*bpf_process_events::genTable*/ /* 26 */,
	nullptr /*bpf_socket_events::genTable*/ /* 27 */,
	nullptr /*osquery::tables::genBrowserplugins*/ /* 28 */,
	osquery::tables::genCarbonBlackInfo, /*29*/
	osquery::tables::genCarves, /*30*/
	osquery::tables::genCerts, /*31*/
	nullptr /*osquery::tables::genChassisinfo*/ /* 32 */,
	nullptr /*osquery::tables::genChocolateypackages*/ /* 33 */,
	osquery::tables::genChromeExtensionContentScripts, /*34*/
	osquery::tables::genChromeExtensions, /*35*/
	nullptr /*osquery::tables::genConnecteddisplays*/ /* 36 */,
	nullptr /*osquery::tables::genConnectivity*/ /* 37 */,
	osquery::tables::genCpuInfo, /*38*/
	osquery::tables::genCpuTime, /*39*/
	osquery::tables::genCPUID, /*40*/
	nullptr /*osquery::tables::genCrashlogs*/ /* 41 */,
	osquery::tables::genCronTab, /*42*/
	nullptr /*osquery::tables::genCupsdestinations*/ /* 43 */,
	nullptr /*osquery::tables::genCupsjobs*/ /* 44 */,
	osquery::tables::genCurl, /*45*/
	osquery::tables::genTLSCertificate, /*46*/
	osquery::tables::genDebPackages, /*47*/
	nullptr /*osquery::tables::genDefaultenvironment*/ /* 48 */,
	osquery::tables::genDeviceFile /* 49 */,
	nullptr /*osquery::tables::genDevicefirmware*/ /* 50 */,
	osquery::tables::genDeviceHash /* 51 */,
	osquery::tables::genDevicePartitions /* 52 */,
	nullptr /*osquery::tables::genDeviceguardstatus*/ /* 53 */,
	osquery::tables::genFDEStatus, /*54*/
	nullptr /*osquery::tables::genTable*/ /* 55 */,
	nullptr /*osquery::tables::genDiskinfo*/ /* 56 */,
	nullptr /*osquery::tables::genDnscache*/ /* 57 */,
	nullptr /*dns_lookup_events::genTable*/ /*58*/,
	osquery::tables::genDNSResolvers, /*59*/
	osquery::tables::genContainerEnvs, /*60*/
	osquery::tables::genContainerFsChanges, /*61*/
	osquery::tables::genContainerLabels, /*62*/
	osquery::tables::genContainerMounts, /*63*/
	osquery::tables::genContainerNetworks, /*64*/
	osquery::tables::genContainerPorts, /*65*/
	osquery::tables::genContainerProcesses, /*66*/
	osquery::tables::genContainerStats, /*67*/
	osquery::tables::genContainers, /*68*/
	osquery::tables::genImageHistory, /*69*/
	osquery::tables::genImageLabels, /*70*/
	osquery::tables::genImageLayers, /*71*/
	osquery::tables::genImages, /*72*/
	osquery::tables::genInfo, /*73*/
	osquery::tables::genNetworkLabels, /*74*/
	osquery::tables::genNetworks, /*75*/
	osquery::tables::genVersion, /*76*/
	osquery::tables::genVolumeLabels, /*77*/
	osquery::tables::genVolumes, /*78*/
	nullptr /*osquery::tables::genDrivers*/ /* 79 */,
	osquery::tables::genEc2Metadata, /*80*/
	osquery::tables::genEc2InstanceTags, /*81*/
	nullptr /*osquery::tables::genTable*/ /* 82 */,
	nullptr /*osquery::tables::genTable*/ /* 83 */,
	osquery::tables::genEtcHosts, /*84*/
	osquery::tables::genEtcProtocols, /*85*/
	osquery::tables::genEtcServices, /*86*/
	nullptr /*osquery::tables::genEventtaps*/ /* 87 */,
	osquery::tables::genXattr, /*88*/
	nullptr /*osquery::tables::genFanspeedsensors*/ /* 89 */,
	osquery::tables::genFile, /*90*/
	nullptr /*file_events::genTable*/ /* 91 */,
	osquery::tables::genFirefoxAddons, /*92*/
	nullptr /*osquery::tables::genGatekeeper*/ /* 93 */,
	nullptr /*osquery::tables::genGatekeeperapprovedapps*/ /* 94 */,
	osquery::tables::genGroups, /*95*/
	nullptr /*hardware_events::genTable*/ /* 96 */,
	osquery::tables::genHash, /*97*/
	nullptr /*osquery::tables::genHomebrewpackages*/ /* 98 */,
	nullptr /*osquery::tables::genIbridgeinfo*/ /* 99 */,
	nullptr /*osquery::tables::genIeextensions*/ /* 100 */,
	osquery::tables::getIntelMEInfo /* 101 */,
	osquery::tables::genInterfaceAddresses, /*102*/
	osquery::tables::genInterfaceDetails, /*103*/
	osquery::tables::genInterfaceIpv6, /*104*/
	nullptr /*osquery::tables::genIokitdevicetree*/ /* 105 */,
	nullptr /*osquery::tables::genIokitregistry*/ /* 106 */,
	osquery::tables::genIptables, /*107*/
	nullptr /*osquery::tables::genKernelextensions*/ /* 108 */,
	osquery::tables::genKernelInfo, /*109*/
	osquery::tables::genKernelKeys, /*110*/
	osquery::tables::genKernelModules, /*111*/
	nullptr /*osquery::tables::genKernelpanics*/ /* 112 */,
	nullptr /*osquery::tables::genKeychainaclapps*/ /* 113 */,
	nullptr /*osquery::tables::genKeychainitems*/ /* 114 */,
	osquery::tables::getKnownHostsKeys /* 115 */,
	nullptr /*osquery::tables::genKvaspeculative*/ /* 116 */,
	osquery::tables::genLastAccess, /*117*/
	nullptr /*osquery::tables::genLaunchd*/ /* 118 */,
	nullptr /*osquery::tables::genLaunchdoverrides*/ /* 119 */,
	osquery::tables::genListeningPorts, /*120*/
	osquery::tables::genLoadAverage, /*121*/
	nullptr /*osquery::tables::genLocationservices*/ /* 122 */,
	osquery::tables::genLoggedInUsers, /*123*/
	nullptr /*osquery::tables::genLogicaldrives*/ /* 124 */,
	nullptr /*osquery::tables::genQuerylogonsessions*/ /* 125 */,
	osquery::tables::genLxdCerts, /*126*/
	osquery::tables::genLxdCluster, /*127*/
	osquery::tables::genLxdClusterMembers, /*128*/
	osquery::tables::genLxdImages, /*129*/
	osquery::tables::genLxdInstanceConfig, /*130*/
	osquery::tables::genLxdInstanceDevices, /*131*/
	osquery::tables::genLxdInstances, /*132*/
	osquery::tables::genLxdNetworks, /*133*/
	osquery::tables::genLxdStoragePools, /*134*/
	osquery::tables::genMagicData, /*135*/
	nullptr /*osquery::tables::genManagedpolicies*/ /* 136 */,
	osquery::tables::genMDDevices, /*137*/
	osquery::tables::genMDDrives, /*138*/
	osquery::tables::genMDPersonalities, /*139*/
	nullptr /*osquery::tables::genMdfindresults*/ /* 140 */,
	nullptr /*osquery::tables::genMdlsresults*/ /* 141 */,
	osquery::tables::genMemoryArrayMappedAddresses, /*142*/
	osquery::tables::genMemoryArrays, /*143*/
	osquery::tables::genMemoryDeviceMappedAddresses, /*144*/
	osquery::tables::genMemoryDevices, /*145*/
	osquery::tables::genMemoryErrorInfo, /*146*/
	osquery::tables::getMemoryInfo /* 147 */,
	osquery::tables::genMemoryMap, /*148*/
	osquery::tables::genMounts, /*149*/
	osquery::tables::genModelSpecificRegister, /*150*/
	nullptr /*osquery::tables::genNfsshares*/ /* 151 */,
	osquery::tables::genNodePackages, /*152*/
	nullptr /*osquery::tables::genNtdomains*/ /* 153 */,
	nullptr /*osquery::tables::genNtfsaclperms*/ /* 154 */,
	nullptr /*osquery::tables::genTable*/ /* 155 */,
	nullptr /*osquery::tables::genNvram*/ /* 156 */,
	osquery::tables::genOEMStrings, /*157*/
	nullptr /*osquery::tables::genOfficemru*/ /* 158 */,
	osquery::tables::genOSVersion, /*159*/
	osquery::tables::genOsqueryEvents, /*160*/
	osquery::tables::genOsqueryExtensions, /*161*/
	osquery::tables::genOsqueryFlags, /*162*/
	osquery::tables::genOsqueryInfo, /*163*/
	osquery::tables::genOsqueryPacks, /*164*/
	osquery::tables::genOsqueryRegistry, /*165*/
	osquery::tables::genOsquerySchedule, /*166*/
	nullptr /*osquery::tables::genPackagebom*/ /* 167 */,
	nullptr /*osquery::tables::genPackageinstallhistory*/ /* 168 */,
	nullptr /*osquery::tables::genPackagereceipts*/ /* 169 */,
	nullptr /*osquery::tables::genPasswordpolicy*/ /* 170 */,
	nullptr /*osquery::tables::genInstalledpatches*/ /* 171 */,
	osquery::tables::genPCIDevices, /*172*/
	nullptr /*osquery::tables::genPhysicaldiskperformance*/ /* 173 */,
	nullptr /*osquery::tables::genPipes*/ /*174*/,
	osquery::tables::genPlatformInfo, /*175*/
	nullptr /*osquery::tables::genOsxplist*/ /* 176 */,
	osquery::tables::genPortageKeywordSummary, /*177*/
	osquery::tables::portagePackages /* 178 */,
	osquery::tables::genPortageUse, /*179*/
	nullptr /*osquery::tables::genPowersensors*/ /* 180 */,
	nullptr /*osquery::tables::genTable*/ /* 181 */,
	nullptr /*osquery::tables::genOsxdefaultpreferences*/ /* 182 */,
	nullptr /*osquery::tables::genPrefetch*/ /* 183 */,
	osquery::tables::genProcessEnvs, /*184*/
	nullptr /*osquery::tables::genTable*/ /* 185 */,
	nullptr /*bpf_process_events::genTable*/ /* 186 */,
	nullptr /*process_file_events::genTable*/ /* 187 */,
	osquery::tables::genProcessMemoryMap, /*188*/
	osquery::tables::genProcessNamespaces, /*189*/
	osquery::tables::genOpenFiles, /*190*/
	osquery::tables::genPipes, /*191*/
	osquery::tables::genOpenSockets, /*192*/
	nullptr /*osquery::tables::genProcesses*/ /* 193 */,
	nullptr /*osquery::tables::genPrograms*/ /* 194 */,
	osquery::tables::genPrometheusMetrics, /*195*/
	osquery::tables::genPythonPackages, /*196*/
	nullptr /*osquery::tables::genQuicklookcache*/ /* 197 */,
	nullptr /*osquery::tables::genRegistry*/ /* 198 */,
	osquery::tables::genRoutes, /*199*/
	nullptr /*osquery::tables::genRpmPackageFiles*/ /* 200 */, /* not event but generator*/
	osquery::tables::genRpmPackages, /*201*/
	nullptr /*osquery::tables::genRunningapps*/ /* 202 */,
	nullptr /*osquery::tables::genSafariextensions*/ /* 203 */,
	nullptr /*osquery::tables::genSandboxcontainers*/ /* 204 */,
	nullptr /*osquery::tables::genScheduledtasks*/ /* 205 */,
	nullptr /*osquery::tables::genScreenlock*/ /* 206 */,
	nullptr /*seccomp_events::genTable*/ /* 207 */,
	osquery::tables::genSecureBoot, /*208*/
	nullptr /*osquery::tables::genSecurityprofileinformation*/ /* 209 */,
	nullptr /*selinux_events::genTable*/ /* 210 */,
	osquery::tables::genSELinuxSettings, /*211*/
	nullptr /*osquery::tables::genServices*/ /* 212 */,
	osquery::tables::genShadow, /*213*/
	nullptr /*osquery::tables::genSharedfolders*/ /* 214 */,
	osquery::tables::genSharedMemory, /*215*/
	nullptr /*osquery::tables::genShares*/ /* 216 */,
	nullptr /*osquery::tables::genSharingpreferences*/ /* 217 */,
	nullptr /*osquery::tables::genShellHistory*/ /* 218 */,
	nullptr /*osquery::tables::genShellbags*/ /* 219 */,
	nullptr /*osquery::tables::genShimcache*/ /* 220 */,
	nullptr /*osquery::tables::genSignature*/ /* 221 */,
	nullptr /*osquery::tables::genSipconfig*/ /* 222 */,
	osquery::tables::genSMBIOSTables, /*223*/
	nullptr /*osquery::tables::genSmckeys*/ /* 224 */,
	nullptr /*bpf_socket_events::genTable*/ /* 225 */,
	osquery::tables::getSshConfigs /* 226 */,
	osquery::tables::genStartupItems, /*227*/
	osquery::tables::genSudoers, /*228*/
	osquery::tables::genSuidBin, /*229*/
	nullptr /*SyslogEventSubscriber::genTable*/ /* 230 */,
	osquery::tables::genSystemControls, /*231*/
	nullptr /*osquery::tables::genSystemextensions*/ /* 232 */,
	osquery::tables::genSystemInfo, /*233*/
	nullptr, /*osquery::tables::genSystemdUnits,*/ /*234*/
	nullptr /*osquery::tables::genTemperaturesensors*/ /* 235 */,
	osquery::tables::genTime, /*236*/
	nullptr /*osquery::tables::genTimemachinebackups*/ /* 237 */,
	nullptr /*osquery::tables::genTimemachinedestinations*/ /* 238 */,
	nullptr /*osquery::tables::genTpminfo*/ /* 239 */,
	osquery::tables::genUlimitInfo, /*240*/
	nullptr /*osquery::tables::genUnifiedlog*/ /* 241 */,
	osquery::tables::genUptime, /*242*/
	osquery::tables::genUSBDevices, /*243*/
	nullptr /*user_events::genTable*/ /* 244 */,
	osquery::tables::genUserGroups, /*245*/
	nullptr /*osquery::tables::genTable*/ /* 246 */,
	osquery::tables::getUserSshKeys /* 247 */,
	nullptr /*osquery::tables::genUserassist*/ /* 248 */,
	osquery::tables::genUsers, /*249*/
	nullptr /*osquery::tables::genVideoinfo*/ /* 250 */,
	nullptr /*osquery::tables::genVirtualmemoryinfo*/ /* 251 */,
	osquery::tables::genVSCodeExtensions, /*252*/
	nullptr /*osquery::tables::genKnownwifinetworks*/ /* 253 */,
	nullptr /*osquery::tables::genWifistatus*/ /* 254 */,
	nullptr /*osquery::tables::genWifiscan*/ /* 255 */,
	nullptr /*osquery::tables::genBasenamedobjects*/ /* 256 */,
	nullptr /*osquery::tables::genCrashlogs*/ /* 257 */,
	nullptr /*osquery::tables::genWindowseventlog*/ /* 258 */,
	nullptr /*osquery::tables::genTable*/ /* 259 */,
	nullptr /*osquery::tables::genWindowsfirewallrules*/ /* 260 */,
	nullptr /*osquery::tables::genWinoptionalfeatures*/ /* 261 */,
	nullptr /*osquery::tables::genWindowssearch*/ /* 262 */,
	nullptr /*osquery::tables::gen_Wsc*/ /* 263 */,
	nullptr /*osquery::tables::gen_Wsp*/ /* 264 */,
	nullptr /*osquery::tables::genWindowsupdatehistory*/ /* 265 */,
	nullptr /*osquery::tables::genBiosinfo*/ /* 266 */,
	nullptr /*osquery::tables::genWmicliconsumers*/ /* 267 */,
	nullptr /*osquery::tables::genWmifilters*/ /* 268 */,
	nullptr /*osquery::tables::genFilterconsumer*/ /* 269 */,
	nullptr /*osquery::tables::genScriptconsumers*/ /* 270 */,
	nullptr /*osquery::tables::genXprotectentries*/ /* 271 */,
	nullptr /*osquery::tables::genXprotectmeta*/ /* 272 */,
	nullptr /*osquery::tables::genXprotectreports*/ /* 273 */,
	osquery::tables::genYara, /*274*/
	nullptr /*yara_events::genTable*/ /* 275 */,
	osquery::tables::genYCloudMetadata, /*276*/
	osquery::tables::genYumSrcs /*277*/
};

using osquery::QueryData;
using osquery::QueryContext;

class AQueryData
{
private:
    QueryData data;

	std::optional<std::map<std::string, std::string>::const_iterator> columnKeyIt;
public:
	AQueryData() : data(), columnKeyIt(std::nullopt){}

    AQueryData(QueryData const & qd): data(qd), columnKeyIt(std::nullopt)
    {}
    
	AQueryData(QueryData&& qd): data(std::move(qd)), columnKeyIt(std::nullopt)
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
		if (!columnKeyIt.has_value())
		{
			columnKeyIt = column.cbegin();
		}

        static std::string temp;
        
        if (columnKeyIt != column.cend())
        {
            temp = (*columnKeyIt)->first;
			columnKeyIt = std::next((*columnKeyIt));
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

  if (tableId == GEN_PROCESSES_TABLE_ID)
  {
    osquery::TableRows results = osquery::tables::genProcesses(aqc->getCtx());
    
	AQueryData* aqd = new AQueryData();

    for (auto const& tr : results)
    {
      aqd->getQd().emplace_back(tr->operator osquery::Row());
    }
    return aqd;
  }

  if (tableId == GEN_SYSTEMD_UNITS_TABLE_ID)
  {
    osquery::TableRows results = osquery::tables::genSystemdUnits(aqc->getCtx());
    
	AQueryData* aqd = new AQueryData();

    for (auto const& tr : results)
    {
      aqd->getQd().emplace_back(tr->operator osquery::Row());
    }
    return aqd;
  }

  if (virtualTables[tableId] == nullptr)
  {
	return new AQueryData(std::vector<std::map<std::string, std::string>>());
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