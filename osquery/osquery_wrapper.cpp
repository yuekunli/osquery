#include <vector>
#include <string>
#include <map>
#include <iostream>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

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

static const int GEN_PROCESSES_TABLE_ID = 193;

namespace osquery {
	namespace tables {
		QueryData gen_wsc(QueryContext& context);
		QueryData gen_wsp(QueryContext& context);
		QueryData genArpCache(QueryContext& context);
		QueryData genAuthenticode(QueryContext& context);
		QueryData genAutoexec(QueryContext& context);
		QueryData genAzureMetadata(QueryContext& context);
		QueryData genAzureTags(QueryContext& context);
		QueryData genBackgroundActivitiesModerator(QueryContext& context);
		QueryData genBaseNamedObjects(QueryContext& context);
		QueryData genBatteryInfo(QueryContext& context);
		QueryData genBiosInfo(QueryContext& context);
		QueryData genBitlockerInfo(QueryContext& context);
		QueryData genCarbonBlackInfo(QueryContext& context);
		QueryData genCarves(QueryContext& context);
		QueryData genCerts(QueryContext& context);
		QueryData genChassisInfo(QueryContext& context);
		QueryData genChocolateyPackages(QueryContext& context);
		QueryData genChromeExtensionContentScripts(QueryContext& context);
		QueryData genChromeExtensions(QueryContext& context);
		QueryData genConnectivity(QueryContext& context);
		QueryData genCPUID(QueryContext& context);
		QueryData genCpuInfo(QueryContext& context);
		QueryData genCrashLogs(QueryContext& context);
		QueryData genCurl(QueryContext& context);
		QueryData genDefaultEnvironment(QueryContext& context);
		QueryData genDeviceGuardStatus(QueryContext& context);
		QueryData genDiskInfo(QueryContext& context);
		QueryData genDnsCache(QueryContext& context);
		QueryData genDrivers(QueryContext& context);
		QueryData genEc2InstanceTags(QueryContext& context);
		QueryData genEc2Metadata(QueryContext& context);
		QueryData genEtcHosts(QueryContext& context);
		QueryData genEtcProtocols(QueryContext& context);
		QueryData genEtcServices(QueryContext& context);
		QueryData genFile(QueryContext& context);
		QueryData genFilterConsumer(QueryContext& context);
		QueryData genFirefoxAddons(QueryContext& context);
		QueryData genGroups(QueryContext& context);
		QueryData genHash(QueryContext& context);
		QueryData genIEExtensions(QueryContext& context);
		QueryData getIntelMEInfo(QueryContext& context);
		QueryData genInstalledPatches(QueryContext& context);
		QueryData genInterfaceAddresses(QueryContext& context);
		QueryData genInterfaceDetails(QueryContext& context);
		QueryData genKernelInfo(QueryContext& context);
		QueryData genKvaSpeculative(QueryContext& context);
		QueryData genListeningPorts(QueryContext& context);
		QueryData genLoggedInUsers(QueryContext& context);
		QueryData genLogicalDrives(QueryContext& context);
		QueryData queryLogonSessions(QueryContext& context);
		QueryData genMemoryDevices(QueryContext& context);
		QueryData genNodePackages(QueryContext& context);
		QueryData genNtdomains(QueryContext& context);
		QueryData genNtfsAclPerms(QueryContext& context);
		QueryData genOfficeMru(QueryContext& context);
		QueryData genOpenSockets(QueryContext& context);
		QueryData genOsqueryEvents(QueryContext& context);
		QueryData genOsqueryExtensions(QueryContext& context);
		QueryData genOsqueryFlags(QueryContext& context);
		QueryData genOsqueryInfo(QueryContext& context);
		QueryData genOsqueryPacks(QueryContext& context);
		QueryData genOsqueryRegistry(QueryContext& context);
		QueryData genOsquerySchedule(QueryContext& context);
		QueryData genOSVersion(QueryContext& context);
		QueryData genPhysicalDiskPerformance(QueryContext& context);
		QueryData genPipes(QueryContext& context);
		QueryData genPlatformInfo(QueryContext& context);
		QueryData genProcessMemoryMap(QueryContext& context);
		QueryData genPrograms(QueryContext& context);
		QueryData genPythonPackages(QueryContext& context);
		QueryData genRegistry(QueryContext& context);
		QueryData genRoutes(QueryContext& context);
		QueryData genScheduledTasks(QueryContext& context);
		QueryData genScriptConsumers(QueryContext& context);
		QueryData genSecureBoot(QueryContext& context);
		QueryData genSecurityProfileInformation(QueryContext& context);
		QueryData genServices(QueryContext& context);
		QueryData genShares(QueryContext& context);
		QueryData genShellbags(QueryContext& context);
		QueryData genShimcache(QueryContext& context);
		QueryData genShims(QueryContext& context);
		QueryData getSshConfigs(QueryContext& context);
		QueryData genStartupItems(QueryContext& context);
		QueryData genSystemInfo(QueryContext& context);
		QueryData genTime(QueryContext& context);
		QueryData genTLSCertificate(QueryContext& context);
		QueryData genTpmInfo(QueryContext& context);
		QueryData genUptime(QueryContext& context);
		QueryData genUserAssist(QueryContext& context);
		QueryData genUserGroups(QueryContext& context);
		QueryData getUserSshKeys(QueryContext& context);
		QueryData genUsers(QueryContext& context);
		QueryData genVideoInfo(QueryContext& context);
		QueryData genVSCodeExtensions(QueryContext& context);
		QueryData genWindowsFirewallRules(QueryContext& context);
		QueryData genWindowsSearch(QueryContext& context);
		QueryData genWindowsUpdateHistory(QueryContext& context);
		QueryData genWinOptionalFeatures(QueryContext& context);
		QueryData genWmiCliConsumers(QueryContext& context);
		QueryData genWmiFilters(QueryContext& context);
		QueryData genYara(QueryContext& context);
		QueryData genYCloudMetadata(QueryContext& context);
	}
}

static genDataFuncPtr virtualTables[] = {
	nullptr /*osquery::tables::genAccountpolicydata*/ /* 0 */,
	nullptr /*osquery::tables::genAcpitables*/ /* 1 */,
	nullptr /*osquery::tables::genAdconfig*/ /* 2 */,
	nullptr /*osquery::tables::genAlf*/ /* 3 */,
	nullptr /*osquery::tables::genAlfexceptions*/ /* 4 */,
	nullptr /*osquery::tables::genAlfexplicitauths*/ /* 5 */,
	nullptr /*osquery::tables::genAppschemes*/ /* 6 */,
	nullptr /*osquery::tables::genTable*/ /* 7 */,
	nullptr /*osquery::tables::genApparmorprofiles*/ /* 8 */,
	osquery::tables::genShims, /*9*/
	nullptr /*osquery::tables::genApps*/ /* 10 */,
	nullptr /*osquery::tables::genAptsrcs*/ /* 11 */,
	osquery::tables::genArpCache, /*12*/
	nullptr /*osquery::tables::genAsl*/ /* 13 */,
	nullptr /*osquery::tables::genAugeas*/ /* 14 */,
	osquery::tables::genAuthenticode, /*15*/
	nullptr /*osquery::tables::genAuthorizationmechanisms*/ /* 16 */,
	nullptr /*osquery::tables::genAuthorizations*/ /* 17 */,
	nullptr /*osquery::tables::genGetauthorizedkeys*/ /* 18 */,
	osquery::tables::genAutoexec, /*19*/
	osquery::tables::genAzureMetadata, /*20*/
	osquery::tables::genAzureTags, /*21*/
	osquery::tables::genBackgroundActivitiesModerator, /*22*/
	osquery::tables::genBatteryInfo, /*23*/
	osquery::tables::genBitlockerInfo, /*24*/
	nullptr /*osquery::tables::genBlockdevs*/ /* 25 */,
	nullptr /*osquery::tables::genTable*/ /* 26 */,
	nullptr /*osquery::tables::genTable*/ /* 27 */,
	nullptr /*osquery::tables::genBrowserplugins*/ /* 28 */,
	osquery::tables::genCarbonBlackInfo, /*29*/
	osquery::tables::genCarves, /*30*/
	osquery::tables::genCerts, /*31*/
	osquery::tables::genChassisInfo, /*32*/
	osquery::tables::genChocolateyPackages, /*33*/
	osquery::tables::genChromeExtensionContentScripts, /*34*/
	osquery::tables::genChromeExtensions, /*35*/
	nullptr /*osquery::tables::genConnecteddisplays*/ /* 36 */,
	osquery::tables::genConnectivity, /*37*/
	osquery::tables::genCpuInfo, /*38*/
	nullptr /*osquery::tables::genCputime*/ /* 39 */,
	osquery::tables::genCPUID, /*40*/
	nullptr, /*osquery::tables::genCrashLogs*/ /*41*/
	nullptr /*osquery::tables::genCrontab*/ /* 42 */,
	nullptr /*osquery::tables::genCupsdestinations*/ /* 43 */,
	nullptr /*osquery::tables::genCupsjobs*/ /* 44 */,
	osquery::tables::genCurl, /*45*/
	osquery::tables::genTLSCertificate, /*46*/
	nullptr /*osquery::tables::genDebpackages*/ /* 47 */,
	osquery::tables::genDefaultEnvironment, /*48*/
	nullptr /*osquery::tables::genDevicefile*/ /* 49 */,
	nullptr /*osquery::tables::genDevicefirmware*/ /* 50 */,
	nullptr /*osquery::tables::genDevicehash*/ /* 51 */,
	nullptr /*osquery::tables::genDevicepartitions*/ /* 52 */,
	osquery::tables::genDeviceGuardStatus, /*53*/
	nullptr /*osquery::tables::genFdestatus*/ /* 54 */,
	nullptr /*osquery::tables::genTable*/ /* 55 */,
	osquery::tables::genDiskInfo, /*56*/
	osquery::tables::genDnsCache, /*57*/
	nullptr, /*dns_lookup_events@genTable*/ /* 58 */
	nullptr /*osquery::tables::genDnsresolvers*/ /* 59 */,
	nullptr /*osquery::tables::genContainerenvs*/ /* 60 */,
	nullptr /*osquery::tables::genContainerfschanges*/ /* 61 */,
	nullptr /*osquery::tables::genContainerlabels*/ /* 62 */,
	nullptr /*osquery::tables::genContainermounts*/ /* 63 */,
	nullptr /*osquery::tables::genContainernetworks*/ /* 64 */,
	nullptr /*osquery::tables::genContainerports*/ /* 65 */,
	nullptr /*osquery::tables::genContainerprocesses*/ /* 66 */,
	nullptr /*osquery::tables::genContainerstats*/ /* 67 */,
	nullptr /*osquery::tables::genContainers*/ /* 68 */,
	nullptr /*osquery::tables::genImagehistory*/ /* 69 */,
	nullptr /*osquery::tables::genImagelabels*/ /* 70 */,
	nullptr /*osquery::tables::genImagelayers*/ /* 71 */,
	nullptr /*osquery::tables::genImages*/ /* 72 */,
	nullptr /*osquery::tables::genInfo*/ /* 73 */,
	nullptr /*osquery::tables::genNetworklabels*/ /* 74 */,
	nullptr /*osquery::tables::genNetworks*/ /* 75 */,
	nullptr /*osquery::tables::genVersion*/ /* 76 */,
	nullptr /*osquery::tables::genVolumelabels*/ /* 77 */,
	nullptr /*osquery::tables::genVolumes*/ /* 78 */,
	osquery::tables::genDrivers, /*79*/
	osquery::tables::genEc2Metadata, /*80*/
	osquery::tables::genEc2InstanceTags, /*81*/
	nullptr /*es_process_events@genTable*/ /* 82 */,
	nullptr /*es_process_file_events@genTable*/ /* 83 */,
	osquery::tables::genEtcHosts, /*84*/
	osquery::tables::genEtcProtocols, /*85*/
	osquery::tables::genEtcServices, /*86*/
	nullptr /*osquery::tables::genEventtaps*/ /* 87 */,
	nullptr /*osquery::tables::genXattr*/ /* 88 */,
	nullptr /*osquery::tables::genFanspeedsensors*/ /* 89 */,
	osquery::tables::genFile, /*90*/
	nullptr /*osquery::tables::genTable*/ /* 91 */,
	osquery::tables::genFirefoxAddons, /*92*/
	nullptr /*osquery::tables::genGatekeeper*/ /* 93 */,
	nullptr /*osquery::tables::genGatekeeperapprovedapps*/ /* 94 */,
	osquery::tables::genGroups, /*95*/
	nullptr /*osquery::tables::genTable*/ /* 96 */,
	osquery::tables::genHash, /*97*/
	nullptr /*osquery::tables::genHomebrewpackages*/ /* 98 */,
	nullptr /*osquery::tables::genIbridgeinfo*/ /* 99 */,
	osquery::tables::genIEExtensions, /*100*/
	osquery::tables::getIntelMEInfo /* 101 */,
	osquery::tables::genInterfaceAddresses, /*102*/
	osquery::tables::genInterfaceDetails, /*103*/
	nullptr /*osquery::tables::genInterfaceipv6*/ /* 104 */,
	nullptr /*osquery::tables::genIokitdevicetree*/ /* 105 */,
	nullptr /*osquery::tables::genIokitregistry*/ /* 106 */,
	nullptr /*osquery::tables::genIptables*/ /* 107 */,
	nullptr /*osquery::tables::genKernelextensions*/ /* 108 */,
	osquery::tables::genKernelInfo, /*109*/
	nullptr /*osquery::tables::genKernelkeys*/ /* 110 */,
	nullptr /*osquery::tables::genKernelmodules*/ /* 111 */,
	nullptr /*osquery::tables::genKernelpanics*/ /* 112 */,
	nullptr /*osquery::tables::genKeychainaclapps*/ /* 113 */,
	nullptr /*osquery::tables::genKeychainitems*/ /* 114 */,
	nullptr /*osquery::tables::genGetknownhostskeys*/ /* 115 */,
	osquery::tables::genKvaSpeculative, /*116*/
	nullptr /*osquery::tables::genLastaccess*/ /* 117 */,
	nullptr /*osquery::tables::genLaunchd*/ /* 118 */,
	nullptr /*osquery::tables::genLaunchdoverrides*/ /* 119 */,
	osquery::tables::genListeningPorts, /*120*/
	nullptr /*osquery::tables::genLoadaverage*/ /* 121 */,
	nullptr /*osquery::tables::genLocationservices*/ /* 122 */,
	osquery::tables::genLoggedInUsers, /*123*/
	osquery::tables::genLogicalDrives, /*124*/
	osquery::tables::queryLogonSessions /* 125 */,
	nullptr /*osquery::tables::genLxdcerts*/ /* 126 */,
	nullptr /*osquery::tables::genLxdcluster*/ /* 127 */,
	nullptr /*osquery::tables::genLxdclustermembers*/ /* 128 */,
	nullptr /*osquery::tables::genLxdimages*/ /* 129 */,
	nullptr /*osquery::tables::genLxdinstanceconfig*/ /* 130 */,
	nullptr /*osquery::tables::genLxdinstancedevices*/ /* 131 */,
	nullptr /*osquery::tables::genLxdinstances*/ /* 132 */,
	nullptr /*osquery::tables::genLxdnetworks*/ /* 133 */,
	nullptr /*osquery::tables::genLxdstoragepools*/ /* 134 */,
	nullptr /*osquery::tables::genMagicdata*/ /* 135 */,
	nullptr /*osquery::tables::genManagedpolicies*/ /* 136 */,
	nullptr /*osquery::tables::genMddevices*/ /* 137 */,
	nullptr /*osquery::tables::genMddrives*/ /* 138 */,
	nullptr /*osquery::tables::genMdpersonalities*/ /* 139 */,
	nullptr /*osquery::tables::genMdfindresults*/ /* 140 */,
	nullptr /*osquery::tables::genMdlsresults*/ /* 141 */,
	nullptr /*osquery::tables::genMemoryarraymappedaddresses*/ /* 142 */,
	nullptr /*osquery::tables::genMemoryarrays*/ /* 143 */,
	nullptr /*osquery::tables::genMemorydevicemappedaddresses*/ /* 144 */,
	osquery::tables::genMemoryDevices, /*145*/
	nullptr /*osquery::tables::genMemoryerrorinfo*/ /* 146 */,
	nullptr /*osquery::tables::genGetmemoryinfo*/ /* 147 */,
	nullptr /*osquery::tables::genMemorymap*/ /* 148 */,
	nullptr /*osquery::tables::genMounts*/ /* 149 */,
	nullptr /*osquery::tables::genModelspecificregister*/ /* 150 */,
	nullptr /*osquery::tables::genNfsshares*/ /* 151 */,
	osquery::tables::genNodePackages, /*152*/
	osquery::tables::genNtdomains, /*153*/
	osquery::tables::genNtfsAclPerms, /*154*/
	nullptr /*NTFSEventSubscriber::genTable*/ /* 155 */,
	nullptr /*osquery::tables::genNvram*/ /* 156 */,
	nullptr /*osquery::tables::genOemstrings*/ /* 157 */,
	osquery::tables::genOfficeMru, /*158*/
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
	osquery::tables::genInstalledPatches, /*171*/
	nullptr /*osquery::tables::genPcidevices*/ /* 172 */,
	osquery::tables::genPhysicalDiskPerformance, /*173*/
	osquery::tables::genPipes, /*174*/
	osquery::tables::genPlatformInfo, /*175*/
	nullptr /*osquery::tables::genOsxplist*/ /* 176 */,
	nullptr /*osquery::tables::genPortagekeywordsummary*/ /* 177 */,
	nullptr /*osquery::tables::genPortagepackages*/ /* 178 */,
	nullptr /*osquery::tables::genPortageuse*/ /* 179 */,
	nullptr /*osquery::tables::genPowersensors*/ /* 180 */,
	nullptr /*PowershellEventSubscriber::genTable*/ /* 181 */,
	nullptr /*osquery::tables::genOsxdefaultpreferences*/ /* 182 */,
	nullptr /*osquery::tables::genPrefetch*/ /* 183 */, /*not event but generator*/
	nullptr /*osquery::tables::genProcessenvs*/ /* 184 */,
	nullptr /*etw_process_events::genTable*/ /* 185 */,
	nullptr /*osquery::tables::genTable*/ /* 186 */,
	nullptr /*osquery::tables::genTable*/ /* 187 */,
	osquery::tables::genProcessMemoryMap, /*188*/
	nullptr /*osquery::tables::genProcessnamespaces*/ /* 189 */,
	nullptr /*osquery::tables::genOpenfiles*/ /* 190 */,
	nullptr, /*osquery::tables::genPipes*/ /*191*/
	osquery::tables::genOpenSockets, /*192*/
	nullptr /*osquery::tables::genProcesses*/ /* 193 */,
	osquery::tables::genPrograms, /*194*/
	nullptr /*osquery::tables::genPrometheusmetrics*/ /* 195 */,
	osquery::tables::genPythonPackages, /*196*/
	nullptr /*osquery::tables::genQuicklookcache*/ /* 197 */,
	osquery::tables::genRegistry, /*198*/
	osquery::tables::genRoutes, /*199*/
	nullptr /*osquery::tables::genRpmpackagefiles*/ /* 200 */,
	nullptr /*osquery::tables::genRpmpackages*/ /* 201 */,
	nullptr /*osquery::tables::genRunningapps*/ /* 202 */,
	nullptr /*osquery::tables::genSafariextensions*/ /* 203 */,
	nullptr /*osquery::tables::genSandboxcontainers*/ /* 204 */,
	osquery::tables::genScheduledTasks, /*205*/
	nullptr /*osquery::tables::genScreenlock*/ /* 206 */,
	nullptr /*osquery::tables::genTable*/ /* 207 */,
	osquery::tables::genSecureBoot, /*208*/
	osquery::tables::genSecurityProfileInformation, /*209*/
	nullptr /*osquery::tables::genTable*/ /* 210 */,
	nullptr /*osquery::tables::genSelinuxsettings*/ /* 211 */,
	osquery::tables::genServices, /*212*/
	nullptr /*osquery::tables::genShadow*/ /* 213 */,
	nullptr /*osquery::tables::genSharedfolders*/ /* 214 */,
	nullptr /*osquery::tables::genSharedmemory*/ /* 215 */,
	osquery::tables::genShares, /*216*/
	nullptr /*osquery::tables::genSharingpreferences*/ /* 217 */,
	nullptr /*osquery::tables::genShellhistory*/ /* 218 */,
	osquery::tables::genShellbags, /*219*/
	osquery::tables::genShimcache, /*220*/
	nullptr /*osquery::tables::genSignature*/ /* 221 */,
	nullptr /*osquery::tables::genSipconfig*/ /* 222 */,
	nullptr /*osquery::tables::genSmbiostables*/ /* 223 */,
	nullptr /*osquery::tables::genSmckeys*/ /* 224 */,
	nullptr /*osquery::tables::genTable*/ /* 225 */,
	osquery::tables::getSshConfigs /* 226 */,
	osquery::tables::genStartupItems, /*227*/
	nullptr /*osquery::tables::genSudoers*/ /* 228 */,
	nullptr /*osquery::tables::genSuidbin*/ /* 229 */,
	nullptr /*osquery::tables::genTable*/ /* 230 */,
	nullptr /*osquery::tables::genSystemcontrols*/ /* 231 */,
	nullptr /*osquery::tables::genSystemextensions*/ /* 232 */,
	osquery::tables::genSystemInfo, /*233*/
	nullptr /*osquery::tables::genSystemdunits*/ /* 234 */,
	nullptr /*osquery::tables::genTemperaturesensors*/ /* 235 */,
	osquery::tables::genTime, /*236*/
	nullptr /*osquery::tables::genTimemachinebackups*/ /* 237 */,
	nullptr /*osquery::tables::genTimemachinedestinations*/ /* 238 */,
	osquery::tables::genTpmInfo, /*239*/
	nullptr /*osquery::tables::genUlimitinfo*/ /* 240 */,
	nullptr /*osquery::tables::genUnifiedlog*/ /* 241 */,
	osquery::tables::genUptime, /*242*/
	nullptr /*osquery::tables::genUsbdevices*/ /* 243 */,
	nullptr /*osquery::tables::genTable*/ /* 244 */,
	osquery::tables::genUserGroups, /*245*/
	nullptr /*osquery::tables::genTable*/ /* 246 */,
	osquery::tables::getUserSshKeys /* 247 */,
	osquery::tables::genUserAssist, /*248*/
	osquery::tables::genUsers, /*249*/
	osquery::tables::genVideoInfo, /*250*/
	nullptr /*osquery::tables::genVirtualmemoryinfo*/ /* 251 */,
	osquery::tables::genVSCodeExtensions, /*252*/
	nullptr /*osquery::tables::genKnownwifinetworks*/ /* 253 */,
	nullptr /*osquery::tables::genWifistatus*/ /* 254 */,
	nullptr /*osquery::tables::genWifiscan*/ /* 255 */,
	osquery::tables::genBaseNamedObjects, /*256*/
	osquery::tables::genCrashLogs, /*257*/
	nullptr /*osquery::tables::genWindowsEventLog*/ /* 258 */, /*not event but generator*/
	nullptr /*WindowsEventSubscriber::genTable*/ /* 259 */,
	osquery::tables::genWindowsFirewallRules, /*260*/
	osquery::tables::genWinOptionalFeatures, /*261*/
	osquery::tables::genWindowsSearch, /*262*/
	osquery::tables::gen_wsc, /*263*/
	osquery::tables::gen_wsp, /*264*/
	osquery::tables::genWindowsUpdateHistory, /*265*/
	osquery::tables::genBiosInfo, /*266*/
	osquery::tables::genWmiCliConsumers, /*267*/
	osquery::tables::genWmiFilters, /*268*/
	osquery::tables::genFilterConsumer, /*269*/
	osquery::tables::genScriptConsumers, /*270*/
	nullptr /*osquery::tables::genXprotectentries*/ /* 271 */,
	nullptr /*osquery::tables::genXprotectmeta*/ /* 272 */,
	nullptr /*osquery::tables::genXprotectreports*/ /* 273 */,
	osquery::tables::genYara, /*274*/
	nullptr /*yara_events::genTable*/ /* 275 */,
	osquery::tables::genYCloudMetadata, /*276*/
	nullptr /*osquery::tables::genYumsrcs*/ /* 277 */
};

extern "C" __declspec(dllexport) std::vector<std::map<std::string, std::string>>
genDispatch(int tableId, std::map<std::string, std::vector<AdaConstraint>>const & constraints)
{
  osquery::QueryContext ctx{};

  for (auto const& entry : constraints)
  {
    for (auto const& oneRule : entry.second)
    {
      osquery::Constraint con{oneRule.op, oneRule.expr};
      ctx.constraints[entry.first].add(con);
    }
  }

  if (tableId == GEN_PROCESSES_TABLE_ID)
  {
    osquery::TableRows results = osquery::tables::genProcesses(ctx);
    osquery::QueryData data;

    for (auto const& tr : results)
    {
      data.emplace_back(tr->operator osquery::Row());
    }
    return data;
  }
  
  if (virtualTables[tableId] == nullptr)
  {
    std::cout << "table id maps to nullptr, " << tableId << std::endl;
    return std::vector<std::map<std::string, std::string>>();
  }

  return (virtualTables[tableId])(ctx);
}