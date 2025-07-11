

#include <vector>
#include <string>
#include <map>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

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
QueryData genInstalledPatches(QueryContext& context);
QueryData genInterfaceAddresses(QueryContext& context);
QueryData genInterfaceDetails(QueryContext& context);
QueryData genKernelInfo(QueryContext& context);
QueryData genKvaSpeculative(QueryContext& context);
QueryData genListeningPorts(QueryContext& context);
QueryData genLoggedInUsers(QueryContext& context);
QueryData genLogicalDrives(QueryContext& context);
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
QueryData genStartupItems(QueryContext& context);
QueryData genSystemInfo(QueryContext& context);
QueryData genTime(QueryContext& context);
QueryData genTLSCertificate(QueryContext& context);
QueryData genTpmInfo(QueryContext& context);
QueryData genUptime(QueryContext& context);
QueryData genUserAssist(QueryContext& context);
QueryData genUserGroups(QueryContext& context);
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
} // namespace tables
} // namespace osquery


namespace osquery
{
    namespace tables
    {
TableRows genProcesses(QueryContext& context);
    }
}

extern "C" struct AdaConstraint
{
  unsigned char op;
  std::string expr;
};


using genDataFuncPtr = osquery::QueryData(*)(osquery::QueryContext&);

  genDataFuncPtr virtualTables[] = 
       {
    osquery::tables::gen_wsc, /*0*/
    osquery::tables::gen_wsp, /*1*/
    osquery::tables::genArpCache, /*2*/
    osquery::tables::genAuthenticode, /*3*/
    osquery::tables::genAutoexec, /*4*/
    osquery::tables::genAzureMetadata, /*5*/
    osquery::tables::genAzureTags, /*6*/
    osquery::tables::genBackgroundActivitiesModerator, /*7*/
    osquery::tables::genBaseNamedObjects, /*8*/
    osquery::tables::genBatteryInfo, /*9*/
    osquery::tables::genBiosInfo, /*10*/
    osquery::tables::genBitlockerInfo, /*11*/
    osquery::tables::genCarbonBlackInfo, /*12*/
    osquery::tables::genCarves, /*13*/
    osquery::tables::genCerts, /*14*/
    osquery::tables::genChassisInfo, /*15*/
    osquery::tables::genChocolateyPackages, /*16*/
    osquery::tables::genChromeExtensionContentScripts, /*17*/
    osquery::tables::genChromeExtensions, /*18*/
    osquery::tables::genConnectivity, /*19*/
    osquery::tables::genCPUID, /*20*/
    osquery::tables::genCpuInfo, /*21*/
    osquery::tables::genCrashLogs, /*22*/
    osquery::tables::genCurl, /*23*/
    osquery::tables::genDefaultEnvironment, /*24*/
    osquery::tables::genDeviceGuardStatus, /*25*/
    osquery::tables::genDiskInfo, /*26*/
    osquery::tables::genDnsCache, /*27*/
    osquery::tables::genDrivers, /*28*/
    osquery::tables::genEc2InstanceTags, /*29*/
    osquery::tables::genEc2Metadata, /*30*/
    osquery::tables::genEtcHosts, /*31*/
    osquery::tables::genEtcProtocols, /*32*/
    osquery::tables::genEtcServices, /*33*/
    osquery::tables::genFile, /*34*/
    osquery::tables::genFilterConsumer, /*35*/
    osquery::tables::genFirefoxAddons, /*36*/
    osquery::tables::genGroups, /*37*/
    osquery::tables::genHash, /*38*/
    osquery::tables::genIEExtensions, /*39*/
    osquery::tables::genInstalledPatches, /*40*/
    osquery::tables::genInterfaceAddresses, /*41*/
    osquery::tables::genInterfaceDetails, /*42*/
    osquery::tables::genKernelInfo, /*43*/
    osquery::tables::genKvaSpeculative, /*44*/
    osquery::tables::genListeningPorts, /*45*/
    osquery::tables::genLoggedInUsers, /*46*/
    osquery::tables::genLogicalDrives, /*47*/
    osquery::tables::genMemoryDevices, /*48*/
    osquery::tables::genNodePackages, /*49*/
    osquery::tables::genNtdomains, /*50*/
    osquery::tables::genNtfsAclPerms, /*51*/
    osquery::tables::genOfficeMru, /*52*/
    osquery::tables::genOpenSockets, /*53*/
    osquery::tables::genOsqueryEvents, /*54*/
    osquery::tables::genOsqueryExtensions, /*55*/
    osquery::tables::genOsqueryFlags, /*56*/
    osquery::tables::genOsqueryInfo, /*57*/
    osquery::tables::genOsqueryPacks, /*58*/
    osquery::tables::genOsqueryRegistry, /*59*/
    osquery::tables::genOsquerySchedule, /*60*/
    osquery::tables::genOSVersion, /*61*/
    osquery::tables::genPhysicalDiskPerformance, /*62*/
    osquery::tables::genPipes, /*63*/
    osquery::tables::genPlatformInfo, /*64*/
    osquery::tables::genProcessMemoryMap, /*65*/
    osquery::tables::genPrograms, /*66*/
    osquery::tables::genPythonPackages, /*67*/
    osquery::tables::genRegistry, /*68*/
    osquery::tables::genRoutes, /*69*/
    osquery::tables::genScheduledTasks, /*70*/
    osquery::tables::genScriptConsumers, /*71*/
    osquery::tables::genSecureBoot, /*72*/
    osquery::tables::genSecurityProfileInformation, /*73*/
    osquery::tables::genServices, /*74*/
    osquery::tables::genShares, /*75*/
    osquery::tables::genShellbags, /*76*/
    osquery::tables::genShimcache, /*77*/
    osquery::tables::genShims, /*78*/
    osquery::tables::genStartupItems, /*79*/
    osquery::tables::genSystemInfo, /*80*/
    osquery::tables::genTime, /*81*/
    osquery::tables::genTLSCertificate, /*82*/
    osquery::tables::genTpmInfo, /*83*/
    osquery::tables::genUptime, /*84*/
    osquery::tables::genUserAssist, /*85*/
    osquery::tables::genUserGroups, /*86*/
    osquery::tables::genUsers, /*87*/
    osquery::tables::genVideoInfo, /*88*/
    osquery::tables::genVSCodeExtensions, /*89*/
    osquery::tables::genWindowsFirewallRules, /*90*/
    osquery::tables::genWindowsSearch, /*91*/
    osquery::tables::genWindowsUpdateHistory, /*92*/
    osquery::tables::genWinOptionalFeatures, /*93*/
    osquery::tables::genWmiCliConsumers, /*94*/
    osquery::tables::genWmiFilters, /*95*/
    osquery::tables::genYara, /*96*/
    osquery::tables::genYCloudMetadata /*97*/
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

  if (tableId == 500)
  {
    osquery::TableRows results = osquery::tables::genProcesses(ctx);
    osquery::QueryData data;

    for (auto const& tr : results)
    {
      data.emplace_back(std::move(tr->operator osquery::Row()));
    }
    return data;
  }

  return (virtualTables[tableId])(ctx);
}