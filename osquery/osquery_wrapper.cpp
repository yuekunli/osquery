#include <vector>
#include <string>
#include <map>
#include <iostream>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

static const int GEN_PROCESSES_TABLE_ID = 193;

struct AdaConstraint
{
    unsigned char op;
    std::string expr;
};

namespace osquery 
{
    namespace tables
    {
        TableRows genProcesses(QueryContext& context);
    }
}

namespace osquery {
	namespace tables {
		QueryData genAccountPolicyData(QueryContext& context);
		QueryData genACPITables(QueryContext& context);
		QueryData genADConfig(QueryContext& context);
		QueryData genALF(QueryContext& context);
		QueryData genALFExceptions(QueryContext& context);
		QueryData genALFExplicitAuths(QueryContext& context);
		QueryData genApps(QueryContext& context);
		QueryData genAppSchemes(QueryContext& context);
		QueryData genArpCache(QueryContext& context);
		QueryData genAsl(QueryContext& context);
		QueryData genAugeas(QueryContext& context);
		QueryData genAuthorizationMechanisms(QueryContext& context);
		QueryData genAuthorizations(QueryContext& context);
		QueryData genAzureMetadata(QueryContext& context);
		QueryData genAzureTags(QueryContext& context);
		QueryData genBatteryInfo(QueryContext& context);
		QueryData genBlockDevs(QueryContext& context);
		QueryData genBrowserPlugins(QueryContext& context);
		QueryData genCarbonBlackInfo(QueryContext& context);
		QueryData genCarves(QueryContext& context);
		QueryData genCerts(QueryContext& context);
		QueryData genChromeExtensionContentScripts(QueryContext& context);
		QueryData genChromeExtensions(QueryContext& context);
		QueryData genConnectedDisplays(QueryContext& context);
		QueryData genContainerEnvs(QueryContext& context);
		QueryData genContainerFsChanges(QueryContext& context);
		QueryData genContainerLabels(QueryContext& context);
		QueryData genContainerMounts(QueryContext& context);
		QueryData genContainerNetworks(QueryContext& context);
		QueryData genContainerPorts(QueryContext& context);
		QueryData genContainerProcesses(QueryContext& context);
		QueryData genContainers(QueryContext& context);
		QueryData genContainerStats(QueryContext& context);
		QueryData genCpuInfo(QueryContext& context);
		QueryData genCpuTime(QueryContext& context);
		//QueryData genCPUID(QueryContext& context);
		QueryData genCrashLogs(QueryContext& context);
		QueryData genCronTab(QueryContext& context);
		QueryData genCupsDestinations(QueryContext& context);
		QueryData genCupsJobs(QueryContext& context);
		QueryData genCurl(QueryContext& context);
		QueryData genDeviceFile(QueryContext& context);
		QueryData genDeviceFirmware(QueryContext& context);
		QueryData genDeviceHash(QueryContext& context);
		QueryData genDevicePartitions(QueryContext& context);
		QueryData genDNSResolvers(QueryContext& context);
		QueryData genEc2InstanceTags(QueryContext& context);
		QueryData genEc2Metadata(QueryContext& context);
		QueryData genEtcHosts(QueryContext& context);
		QueryData genEtcProtocols(QueryContext& context);
		QueryData genEtcServices(QueryContext& context);
		QueryData genEventTaps(QueryContext& context);
		QueryData genExample(QueryContext& context);
		QueryData genFanSpeedSensors(QueryContext& context);
		QueryData genFDEStatus(QueryContext& context);
		QueryData genFile(QueryContext& context);
		QueryData genFirefoxAddons(QueryContext& context);
		QueryData genGateKeeper(QueryContext& context);
		QueryData genGateKeeperApprovedApps(QueryContext& context);
		QueryData getAuthorizedKeys(QueryContext& context);
		QueryData getKnownHostsKeys(QueryContext& context);
		QueryData getSshConfigs(QueryContext& context);
		QueryData getUserSshKeys(QueryContext& context);
		QueryData genGroups(QueryContext& context);
		QueryData genHash(QueryContext& context);
		QueryData genHomebrewPackages(QueryContext& context);
		QueryData genIBridgeInfo(QueryContext& context);
		QueryData genImageHistory(QueryContext& context);
		QueryData genImageLabels(QueryContext& context);
		QueryData genImageLayers(QueryContext& context);
		QueryData genImages(QueryContext& context);
		QueryData genInfo(QueryContext& context);
		QueryData genInterfaceAddresses(QueryContext& context);
		QueryData genInterfaceDetails(QueryContext& context);
		QueryData genInterfaceIpv6(QueryContext& context);
		QueryData genIOKitDeviceTree(QueryContext& context);
		QueryData genIOKitRegistry(QueryContext& context);
		QueryData genKernelExtensions(QueryContext& context);
		QueryData genKernelInfo(QueryContext& context);
		QueryData genKernelPanics(QueryContext& context);
		QueryData genKeychainACLApps(QueryContext& context);
		QueryData genKeychainItems(QueryContext& context);
		QueryData genKnownWifiNetworks(QueryContext& context);
		QueryData genLastAccess(QueryContext& context);
		QueryData genLaunchd(QueryContext& context);
		QueryData genLaunchdOverrides(QueryContext& context);
		QueryData genListeningPorts(QueryContext& context);
		QueryData genLoadAverage(QueryContext& context);
		QueryData genLocationServices(QueryContext& context);
		QueryData genLoggedInUsers(QueryContext& context);
		QueryData genMagicData(QueryContext& context);
		QueryData genManagedPolicies(QueryContext& context);
		QueryData genMdfindResults(QueryContext& context);
		QueryData genMdlsResults(QueryContext& context);
		QueryData genMemoryArrayMappedAddresses(QueryContext& context);
		QueryData genMemoryArrays(QueryContext& context);
		QueryData genMemoryDeviceMappedAddresses(QueryContext& context);
		QueryData genMemoryDevices(QueryContext& context);
		QueryData genMemoryErrorInfo(QueryContext& context);
		QueryData genMounts(QueryContext& context);
		QueryData genNetworkLabels(QueryContext& context);
		QueryData genNetworks(QueryContext& context);
		QueryData genNFSShares(QueryContext& context);
		QueryData genNodePackages(QueryContext& context);
		QueryData genNVRAM(QueryContext& context);
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
		QueryData genOSXDefaultPreferences(QueryContext& context);
		QueryData genOSXPlist(QueryContext& context);
		QueryData genPackageBOM(QueryContext& context);
		QueryData genPackageInstallHistory(QueryContext& context);
		QueryData genPackageReceipts(QueryContext& context);
		QueryData genPasswordPolicy(QueryContext& context);
		QueryData genPCIDevices(QueryContext& context);
		QueryData genPlatformInfo(QueryContext& context);
		QueryData genPowerSensors(QueryContext& context);
		QueryData genProcessEnvs(QueryContext& context);
		QueryData genProcessMemoryMap(QueryContext& context);
		QueryData genPrometheusMetrics(QueryContext& context);
		QueryData genPythonPackages(QueryContext& context);
		QueryData genQuicklookCache(QueryContext& context);
		QueryData genRoutes(QueryContext& context);
		QueryData genRunningApps(QueryContext& context);
		QueryData genSafariExtensions(QueryContext& context);
		QueryData genSandboxContainers(QueryContext& context);
		QueryData genScreenlock(QueryContext& context);
		QueryData genSecureBoot(QueryContext& context);
		QueryData genSharedFolders(QueryContext& context);
		QueryData genSharingPreferences(QueryContext& context);
		QueryData genShellHistory(QueryContext& context);
		QueryData genSignature(QueryContext& context);
		QueryData genSIPConfig(QueryContext& context);
		QueryData genSMBIOSTables(QueryContext& context);
		QueryData genSMCKeys(QueryContext& context);
		QueryData getSshConfigs(QueryContext& context);
		QueryData genStartupItems(QueryContext& context);
		QueryData genSudoers(QueryContext& context);
		QueryData genSuidBin(QueryContext& context);
		QueryData genSystemControls(QueryContext& context);
		QueryData genSystemExtensions(QueryContext& context);
		QueryData genSystemInfo(QueryContext& context);
		QueryData genTemperatureSensors(QueryContext& context);
		QueryData genTime(QueryContext& context);
		QueryData genTimeMachineBackups(QueryContext& context);
		QueryData genTimeMachineDestinations(QueryContext& context);
		QueryData genTLSCertificate(QueryContext& context);
		QueryData genUlimitInfo(QueryContext& context);
		QueryData genUnifiedLog(QueryContext& context);
		QueryData genUptime(QueryContext& context);
		QueryData genUSBDevices(QueryContext& context);
		QueryData genUserGroups(QueryContext& context);
		QueryData genUsers(QueryContext& context);
		QueryData genVersion(QueryContext& context);
		QueryData genVirtualMemoryInfo(QueryContext& context);
		QueryData genVolumeLabels(QueryContext& context);
		QueryData genVolumes(QueryContext& context);
		QueryData genVSCodeExtensions(QueryContext& context);
		QueryData genWifiScan(QueryContext& context);
		QueryData genWifiStatus(QueryContext& context);
		QueryData genXattr(QueryContext& context);
		QueryData genXProtectEntries(QueryContext& context);
		QueryData genXProtectMeta(QueryContext& context);
		QueryData genXProtectReports(QueryContext& context);
		QueryData genYara(QueryContext& context);
		QueryData genYCloudMetadata(QueryContext& context);
	}
}

using genDataFuncPtr = osquery::QueryData(*)(osquery::QueryContext&);

genDataFuncPtr virtualTables[] = 
{
	osquery::tables::genAccountPolicyData, /*0*/
	osquery::tables::genACPITables, /*1*/
	osquery::tables::genADConfig, /*2*/
	osquery::tables::genALF, /*3*/
	osquery::tables::genALFExceptions, /*4*/
	osquery::tables::genALFExplicitAuths, /*5*/
	osquery::tables::genAppSchemes, /*6*/
	nullptr, /*apparmor_events*/ /*7*/
	nullptr, /*apparmor_profiles*/ /*8*/
	nullptr, /*appcompat_shims*/ /*9*/
	osquery::tables::genApps, /*10*/
	nullptr, /*apt_sources*/ /*11*/
	osquery::tables::genArpCache, /*12*/
	osquery::tables::genAsl, /*13*/
	osquery::tables::genAugeas, /*14*/
	nullptr, /*authenticode*/ /*15*/
	osquery::tables::genAuthorizationMechanisms, /*16*/
	osquery::tables::genAuthorizations, /*17*/
	osquery::tables::getAuthorizedKeys, /*18*/
	nullptr, /*autoexec*/ /*19*/
	osquery::tables::genAzureMetadata, /*20*/
	osquery::tables::genAzureTags, /*21*/
	nullptr, /*azure_instance_tags*/ /*22*/
	osquery::tables::genBatteryInfo, /*23*/
	nullptr, /*bitlocker_info*/ /*24*/
	osquery::tables::genBlockDevs, /*25*/
	nullptr, /*bpf_process_events*/ /*26*/
	nullptr, /*bpf_socket_events*/ /*27*/
	osquery::tables::genBrowserPlugins, /*28*/
	osquery::tables::genCarbonBlackInfo, /*29*/
	osquery::tables::genCarves, /*30*/
	osquery::tables::genCerts, /*31*/
	nullptr, /*chassis_info*/ /*32*/
	nullptr, /*chocolatey_packages*/ /*33*/
	osquery::tables::genChromeExtensionContentScripts, /*34*/
	osquery::tables::genChromeExtensions, /*35*/
	osquery::tables::genConnectedDisplays, /*36*/
	nullptr, /*connectivity*/ /*37*/
	osquery::tables::genCpuInfo, /*38*/
	osquery::tables::genCpuTime, /*39*/
	nullptr, /*osquery::tables::genCPUID*/ /*40*/ /*?*/
	osquery::tables::genCrashLogs, /*41*/
	osquery::tables::genCronTab, /*42*/
	osquery::tables::genCupsDestinations, /*43*/
	osquery::tables::genCupsJobs, /*44*/
	osquery::tables::genCurl, /*45*/
	osquery::tables::genTLSCertificate, /*46*/
	nullptr, /*deb_packages*/ /*47*/
	nullptr, /*default_environment*/ /*48*/
	osquery::tables::genDeviceFile, /*49*/
	osquery::tables::genDeviceFirmware, /*50*/
	osquery::tables::genDeviceHash, /*51*/
	osquery::tables::genDevicePartitions, /*52*/
	nullptr, /*deviceguard_status*/ /*53*/
	osquery::tables::genFDEStatus, /*54*/
	nullptr, /*disk_events::genTable*/ /*55*/
	nullptr, /*disk_info*/ /*56*/
	nullptr, /*dns_cache*/ /*57*/
	nullptr, /*dns_lookup_events*/ /*58*/
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
	nullptr, /*drivers*/ /*79*/
	osquery::tables::genEc2Metadata, /*80*/
	osquery::tables::genEc2InstanceTags, /*81*/
	nullptr, /*es_process_events::genTable*/ /*82*/
	nullptr, /*es_process_file_events::genTable*/ /*83*/
	osquery::tables::genEtcHosts, /*84*/
	osquery::tables::genEtcProtocols, /*85*/
	osquery::tables::genEtcServices, /*86*/
	osquery::tables::genEventTaps, /*87*/
	osquery::tables::genXattr, /*88*/
	osquery::tables::genFanSpeedSensors, /*89*/
	osquery::tables::genFile, /*90*/
	nullptr, /*file_events::genTable*/ /*91*/
	osquery::tables::genFirefoxAddons, /*92*/
	osquery::tables::genGateKeeper, /*93*/
	osquery::tables::genGateKeeperApprovedApps, /*94*/
	osquery::tables::genGroups, /*95*/
	nullptr, /*hardware_events::genTable*/ /*96*/
	osquery::tables::genHash, /*97*/
	osquery::tables::genHomebrewPackages, /*98*/
	osquery::tables::genIBridgeInfo, /*99*/
	nullptr, /*ie_extensions*/ /*100*/
	nullptr, /*intel_me_info*/ /*101*/
	osquery::tables::genInterfaceAddresses, /*102*/
	osquery::tables::genInterfaceDetails, /*103*/
	osquery::tables::genInterfaceIpv6, /*104*/
	osquery::tables::genIOKitDeviceTree, /*105*/
	osquery::tables::genIOKitRegistry, /*106*/
	nullptr, /*iptables*/ /*107*/
	osquery::tables::genKernelExtensions, /*108*/
	osquery::tables::genKernelInfo, /*109*/
	nullptr, /*kernel_keys*/ /*110*/
	nullptr, /*kernel_modules*/ /*111*/
	osquery::tables::genKernelPanics, /*112*/
	osquery::tables::genKeychainACLApps, /*113*/
	osquery::tables::genKeychainItems, /*114*/
	osquery::tables::getKnownHostsKeys, /*115*/
	nullptr, /*kva_speculative_info*/ /*116*/
	osquery::tables::genLastAccess, /*117*/
	osquery::tables::genLaunchd, /*118*/
	osquery::tables::genLaunchdOverrides, /*119*/
	osquery::tables::genListeningPorts, /*120*/
	osquery::tables::genLoadAverage, /*121*/
	osquery::tables::genLocationServices, /*122*/
	osquery::tables::genLoggedInUsers, /*123*/
	nullptr, /*logical_drives*/ /*124*/
	nullptr, /*logon_sessions*/ /*125*/
	nullptr, /*lxd_certificates*/ /*126*/
	nullptr, /*lxd_cluster*/ /*127*/
	nullptr, /*lxd_cluster_members*/ /*128*/
	nullptr, /*lxd_images*/ /*129*/
	nullptr, /*lxd_instance_config*/ /*130*/
	nullptr, /*lxd_instance_configs*/ /*131*/
	nullptr, /*lxd_instances*/ /*132*/
	nullptr, /*lxd_networks*/ /*133*/
	nullptr, /*lxd_storage_pools*/ /*134*/
	osquery::tables::genMagicData, /*135*/
	osquery::tables::genManagedPolicies, /*136*/
	nullptr, /*md_devices*/ /*137*/
	nullptr, /*md_drives*/ /*138*/
	nullptr, /*md_personalities*/ /*139*/
	osquery::tables::genMdfindResults, /*140*/
	osquery::tables::genMdlsResults, /*141*/
	osquery::tables::genMemoryArrayMappedAddresses, /*142*/
	osquery::tables::genMemoryArrays, /*143*/
	osquery::tables::genMemoryDeviceMappedAddresses, /*144*/
	osquery::tables::genMemoryDevices, /*145*/
	osquery::tables::genMemoryErrorInfo, /*146*/
	nullptr, /*memory_info*/ /*147*/
	nullptr, /*memory_map*/ /*148*/
	osquery::tables::genMounts, /*149*/
	nullptr, /*msr*/ /*150*/
	osquery::tables::genNFSShares, /*151*/
	osquery::tables::genNodePackages, /*152*/
	nullptr, /*ntdomains*/ /*153*/
	nullptr, /*ntfs_acl_permissions*/ /*154*/
	nullptr, /*ntfs_journal_events*/ /*155*/
	osquery::tables::genNVRAM, /*156*/
	osquery::tables::genOEMStrings, /*157*/
	nullptr, /*office_mru*/ /*158*/
	osquery::tables::genOSVersion, /*159*/
	osquery::tables::genOsqueryEvents, /*160*/
	osquery::tables::genOsqueryExtensions, /*161*/
	osquery::tables::genOsqueryFlags, /*162*/
	osquery::tables::genOsqueryInfo, /*163*/
	osquery::tables::genOsqueryPacks, /*164*/
	osquery::tables::genOsqueryRegistry, /*165*/
	osquery::tables::genOsquerySchedule, /*166*/
	osquery::tables::genPackageBOM, /*167*/
	osquery::tables::genPackageInstallHistory, /*168*/
	osquery::tables::genPackageReceipts, /*169*/
	osquery::tables::genPasswordPolicy, /*170*/
	nullptr, /*patches*/ /*171*/
	osquery::tables::genPCIDevices, /*172*/
	nullptr, /*physical_disk_performance*/ /*173*/
	nullptr, /*pipes*/ /*174*/
	osquery::tables::genPlatformInfo, /*175*/
	osquery::tables::genOSXPlist, /*176*/
	nullptr, /*portage_keywords*/ /*177*/
	nullptr, /*portage_packages*/ /*178*/
	nullptr, /*portage_use*/ /*179*/
	osquery::tables::genPowerSensors, /*180*/
	nullptr, /*powershell_events*/ /*181*/
	osquery::tables::genOSXDefaultPreferences, /*182*/
	nullptr, /*prefetch*/ /*183*/
	osquery::tables::genProcessEnvs, /*184*/
	nullptr, /*process_etw_events*/ /*185*/
	nullptr, /*process_events::genTable*/ /*186*/
	nullptr, /*process_file_events*/ /*187*/
	osquery::tables::genProcessMemoryMap, /*188*/
	nullptr, /*process_namespaces*/ /*189*/
	osquery::tables::genOpenFiles, /*190*/
	nullptr, /*process_open_pipes*/ /*191*/
	osquery::tables::genOpenSockets, /*192*/
	nullptr, /*processes*/ /*193*/ /*different signature*/
	nullptr, /*programs*/ /*194*/
	osquery::tables::genPrometheusMetrics, /*195*/
	osquery::tables::genPythonPackages, /*196*/
	osquery::tables::genQuicklookCache, /*197*/
	nullptr, /*registry*/ /*198*/
	osquery::tables::genRoutes, /*199*/
	nullptr, /*rpm_package_files*/ /*200*/
	nullptr, /*rpm_packages*/ /*201*/
	osquery::tables::genRunningApps, /*202*/
	osquery::tables::genSafariExtensions, /*203*/
	osquery::tables::genSandboxContainers, /*204*/
	nullptr, /*scheduled_tasks*/ /*205*/
	osquery::tables::genScreenlock, /*206*/
	nullptr, /*seccomp_events*/ /*207*/
	osquery::tables::genSecureBoot, /*208*/
	nullptr, /*security_profile_info*/ /*209*/
	nullptr, /*selinux_events*/ /*210*/
	nullptr, /*selinux_settings*/ /*211*/
	nullptr, /*services*/ /*212*/
	nullptr, /*shadow*/ /*213*/
	osquery::tables::genSharedFolders, /*214*/
	nullptr, /*shared_memory*/ /*215*/
	nullptr, /*shared_resources*/ /*216*/
	osquery::tables::genSharingPreferences, /*217*/
	nullptr, /*osquery::tables::genShellHistory*/ /*218*/ /*not event but generator*/
	nullptr, /*shellbags*/ /*219*/
	nullptr, /*shimcache*/ /*220*/
	osquery::tables::genSignature, /*221*/
	osquery::tables::genSIPConfig, /*222*/
	osquery::tables::genSMBIOSTables, /*223*/
	osquery::tables::genSMCKeys, /*224*/
	nullptr, /*socket_events::genTable*/ /*225*/
	osquery::tables::getSshConfigs, /*226*/
	osquery::tables::genStartupItems, /*227*/
	osquery::tables::genSudoers, /*228*/
	osquery::tables::genSuidBin, /*229*/
	nullptr, /*syslog_events*/ /*230*/
	osquery::tables::genSystemControls, /*231*/
	osquery::tables::genSystemExtensions, /*232*/
	osquery::tables::genSystemInfo, /*233*/
	nullptr, /*systemd_units*/ /*234*/
	osquery::tables::genTemperatureSensors, /*235*/
	osquery::tables::genTime, /*236*/
	osquery::tables::genTimeMachineBackups, /*237*/
	osquery::tables::genTimeMachineDestinations, /*238*/
	nullptr, /*tpm_info*/ /*239*/
	osquery::tables::genUlimitInfo, /*240*/
	osquery::tables::genUnifiedLog, /*241*/
	osquery::tables::genUptime, /*242*/
	osquery::tables::genUSBDevices, /*243*/
	nullptr, /*user_events::genTable*/ /*244*/
	osquery::tables::genUserGroups, /*245*/
	nullptr, /*user_interaction_events::genTable*/ /*246*/
	osquery::tables::getUserSshKeys, /*247*/
	nullptr, /*userassist*/ /*248*/
	osquery::tables::genUsers, /*249*/
	nullptr, /*video_info*/ /*250*/
	osquery::tables::genVirtualMemoryInfo, /*251*/
	osquery::tables::genVSCodeExtensions, /*252*/
	osquery::tables::genKnownWifiNetworks, /*253*/
	osquery::tables::genWifiStatus, /*254*/
	osquery::tables::genWifiScan, /*255*/
	nullptr, /*winbaseobj*/ /*256*/
	nullptr, /*windows_crashes*/ /*257*/
	nullptr, /*windows_eventlog*/ /*258*/
	nullptr, /*windows_events*/ /*259*/
	nullptr, /*windows_firewall_rules*/ /*260*/
	nullptr, /*windows_optional_features*/ /*261*/
	nullptr, /*windows_search*/ /*262*/
	nullptr, /*windows_security_center*/ /*263*/
	nullptr, /*windows_security_products*/ /*264*/
	nullptr, /*windows_update_history*/ /*265*/
	nullptr, /*wmi_bios_info*/ /*266*/
	nullptr, /*wmi_cli_event_consumers*/ /*267*/
	nullptr, /*wmi_event_filters*/ /*268*/
	nullptr, /*wmi_filter_consumer_binding*/ /*269*/
	nullptr, /*wmi_script_event_consumers*/ /*270*/
	osquery::tables::genXProtectEntries, /*271*/
	osquery::tables::genXProtectMeta, /*272*/
	osquery::tables::genXProtectReports, /*273*/
	osquery::tables::genYara, /*274*/
	nullptr, /*yara_events::genTable*/ /*275*/
	osquery::tables::genYCloudMetadata, /*276*/
	nullptr /*yum_sources*/ /*277*/
};

extern "C" __attribute__((visibility("default")))
std::vector<std::map<std::string, std::string>> genDispatch(int tableId, std::map<std::string, std::vector<AdaConstraint>>const & constraints)
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
		std::cout<<"table id maps to nullptr, "<< tableId <<std::endl;
		return std::vector<std::map<std::string, std::string>>();
    }
    
    return (virtualTables[tableId])(ctx);
}
