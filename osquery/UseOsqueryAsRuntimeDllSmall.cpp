#include <iostream>
#include <vector>
#include <string>
#include <map>

#include <Windows.h>


using genDataFuncP = std::vector<std::map<std::string, std::string>>(*)();

int main()
{
    std::cout << "Loading dll" << std::endl;
	HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
	if (!dllHandle)
	{
		std::cerr << "Fail to load Dll." << std::endl;
		return 1;
	}
    std::cout << "dll loaded" << std::endl;


	std::cout << "finding function address" << std::endl;
	genDataFuncP genKernelInfo = reinterpret_cast<genDataFuncP>(GetProcAddress(dllHandle, "genKernelInfo_ex"));

	if (!genKernelInfo)
	{
		std::cerr << "Fail to find function genKernelInfo_ex" << std::endl;
		FreeLibrary(dllHandle);
		return 2;
	}
    std::cout << "found function address" << std::endl;

	//osquery::QueryContext qc{};

	//osquery::QueryData qd = genKernelInfo(qc);

	std::vector<std::map<std::string, std::string>> qd = genKernelInfo();

	for (auto& row : qd)
	{
		for (auto& p : row)
		{
			std::cout << p.first << "     " << p.second << std::endl;
		}
	}
	
	FreeLibrary(dllHandle);
}