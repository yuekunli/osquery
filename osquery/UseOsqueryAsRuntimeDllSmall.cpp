#include <iostream>
#include <vector>
#include <string>
#include <map>

#include <Windows.h>


struct AdaConstraint {
  unsigned char op;
  std::string expr;
  AdaConstraint(unsigned char _op, char const* _expr) : op(_op), expr(_expr) {}
};

using genDataFuncP = std::vector<std::map<std::string, std::string>>(*)();
using genDataFuncWithConstraintP = std::vector<std::map<std::string, std::string>>(*)(std::vector<std::pair<std::string, std::string>>&&);
using genDispatchFunctionPrototype = std::vector<std::map<std::string, std::string>>(*)(int, std::map<std::string, std::vector<AdaConstraint>>const &);

int test1()
{
  std::cout << "Loading dll" << std::endl;
  HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
  if (!dllHandle) {
    std::cerr << "Fail to load Dll." << std::endl;
    return 1;
  }
  std::cout << "dll loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDataFuncP genKernelInfo = reinterpret_cast<genDataFuncP>(
      GetProcAddress(dllHandle, "genKernelInfo_ex"));

  if (!genKernelInfo) {
    std::cerr << "Fail to find function genKernelInfo_ex" << std::endl;
    FreeLibrary(dllHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  // osquery::QueryContext qc{};

  // osquery::QueryData qd = genKernelInfo(qc);

  std::vector<std::map<std::string, std::string>> qd = genKernelInfo();

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  FreeLibrary(dllHandle);
  return EXIT_SUCCESS;
}


int test2()
{
  std::cout << "Loading dll" << std::endl;
  HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
  if (!dllHandle) {
    std::cerr << "Fail to load Dll." << std::endl;
    return 1;
  }
  std::cout << "dll loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDataFuncWithConstraintP genFile =
      reinterpret_cast<genDataFuncWithConstraintP>(
      GetProcAddress(dllHandle, "genFile_ex"));

  if (!genFile) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    FreeLibrary(dllHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  // osquery::QueryContext qc{};

  // osquery::QueryData qd = genKernelInfo(qc);

  using OneRule = std::pair<std::string, std::string>;
  using OneRow = std::map<std::string, std::string>;

  std::vector<OneRow> qd =
      genFile(std::vector<OneRule>{OneRule{"path", "C:\\fdni.conf"}});

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  FreeLibrary(dllHandle);
  return EXIT_SUCCESS;

}

int test3() {
  std::cout << "Loading dll" << std::endl;
  HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
  if (!dllHandle) {
    std::cerr << "Fail to load Dll." << std::endl;
    return 1;
  }
  std::cout << "dll loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDispatchFunctionPrototype genDispatch =
      reinterpret_cast<genDispatchFunctionPrototype>(
          GetProcAddress(dllHandle, "genDispatch"));

  if (!genDispatch) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    FreeLibrary(dllHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  using OneRow = std::map<std::string, std::string>;

  std::map<std::string, std::vector<AdaConstraint>> constraints;

  //constraints["path"].emplace_back(2U, "C:\\fdni.conf");
  constraints["path"].emplace_back(65U, "C:\\temp\\%.txt");

  std::vector<OneRow> qd = genDispatch(34, constraints);

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  FreeLibrary(dllHandle);
  return EXIT_SUCCESS;
}


int test4() {
  std::cout << "Loading dll" << std::endl;
  HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
  if (!dllHandle) {
    std::cerr << "Fail to load Dll." << std::endl;
    return 1;
  }
  std::cout << "dll loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDispatchFunctionPrototype genDispatch =
      reinterpret_cast<genDispatchFunctionPrototype>(
          GetProcAddress(dllHandle, "genDispatch"));

  if (!genDispatch) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    FreeLibrary(dllHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  using OneRow = std::map<std::string, std::string>;

  std::map<std::string, std::vector<AdaConstraint>> constraints;

  // constraints["path"].emplace_back(2U, "C:\\fdni.conf");
  //constraints["path"].emplace_back(65U, "C:\\temp\\%.txt");
  
  constraints["pid"].emplace_back(2U, "20876");

  std::vector<OneRow> qd = genDispatch(500, constraints);

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  FreeLibrary(dllHandle);
  return EXIT_SUCCESS;
}

int testTableNoConstraint(int tableId) {
  std::cout << "Loading dll" << std::endl;
  HMODULE dllHandle = LoadLibraryA("osqueryd.dll");
  if (!dllHandle) {
    std::cerr << "Fail to load Dll." << std::endl;
    return 1;
  }
  std::cout << "dll loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDispatchFunctionPrototype genDispatch =
      reinterpret_cast<genDispatchFunctionPrototype>(
          GetProcAddress(dllHandle, "genDispatch"));

  if (!genDispatch) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    FreeLibrary(dllHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  using OneRow = std::map<std::string, std::string>;

  std::map<std::string, std::vector<AdaConstraint>> constraints;

  std::vector<OneRow> qd = genDispatch(tableId, constraints);

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  FreeLibrary(dllHandle);
  return EXIT_SUCCESS;
}

int main()
{
  try {
    testTableNoConstraint(35);
  }
  catch (const std::exception& ex)
  {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(102);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }


  try {
    testTableNoConstraint(120);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(173);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(12);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(239);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(109);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }

  try {
    testTableNoConstraint(175);
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }


}