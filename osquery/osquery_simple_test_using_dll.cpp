#include <iostream>
#include <vector>
#include <string>
#include <map>

#include<dlfcn.h>

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
  std::cout << "Loading dynamic library" << std::endl;
  void* soHandle = dlopen("libosqueryd.so", RTLD_NOW);
  if (!soHandle) {
    std::cerr << "Fail to load dynamic lib." << std::endl;
    return 1;
  }
  std::cout << "dynamic lib loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDataFuncP genKernelInfo = reinterpret_cast<genDataFuncP>(
      dlsym(soHandle, "genKernelInfo_ex"));

  if (!genKernelInfo) {
    std::cerr << "Fail to find function genKernelInfo_ex" << std::endl;
    dlclose(soHandle);
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

  dlclose(soHandle);
  return 0;
}


int test2()
{
  std::cout << "Loading dynamic lib" << std::endl;
  void* soHandle = dlopen("libosqueryd.so", RTLD_NOW);
  if (!soHandle) {
    std::cerr << "Fail to load dynamic lib." << std::endl;
    return 1;
  }
  std::cout << "dynamic lib loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDataFuncWithConstraintP genFile =
      reinterpret_cast<genDataFuncWithConstraintP>(
      dlsym(soHandle, "genFile_ex"));

  if (!genFile) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    dlclose(soHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  // osquery::QueryContext qc{};

  // osquery::QueryData qd = genKernelInfo(qc);

  using OneRule = std::pair<std::string, std::string>;
  using OneRow = std::map<std::string, std::string>;

  std::vector<OneRow> qd =
      genFile(std::vector<OneRule>{OneRule{"path", "/home/adaptiva/fdni.conf"}});

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  dlclose(soHandle);
  return 0;

}

int test3() {
  std::cout << "Loading dynamic lib" << std::endl;
  void* soHandle = dlopen("/home/adaptiva/osquery/build/osquery/libosqueryd.so", RTLD_NOW);
  if (!soHandle) {
    std::cerr << "Fail to load dynamic lib.   " << dlerror() << std::endl;
    return 1;
  }
  std::cout << "dynamic lib loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDispatchFunctionPrototype genDispatch =
      reinterpret_cast<genDispatchFunctionPrototype>(
          dlsym(soHandle, "genDispatch"));

  if (!genDispatch) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    dlclose(soHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  using OneRow = std::map<std::string, std::string>;

  std::map<std::string, std::vector<AdaConstraint>> constraints;

  //constraints["path"].emplace_back(2U, "C:\\fdni.conf");
  constraints["path"].emplace_back(65U, "/home/adaptiva/%.txt");

  std::vector<OneRow> qd = genDispatch(35, constraints);

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  dlclose(soHandle);
  return 0;
}

int test4() {
  std::cout << "Loading dynamic lib" << std::endl;
  void* soHandle = dlopen("/opt/adaptiva/adaptivaclient/bin/libosqueryd.so", RTLD_NOW);
  if (!soHandle) {
    std::cerr << "Fail to load dynamic lib.   " << dlerror() << std::endl;
    return 1;
  }
  std::cout << "dynamic lib loaded" << std::endl;

  std::cout << "finding function address" << std::endl;
  genDispatchFunctionPrototype genDispatch =
      reinterpret_cast<genDispatchFunctionPrototype>(
          dlsym(soHandle, "genDispatch"));

  if (!genDispatch) {
    std::cerr << "Fail to find function genFile_ex" << std::endl;
    dlclose(soHandle);
    return 2;
  }
  std::cout << "found function address" << std::endl;

  using OneRow = std::map<std::string, std::string>;

  std::map<std::string, std::vector<AdaConstraint>> constraints;

  //constraints["path"].emplace_back(2U, "C:\\fdni.conf");
  constraints["path"].emplace_back(2U, "/home/yli/test/log-1");
  //constraints["pid"].emplace_back(2U, "271521");
  std::vector<OneRow> qd = genDispatch(35, constraints);

  for (auto& row : qd) {
    for (auto& p : row) {
      std::cout << p.first << "     " << p.second << std::endl;
    }
  }

  dlclose(soHandle);
  return 0;
}



int main()
{
  return  test4();

}