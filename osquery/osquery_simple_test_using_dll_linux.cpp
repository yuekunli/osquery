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


using getConstraintHandlePrototype = void*(*)();
using destroyConstraintPrototype = void(*)(void*);
using destroyQueryDataPrototype = void(*)(void*);
using addQueryConstraintPrototype = void(*)(void*, const char*, unsigned char, const char*);
using genDispatchPrototype = void*(*)(int, void*);
using getRowCountPrototype = size_t(*)(void*);
using getColumnCountPrototype = size_t(*)(void*);
using getNextKeyPrototype = const char*(*)(void*);
using getValuePrototype = const char*(*)(void*, size_t, const char*);


int test11()
{
  std::cout << "loading dynamic lib" << std::endl;
  void* dlhandle = dlopen("/home/adaptiva/osquery/build/osquery/libosqueryd.so", RTLD_NOW);
  if (!dlhandle)
  {
    std::cerr<<"Fail to load dynamic lib"<<std::endl;
    return 1;
  }
  std::cout<<"dynamic lib loaded"<<std::endl;

  std::cout<<"finding function symbols"<<std::endl;

  getConstraintHandlePrototype fptrGetConstraintHandle = reinterpret_cast<getConstraintHandlePrototype>(dlsym(dlhandle, "getConstraintHandle"));
  destroyConstraintPrototype fptrDestroyConstraint = reinterpret_cast<destroyConstraintPrototype>(dlsym(dlhandle, "destroyConstraint"));
  destroyQueryDataPrototype fptrDestroyQueryData = reinterpret_cast<destroyQueryDataPrototype>(dlsym(dlhandle, "destroyQueryData"));
  addQueryConstraintPrototype fptrAddQueryConstraint = reinterpret_cast<addQueryConstraintPrototype>(dlsym(dlhandle, "addQueryConstraint"));
  genDispatchPrototype fptrGenDispatch = reinterpret_cast<genDispatchPrototype>(dlsym(dlhandle, "genDispatch"));
  getRowCountPrototype fptrGetRowCount = reinterpret_cast<getRowCountPrototype>(dlsym(dlhandle, "getRowCount"));
  getColumnCountPrototype fptrGetColumnCount = reinterpret_cast<getColumnCountPrototype>(dlsym(dlhandle, "getColumnCount"));
  getNextKeyPrototype fptrGetNextKey = reinterpret_cast<getNextKeyPrototype>(dlsym(dlhandle, "getNextKey"));
  getValuePrototype fptrGetValue = reinterpret_cast<getValuePrototype>(dlsym(dlhandle, "getValue"));


  void* qcHandle = fptrGetConstraintHandle();

  std::cout<<"query constraint handle: " << qcHandle << std::endl;

  fptrAddQueryConstraint(qcHandle, "path", 2U, "/home/adaptiva/build.log.txt");

  void* qdHandle = fptrGenDispatch(35, qcHandle);

  std::cout<<"query data handle: " << qdHandle << std::endl;

  size_t rowCount = fptrGetRowCount(qdHandle);
  
  std::cout<<"row count: " << rowCount << std::endl;

  size_t columnCount = fptrGetColumnCount(qdHandle);

  std::cout<<"column count: " << columnCount << std::endl;

  //const char** keys = new const char*[columnCount];

  char(*keys)[256] = new char[columnCount][256];
  
  for (int i = 0; i < columnCount; ++i)
  {
    const char* key = fptrGetNextKey(qdHandle);
    memset(keys[i], 0, 256);
    memcpy(keys[i], key, strlen(key));
  }

  for (int i = 0; i < rowCount; ++i)
  {
    for (int j = 0; j < columnCount; ++j)
    {
      std::cout<<keys[j]<<": "<<fptrGetValue(qdHandle, i, keys[j])<<std::endl;
    }
  }
  delete[] keys;
  fptrDestroyConstraint(qcHandle);
  fptrDestroyQueryData(qdHandle);

  dlclose(dlhandle);

  return 0;
}
#if 0
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

#endif

int main()
{
  return  test11();

}