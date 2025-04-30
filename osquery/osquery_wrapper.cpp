

#include <vector>
#include <string>
#include <map>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>


namespace osquery {
	namespace tables {
		QueryData genKernelInfo(QueryContext& context);
}
}

extern "C" __declspec(dllexport) std::vector<std::map<std::string, std::string>>
genKernelInfo_ex(/* osquery::QueryContext& context*/) 
{
  return osquery::tables::genKernelInfo(osquery::QueryContext{});
}