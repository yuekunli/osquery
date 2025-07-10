#include <iostream>
#include <vector>
#include <string>
#include <map>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

namespace osquery {
    namespace tables {
        QueryData genCpuInfo(QueryContext& context);

        QueryData genKernelInfo(QueryContext& context);
    }
}


int main()
{
    osquery::QueryContext qc{};

    //osquery::QueryData qd = osquery::tables::genCpuInfo(qc);

    osquery::QueryData qd = osquery::tables::genKernelInfo(qc);

    for (auto& row : qd)
    {
        for (auto& p : row)
        {
            std::cout << p.first << "               " << p.second << std::endl;
        }
    }

}