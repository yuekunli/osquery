// UseOsqueryAsStaticLib.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <string>
#include <map>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

/*
namespace osquery {
    using RowData = std::string;

    using Row = std::map<std::string, RowData>;
}

namespace osquery {
    using QueryData = std::vector<Row>;
}

namespace osquery{
    struct QueryContext;
}
*/
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
