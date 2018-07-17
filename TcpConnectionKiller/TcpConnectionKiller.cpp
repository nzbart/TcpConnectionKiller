#include "stdafx.h"
#include <iostream>

using namespace std;

string FormatAddress(DWORD ip)
{
	struct in_addr paddr;
	paddr.S_un.S_addr = ip;

	return inet_ntoa(paddr);
}

uint16_t FixPortNumber(DWORD port)
{
	return ntohs(port & 0xffff);
}

void KillAll(vector<MIB_TCPROW2> const& toKill)
{
	for (auto con : toKill) {

		MIB_TCPROW row;
		row.dwLocalAddr = con.dwLocalAddr;
		row.dwLocalPort = FixPortNumber(con.dwLocalPort);
		row.dwRemoteAddr = con.dwRemoteAddr;
		row.dwRemotePort = FixPortNumber(con.dwRemotePort);
		row.dwState = MIB_TCP_STATE_DELETE_TCB;

		cout << "Killing " << FormatAddress(row.dwLocalAddr) << ":" << row.dwLocalPort << " -> " << FormatAddress(row.dwRemoteAddr) << ":" << row.dwRemotePort << endl;

		DWORD result;
		if ((result = SetTcpEntry(&row)) == 0)
		{
			cout << "Killed." << endl;
		}
		else
		{
			cout << "Windows reported that it failed to kill this connection, but may be lying. The result was " << result << "." << endl;
		}
	}
}

vector<MIB_TCPROW2> GetConnectionsFromProcess(int processIdToKill)
{
	auto tableMemory = vector<uint8_t>(1000000);
	const auto table = reinterpret_cast<MIB_TCPTABLE2*>(&tableMemory[0]);
	ULONG size = tableMemory.size();
	if (GetTcpTable2(table, &size, TRUE) != 0)
	{
		throw exception("Failed to get TCP table");
	}

	vector<MIB_TCPROW2> rows;
	copy_if(&table->table[0], &table->table[table->dwNumEntries], back_inserter(rows), [processIdToKill](const MIB_TCPROW2 row) { return row.dwOwningPid == processIdToKill; });

	return rows;
}

int main(const int argc, char const* argv[])
{
	try {
		if (argc != 2)
		{
			throw exception("Process ID is required.");
		}

		auto const processIdToKill = stoi(argv[1]);
		auto const rows = GetConnectionsFromProcess(processIdToKill);
		KillAll(rows);
		cout << "Ensuring all connections were killed..." << endl;
		auto const remainingRows = GetConnectionsFromProcess(processIdToKill);
		if(remainingRows.size() != 0)
		{
			throw exception("Not all connections were killed.");
		}
		cout << "Done." << endl;
		return 0;
	}
	catch(exception& ex)
	{
		cout << "Failed: " << ex.what() << endl;
		return 1;
	}
}

