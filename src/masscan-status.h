#ifndef MASSCAN_STATUS_H
#define MASSCAN_STATUS_H

enum PortStatus {
    PortStatus_Unknown,
    PortStatus_Open,
    PortStatus_Closed,
    PortStatus_ZeroWin, /*Recv a SYNACK with zero win*/
    PortStatus_Responsed, /*ACK our req of app-layer with data in stateless mode*/
    PortStatus_Arp,
    PortStatus_Count

};



#endif
