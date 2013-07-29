/* 
 * File:   ddos_protection.h
 * Author: unknown
 *
 * Created on July 7, 2011, 4:35 PM
 */

#ifndef DDOS_PROTECTION_H
#define	DDOS_PROTECTION_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AUTHOR "unknown_had"
#define VERSION 0.1
/*#define DDOS_PROTECTION_CONF    "/usr/local/ddos_protection/ddos_protection.conf"*/
#define DDOS_PROTECTION_CONF    "/home/default/NetBeansProjects/ddos_protection/ddos_protection.conf"
#define OPT_IPPORT 0
#define OPT_IP  1
#define OPT_PORT 2

    enum BOOLEAN { false = 0, true = 1};

    struct connectionCount {
        char hexIP[8];
        char IP[15];
        unsigned int nCount;
        char *strTrustedName; /* For ignore ip list {NULL: non-trusted} */
        struct connectionCount *prev, *next;
    };

    void myHeader();
    void displayProgramHelp();
    char *hexAddrToDecIP(char *, int);
    void argHandler(char *);
    enum BOOLEAN loadConfigFile();
    void processConfigTags(char *, enum BOOLEAN);
    void getTrutedIPList();
    enum BOOLEAN checkTrustedIP(struct connectionCount *);
    enum BOOLEAN readTCPUDP();
    void blockIP(struct connectionCount *);
    enum BOOLEAN release();



#ifdef	__cplusplus
}
#endif

#endif	/* DDOS_PROTECTION_H */

