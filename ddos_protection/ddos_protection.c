/* 
 * File:   ddos_protection.c
 * Author: unknown
 *
 * Created on July 7, 2011, 4:32 PM
 */

#include "include/ddos_protection.h"


enum BOOLEAN displayHelp = false, invalidArgs = false, configMode = false, verboseMode = false, \
listConnections = false;

long int cronTime = -1;
int nConAllowed = 150;
char *progName, *progLocation, *configLocation, *iptablesLocation, *trustedIPLocation;
FILE *fConfigFile, *fTCP, *fUDP, *fTrustedListFile;
char buffer[2048];
char strOutputIP[21];
struct connectionCount *trustedList = NULL;



/*
 *  Header to display when program is started .. 
 */
void myHeader(void)
{
    printf("DDoS_Protection v%0.1f by %s\n\r\n\r", VERSION, AUTHOR);
    configLocation = (char *)malloc(strlen(DDOS_PROTECTION_CONF));
    if (configLocation != NULL)
        sprintf(configLocation, DDOS_PROTECTION_CONF);
}

/*
 * Display program help/arguement information ..
 */
void displayProgramHelp(void)
{
    printf("Usage: ddos_protection [OPTIONS]" \
           "OPTIONS:\n\r" \
           "-h : Show this help screen\n\r"
           "-c : Create cron job to run this script regularly (default 60 sec) eq: -c60\n\r" \
           "-k : Block the offending ip making more than N connections (Default 150). Max 3600s eq: -k150\n\r" \
           "-f : Read configuration from file. eq: -f./ddos_protection.conf\n\r" \
           "-v : Enable verbose mode\n\r" \
           "-f : Specify configuration file location (eq: -f./config.conf)\n\r" \
           "-l : List no. of connections / ip\n\r");
}

/*
 * Convert hex Address from /proc/net/tcp or /proc/net/udp to IP:Port..
 */
char *hexAddrToDecIP(char *hexAddr, int format)
{
    int i, j = 0;

    int octIP[4];
    long lPort = 0;

    char *strTmp;
    char hexTmp[3];
    char strIP[15], strPort[5];

    strOutputIP[0] = '\0';

    strTmp = strchr(hexAddr, ':');
    if (strTmp == NULL)
        return NULL;

    lPort = strtol(strTmp + 1, NULL, 16);
    sprintf(strPort, "%d", lPort);

    hexTmp[2] = '\0';
    for (i = 7; i >= 0; i-=2, j++)
    {
        hexTmp[i%2] = hexAddr[i];    /* hex is always reversed */
        hexTmp[i%2 - 1] = hexAddr[i-1];

        octIP[j] = strtol(hexTmp, NULL, 16);
    }

    sprintf(strIP, "%d.%d.%d.%d", octIP[0], octIP[1], octIP[2], octIP[3]);
    sprintf(strPort, "%d", lPort);

    if (verboseMode)
    {
        printf("\n%s:%s\n", strIP, strPort);
    }

    if (format == OPT_IPPORT)
    {
        sprintf(strOutputIP, "%s:%s", strIP, strPort);
        return strOutputIP;
    }
    else if (format == OPT_IP)
    {
        strcpy(strOutputIP, strIP);
    }
    else if (format == OPT_PORT)
    {
        strcpy(strOutputIP, strPort);
    }

    return strOutputIP;
}

/*
 * Handle command line arguements provided to program ..
 */
void argHandler(char *arg)
{
    size_t argLen;
    argLen = strlen(arg);
    if (!strncmp(arg, "-h", 2))
    {
        displayHelp = true;
    }
    else if (!strncmp(arg,"-c", 2))
    {
        cronTime = atol(arg+2);
        if (cronTime < -1 || cronTime > 3600)
            invalidArgs = true;
    }
    else if (!strncmp(arg,"-k", 2))
    {
        if (argLen > 2)
            nConAllowed = atol(arg+2);
        if (nConAllowed < 1)
            invalidArgs = true;
    }
    else if (!strncmp(arg,"-f", 2))
    {
        if (argLen > 2)
        {
            configMode = true;
            configLocation = strdup(arg + 2);
/*            configLocation = (char *)malloc(argLen - 2 +1); */
            if (configLocation == NULL) {
                invalidArgs = true;
                return;
            }

            /* strcpy(configLocation, arg+2); */
        }
    }
    else if (!strncmp(arg,"-v", 2)) {
        printf("+++++++ verbose mode enabled ++++++++ \n\n");
        verboseMode = true;
    }
    else if (!strncmp(arg, "-l", 2))
        listConnections = true;
}

/*
 * Creates a new configuration file with default configuration ..
 */
void createConfigFile(void)
{
    /* TODO: create configuration file */
 /*   fConfigFile = fopen(configLocation, "w+");
    if (fConfigFile)
    {
        
    }*/
}

/*
 * Load configuration file ..
 */
enum BOOLEAN loadConfigFile(void)
{
    char *readLine;

    fConfigFile = fopen(configLocation, "r+");
    if (fConfigFile == NULL) {
        printf("%s : Unable to open. ", configLocation);
        perror("");
        return(false);
    }

    /* TODO: use fgets instead ;) */
    while (!feof(fConfigFile))
    {
        fgets(buffer, 2048, fConfigFile);
        
        /* Since fgets output includes \n */
        if ( (readLine=strchr(buffer, '\n')) != NULL) *readLine= '\0';

        readLine = buffer;

        /* Now, process read line .. */
        processConfigTags(readLine, false);
    }
    
    fclose(fConfigFile);

    return(true);
}


/*
 * Processes Configuration Tags eq: IPT="/sbin/iptables"
 */
void processConfigTags(char *tagsLine, enum BOOLEAN bTrustedList)
{
    char *var, *varValue;
    char *temp;
    struct connectionCount *myNewNode = NULL;
    enum BOOLEAN trustedIPFound = false;

    if (tagsLine == NULL) return;
    if (*tagsLine == '#') return; /* Line is a comment */

    temp = strchr(tagsLine, '=');
    if (temp == NULL)           /* Variable or Value not found.. */
        return;

    if (temp - tagsLine == 0)   /* Invalid Statement, Variable not Defined */
        return;
    
    varValue = temp + 1;
    var = tagsLine;
    *temp = '\0';

    if (*varValue == '\"') { /* trimQuotes() */
        varValue ++;
        temp = strchr(varValue, '\"');
        *temp = '\0';
    }

    if (verboseMode) printf("ConfigFile [%s:%s]\n", var, varValue);

    if (!bTrustedList)
    {
        if (!strcmp(var, "IPT"))
        {
            iptablesLocation = strdup(varValue);
        }
        else if (!strcmp(var, "PROG"))
        {
            progName = strdup(varValue);
        }
        else if (!strcmp(var, "PROGDIR"))
        {
            progLocation = strdup(varValue);
        }
        else if (!strcmp(var, "TRUSTED_LIST"))
        {
            trustedIPLocation = strdup(varValue);
        }
    }
    else /* Treat as trusted ip */
    {
        /* Search for already existing entry for IP */
        trustedIPFound = false;
        myNewNode = trustedList;
        while (myNewNode != NULL)
        {
            if (!strcmp(myNewNode->IP, varValue))   /* IP Already exists in list */
            {
                trustedIPFound = true;

                temp = (char *)malloc(strlen(myNewNode->strTrustedName) + 1 + strlen(varValue));

                if (temp == NULL && verboseMode) /* Unable to allocate enough memory */
                    printf("Insufficient Memory\n");

                else if (temp != NULL)  /* Add new tag name for ip to list */

                {
                    sprintf(temp, "%s,%s", myNewNode->strTrustedName, varValue);
                    free(myNewNode->strTrustedName);
                    myNewNode->strTrustedName = temp;
                }

                return;
            }
            
            myNewNode = myNewNode->next;
        }

        /* EIP reaches this place only if IP wasn't already added to trustedList */
        myNewNode = (struct connectionCount *)malloc(sizeof(struct connectionCount));
        if (myNewNode == NULL) /* Again, unable to allocate enough memory */
            return;

        strncpy(myNewNode->IP, varValue, 15); /* In case varValue > 15 this shouldn't rise a seg dump*/
        myNewNode->strTrustedName = strdup(var);
        if (trustedList != NULL) 
        {
            myNewNode->next = trustedList;
            trustedList->prev = myNewNode;
        }
        else
            myNewNode->next = NULL;
        
        myNewNode->prev = NULL;
        trustedList = myNewNode;
    }
}

void getTrutedIPList(void)
{
    char *temp;
    fTrustedListFile = fopen(trustedIPLocation, "r");
    if (fTrustedListFile != NULL)
    {
        while (!feof(fTrustedListFile))
        {
            fgets(buffer, 2048, fTrustedListFile);

            /* fgets includes \n in output, trim it */
            temp = strchr(buffer, '\n');
            if (temp != NULL)
                *temp = '\0';

            processConfigTags(buffer, true);
        }

        fclose(fTrustedListFile);
    }
}

enum BOOLEAN checkTrustedIP(struct connectionCount *IP)
{
    struct connectionCount *node;
    enum BOOLEAN foundTrusted = false;

    if (IP == NULL)
        return false;

    node = trustedList;
    while (node != NULL)
    {
        if (!strcmp(node->IP, IP->IP))
        {
            IP->strTrustedName = strdup(node->strTrustedName);
            foundTrusted = true;
            break;
        }
        
        node = node->next;
    }
    
    return foundTrusted;
}

enum BOOLEAN readTCPUDP(void)
{
    int lineNum = 0;
    char *strHexIPPORT, *strTemp;
    struct connectionCount *myTCPConnectionList = NULL, *myNewNode = NULL;
    enum BOOLEAN hexIPFound = false, processedUDP = false;
    
    fTCP = fopen("/proc/net/tcp", "r");
    if (fTCP == NULL)
        return(false);

    if (verboseMode) printf("\n\n <TCP RAW DATA> \n\n");

processUDP:
    while (!feof(fTCP)) {
        lineNum++;
        fgets(buffer, 2048, fTCP);
        if (lineNum == 1)
            continue;

        if (verboseMode)    /* Display TCP Raw Data .. */
            fputs(buffer, stdout);

        if ( (strHexIPPORT = strchr(buffer, ':')) == NULL)
            continue; /* No data to parse .. sl: not found .. */
        else {
            strHexIPPORT = strchr(strHexIPPORT+1, ':') + 4 + 1 +1; /* added 4 for local port hexadecimal  + 1 space*/
            /* Alternate way could be to look for ' ' or to place all data into an array ;) */
            
            if (strHexIPPORT == NULL)
                break;

            strTemp = strchr(strHexIPPORT, ' ');
            if (strTemp == NULL)
                break;
            
            /* Locate Next Field start .. and replace it with '\0' */
            *(strTemp) = '\0';

            hexIPFound = false;
            myNewNode = myTCPConnectionList;
            while (myNewNode != NULL)
            {
                if (!strncmp(myNewNode->hexIP, strHexIPPORT, 8)) /* Hexadecimal IP Address Matched, increase count .. */
                {
                    hexIPFound = true;
                    break;
                }
                
                myNewNode = myNewNode->next;
            }

            if (hexIPFound == false)
            {
                /* Create new node since this IP wasn't found in our connectionList */
                myNewNode = (struct connectionCount *)malloc(sizeof(struct connectionCount));
                if (myNewNode == NULL && verboseMode)
                {
                    printf("Unable to allocate memory..\n");
                    exit(EXIT_FAILURE);
                }
                strncpy(myNewNode->hexIP, strHexIPPORT, 8);
                *(myNewNode->IP) = '\0';
                myNewNode->nCount = 0;
                myNewNode->prev = myNewNode->next = myNewNode->strTrustedName = NULL;

                if (myTCPConnectionList == NULL)
                    myTCPConnectionList = myNewNode;
                else 
                {
                    myNewNode->next = myTCPConnectionList;
                    myTCPConnectionList->prev = myNewNode;
                    myTCPConnectionList = myNewNode;

                }
            }

            if (!*(myNewNode->IP)) {
                hexAddrToDecIP(strHexIPPORT, OPT_IP);
                strcpy(myNewNode->IP, strOutputIP);
                
                /* Verify if its trusted IP */
                if (checkTrustedIP(myNewNode) && verboseMode)
                    printf("\n%s : TRUSTED [%s]\n", myNewNode->IP, myNewNode->strTrustedName);
            }

            myNewNode->nCount ++;
            if (myNewNode->nCount > nConAllowed && myNewNode->strTrustedName == NULL) {
                /* no. of connections exceeds allowed no. of connections .. */
                blockIP(myNewNode);
            }
        }
    }

    fclose(fTCP);

    if (processedUDP == true)
        goto finally;

    lineNum = 0;
    /* loading file into fTCP again ;) and using goto.. :D */
    fTCP = fopen("/proc/net/udp", "r");
    if (fTCP == NULL)
        return(false);

    if (verboseMode) printf("\n\n <UDP RAW DATA> \n\n");

    processedUDP = true;
    goto processUDP;

finally:
    /* time to free all memory allocated in linked list .. */
    myNewNode = myTCPConnectionList;
    while (myNewNode != NULL)
    {
        if (listConnections) printf("\n%s, %d Connections [%s]\n", myNewNode->IP, myNewNode->nCount, (myNewNode->strTrustedName == NULL ? "NOT TRUSTED" : "TRUSTED"));
        
        if (myNewNode->next != NULL)
        {
            myNewNode = myNewNode->next;
            if (myNewNode->prev->strTrustedName != NULL)
                free(myNewNode->prev->strTrustedName);
            free(myNewNode->prev);
        }
        else
        {
            if (myNewNode->strTrustedName != NULL)
                free(myNewNode->strTrustedName);
            free(myNewNode);
            break;
        }
    }
    
    return(true);
}

void blockIP(struct connectionCount *IP)
{
    sprintf(buffer, "iptables -t filter -I INPUT -s %s -j DROP;"        \
                    "iptables -t filter -I OUTPUT -s %s -j DROP;"       \
                    "iptables -t filter -I FORWARD -s %s -j DROP;"      \
                    "iptables -t filter -I INPUT -d %s -j REJECT;"      \
                    "iptables -t filter -I OUTPUT -d %s -j REJECT;"     \
                    "iptables -t filter -I FORWARD -d %s -j REJECT;",   \
                    IP->IP, IP->IP, IP->IP, IP->IP, IP->IP, IP->IP      \
            );
    
    printf("\nBlocking %s (%d) \n", IP->IP, IP->nCount);
    system(buffer);
}

enum BOOLEAN release(void)
{
    struct connectionCount *node;

    free(progName);
    free(progLocation);
    free(configLocation);
    free(iptablesLocation);
    free(trustedIPLocation);

    /* Release TrustedList .. */
    if (trustedList != NULL)
    {
        node = trustedList;
        while(node != NULL)
        {
            if (node->next != NULL)
            {
                node = node->next;
                free(node->prev->strTrustedName);
                free(node->prev);
            }
            else
            {
                if (node->strTrustedName != NULL)
                    free(node->strTrustedName);

                free(node);
                break;
            }
        }
    }
    
    return(true);
}

/*
 * 
 */
int main(int argc, char* argv[])
{
    int i;
    char *progPath = "/home/default/NetbeansProjects";
    myHeader();

    progLocation = strdup(progPath);
    for (i=1; i < argc; i++) {
        argHandler(argv[i]);
    }

    if (invalidArgs)
    {
        printf("Invalid Arguements Supplied..\n\r");
        displayProgramHelp();
        release();
        exit(EXIT_FAILURE);
    }
    else if (displayHelp)
    {
        displayProgramHelp();
        release();
        exit(EXIT_SUCCESS);
    }

    if (loadConfigFile() == false) ;
        /*createConfigFile();*/ /* TODO: add create config file if load config returns false */

    if (trustedIPLocation != NULL)  /* Configuration file contained trusted ip list path */
        getTrutedIPList();

    readTCPUDP();

    release();
    return (EXIT_SUCCESS);
}

