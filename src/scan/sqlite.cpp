#include "sqlite.h"
#include "..\lib\sqlite\sqlite-amalgamation-3450100\sqlite3.h"


#ifdef _WIN64  
#ifdef _DEBUG
#pragma comment(lib, "..\\x64\\Debug\\sqlite3.lib")
#else
#pragma comment(lib, "..\\x64\\release\\sqlite3.lib")
#endif
#else 
#ifdef _DEBUG
#pragma comment(lib, "..\\Debug\\sqlite3.lib")
#else
#pragma comment(lib, "..\\Debug\\sqlite3.lib")
#endif
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


int callback(void * NotUsed, int argc, char ** argv, char ** azColName)
{
    UNREFERENCED_PARAMETER(NotUsed);

    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }

    printf("\n");

    return 0;
}


int sqlite(int argc, char ** argv)
{
    sqlite3 * db;
    char * zErrMsg = 0;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s DATABASE SQL-STATEMENT\n", argv[0]);
        return(1);
    }

    rc = sqlite3_open(argv[1], &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    rc = sqlite3_exec(db, argv[2], callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    sqlite3_close(db);

    return 0;
}