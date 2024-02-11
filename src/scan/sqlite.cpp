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


int sqlite(const char * Filename, const char * sql)
{
    sqlite3 * db;    
    int rc = sqlite3_open(Filename, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    char * zErrMsg = 0;
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    sqlite3_close(db);
    return 0;
}