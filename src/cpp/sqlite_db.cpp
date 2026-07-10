#include "sqlite_db.h"

#ifdef STAS_WITH_SQLITE
#include <sqlite3.h>
#endif

#include <iostream>

SQLiteDB::SQLiteDB(const std::string& dbfile) {
#ifdef STAS_WITH_SQLITE
    int rc = sqlite3_open(dbfile.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database " << dbfile << ": " << sqlite3_errmsg(db) << std::endl;
        db = nullptr;
    } else {
        std::cout << "Database " << dbfile << " opened successfully" << std::endl;
    }
#else
    db = nullptr;
    std::cout << "SQLite support is disabled; not opening " << dbfile << std::endl;
#endif
}

void SQLiteDB::storeEvents(const std::vector<Event>& events) {
#ifdef STAS_WITH_SQLITE
    if (!db) {
        std::cerr << "Database not open!" << std::endl;
        return;
    }

    // Create table
    const char* sqlCreate = 
        "CREATE TABLE IF NOT EXISTS events("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "type TEXT NOT NULL,"
        "timestamp INTEGER NOT NULL,"
        "details TEXT);";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sqlCreate, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error creating table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Events table ready" << std::endl;
    }

    // Insert events
    const char* sqlInsert = "INSERT INTO events (type, timestamp, details) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sqlInsert, -1, &stmt, nullptr);

    for (const auto& e : events) {
        sqlite3_bind_text(stmt, 1, e.type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, e.timestamp);
        sqlite3_bind_text(stmt, 3, "simulated", -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "Insert error: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    std::cout << "Saved " << events.size() << " events to database" << std::endl;
#else
    std::cout << "SQLite support is disabled; skipped storing "
              << events.size() << " events" << std::endl;
#endif
}

SQLiteDB::~SQLiteDB() {
#ifdef STAS_WITH_SQLITE
    if (db) {
        sqlite3_close(db);
        std::cout << "Database closed" << std::endl;
    }
#endif
}
