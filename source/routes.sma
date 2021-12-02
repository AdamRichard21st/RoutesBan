#include < amxmodx >
#include < amxmisc >
#include < regex >
#include < json >
#include < sqlx >


#define CLIENT_AUTHORIZED_TASKID 192


#define ROUTES_CONFIG_FILE "routes.jsonc"
#define ROUTES_ERROR_FILE "routes-error.log"
#define ROUTES_LOG_FILE "routes.log"


enum RouteDriver
{
    MYSQL_DRIVER,
    SQLITE_DRIVER
}


enum _:RouteCredentials
{
    HOSTNAME[92],
    USERNAME[92],
    PASSWORD[92],
    DATABASE[92]
}


enum _:RouteRules
{
    Regex:ipValidation,
    bool:banPreviuosly,
    bool:checkNames,
    accessLevelFlags
}


enum _:QueryData
{
    queryPlayer
}


enum _:PlayerData
{
    userAuthid[MAX_AUTHID_LENGTH],
    userName[MAX_NAME_LENGTH],
    userIP[MAX_IP_LENGTH],
    userSafeName[MAX_NAME_LENGTH * 2],
    bool:verified
}


public RouteDriver:driver;
public Handle:database;
public bool:online;

public credentials[RouteCredentials];
public rules[RouteRules];
public players[MAX_PLAYERS][PlayerData];
public routeLogs[MAX_RESOURCE_PATH_LENGTH];
public routeErrors[MAX_RESOURCE_PATH_LENGTH];


public plugin_init()
{
    register_plugin("Routes Ban", "1.0.0", "AdamRichard21st");

    register_clcmd("route_ban", "OnRouteBan", .info = "ROUTES_USAGE", .info_ml = true);

    register_dictionary("routes.txt");

    new error[128];

    if (!LoadRouteSettings(error, charsmax(error)))
    {
        set_fail_state("%L", LANG_SERVER, "ROUTES_ERROR_COULD_NOT_LOAD_SETTINGS", error);
    }
}


public plugin_cfg()
{
    new logsDir[MAX_RESOURCE_PATH_LENGTH];

    get_localinfo("amxx_logs", logsDir, charsmax(logsDir));

    formatex(routeLogs, charsmax(routeLogs), "%s/%s", logsDir, ROUTES_LOG_FILE);
    formatex(routeErrors, charsmax(routeErrors), "%s/%s", logsDir, ROUTES_ERROR_FILE);

    CompileIpValidationRegex();
    CreateRouteDatabase();
}


public plugin_end()
{
    if (rules[ipValidation])
    {
        regex_free(rules[ipValidation]);
    }

    SQL_FreeHandle(database);
}


public client_authorized(id)
{
    id = id > CLIENT_AUTHORIZED_TASKID
        ? id - CLIENT_AUTHORIZED_TASKID
        : id;

    if (!online)
    {
        new taskId = id + CLIENT_AUTHORIZED_TASKID;

        if (!task_exists(taskId))
        {
            set_task(3.0, "client_authorized", taskId);
        }

        return;
    }

    get_user_authid(id, players[id][userAuthid], charsmax(players[][userAuthid]));
    get_user_name(id, players[id][userName], charsmax(players[][userName]));
    get_user_ip(id, players[id][userIP], charsmax(players[][userIP]), .without_port = 1);

    EscapeString(players[id][userName], players[id][userSafeName], charsmax(players[][userSafeName]));


    if (players[id][verified])
    {
        CheckRouteBan(id);
    }
    else
    {
        CheckPreviousBans(id);
    }
}


public client_disconnected(id)
{
    players[id][verified] = false;


    new taskId = id + CLIENT_AUTHORIZED_TASKID;

    if (task_exists(taskId))
    {
        remove_task(taskId);
    }
}


public RouteMenu(id)
{
    // TO DO
}


public OnRouteBan(id)
{
    if (!hasRouteBanAccess(id))
    {
        console_print(id, "%L", id, "ROUTES_NO_ACCESS");
        return PLUGIN_HANDLED;
    }

    new argsNum = read_argc();


    if (argsNum == 1)
    {
        // opens the menu
    }


    if (argsNum > 3)
    {
        console_print(id, "%L", id, "ROUTES_USAGE");
        return PLUGIN_HANDLED;
    }


    new bool:withTimestamp = argsNum == 3;
    new routeIp[MAX_IP_LENGTH];

    
    read_argv(2, routeIp, charsmax(routeIp));


    if (!regex_match_c(routeIp, rules[ipValidation]))
    {
        console_print(id, "%L", id, "ROUTES_USAGE");
        return PLUGIN_HANDLED;
    }


    if (withTimestamp)
    {
        new timestamp[32];
        new minutes[6];

        read_argv(3, minutes, charsmax(minutes));
        num_to_str(get_systime() + str_to_num(minutes) * 60, timestamp, charsmax(timestamp));

        BanRoute(id, routeIp, timestamp);
    }
    else
    {
        BanRoute(id, routeIp);
    }


    return PLUGIN_HANDLED;
}


CreateRouteDatabase()
{
    SQL_SetAffinity(driver == MYSQL_DRIVER ? "mysql" : "sqlite");

    database = SQL_MakeDbTuple(
        .host = credentials[HOSTNAME],
        .user = credentials[USERNAME],
        .pass = credentials[PASSWORD],
        .db = credentials[DATABASE]
    );

    switch (driver)
    {
        case MYSQL_DRIVER:
        {
            RouteQuery("CreateRouteDatabaseCallback",
                "CREATE TABLE IF NOT EXISTS routes(\
                    `id` INT(11) PRIMARY KEY AUTO_INCREMENT,\
                    `route` VARCHAR(16) NOT NULL UNIQUE,\
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\
                    `expire_at` TIMESTAMP\
                );\
                CREATE TABLE IF NOT EXISTS bans(\
                    `id` INT(11) PRIMARY KEY AUTO_INCREMENT,\
                    `route_id` INT(11),\
                    `name` VARCHAR(64),\
                    `authid` VARCHAR(64),\
                    `ip` VARCHAR(16),\
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP\
                );"
            );
        }

        case SQLITE_DRIVER:
        {
            RouteQuery("CreateRouteDatabaseCallback",
                "CREATE TABLE IF NOT EXISTS routes(\
                    id INTEGER PRIMARY KEY AUTOINCREMENT,\
                    route TEXT NOT NULL UNIQUE,\
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\
                    expire_at TIMESTAMP\
                );"
            );

            RouteQuery("CreateRouteDatabaseCallback",
                "CREATE TABLE IF NOT EXISTS bans(\
                    id INTEGER PRIMARY KEY AUTOINCREMENT,\
                    route_id INTEGER,\
                    name TEXT,\
                    authid TEXT,\
                    ip TEXT,\
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\
                );"
            );
        }
    }
}


public CreateRouteDatabaseCallback(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    if (!RouteValidQuery("CreateRouteDatabaseCallback", failstate, error, queuetime))
    {
        set_fail_state("%L", LANG_SERVER, "ROUTES_ERROR_LOADING_DATABASE");
        return;
    }

    if (!online)
    {
        online = true;

        log_amx("%L", LANG_SERVER, "ROUTES_ONLINE", queuetime);
    }
}


CheckPreviousBans(id)
{
    new data[QueryData];

    data[queryPlayer] = id;

    if (rules[checkNames])
    {
        return RouteQueryData("CheckPreviousBansCallback", data,
            "SELECT \
                COUNT(id) \
            FROM \
                bans \
            WHERE \
                name = ^"%s^" \
            OR  \
                authid = ^"%s^" \
            OR  \
                ip = ^"%s^" \
            GROUP BY id",
            players[id][userSafeName],
            players[id][userAuthid],
            players[id][userIP]
        );
    }

    return RouteQueryData("CheckPreviousBansCallback", data,
        "SELECT \
            COUNT(id) \
        FROM \
            bans \
        WHERE \
            authid = ^"%s^" \
        OR  \
            ip = ^"%s^" \
        GROUP BY id",
        players[id][userAuthid],
        players[id][userIP]
    );
}


public CheckPreviousBansCallback(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    if (!RouteValidQuery("CheckPreviousBansCallback", failstate, error, queuetime))
    {
        return;
    }

    new id = data[queryPlayer];

    if (SQL_NumResults(query))
    {
        new totalBans = SQL_ReadResult(query, 0);
        new log[128];

        
        if (rules[banPreviuosly])
        {
            AddBanRegitry(id);

            server_cmd("kick #%d %L", get_user_userid(id), id, "ROUTES_KICK_MESSAGE");
            return;
        }

        formatex(log, charsmax(log), "%L",
            LANG_SERVER,
            "ROUTES_LOG_PLAYER_BANNED",
            players[id][userName],
            players[id][userAuthid],
            players[id][userIP],
            totalBans
        );

        log_to_file(routeLogs, log);
        log_amx(log);
    }

    players[id][verified] = true;

    CheckRouteBan(id);
}


CheckRouteBan(id)
{
    new data[QueryData];
    new userRoute[MAX_IP_LENGTH];

    data[queryPlayer] = id;

    for (new i = strlen(players[id][userIP]) - 1; i >= 0; i--)
    {
        if (players[id][userIP][i] == '.')
        {
            parse(players[id][userIP], userRoute, i);
            break;
        }
    }

    return RouteQueryData("CheckRouteBanCallback", data,
        "SELECT \
            * \
        FROM \
            routes \
        WHERE \
            route = ^"%s^"",
        userRoute
    );
}


public CheckRouteBanCallback(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    if (!RouteValidQuery("CheckRouteBanCallback", failstate, error, queuetime))
    {
        return;
    }

    new id = data[queryPlayer];

    if (SQL_NumResults(query))
    {
        new routeId[6];

        SQL_ReadResult(query, 0, routeId, charsmax(routeId));

        AddBanRegitry(id, routeId);

        server_cmd("kick #%d %L", get_user_userid(id), id, "ROUTES_KICK_MESSAGE");
    }
}


AddBanRegitry(id, routeId[] = "NULL")
{
    RouteQueryMultiData("AddBanRegitryCallback", players[id], PlayerData,
        "INSERT INTO \
            bans (route_id, authid, ip, name) \
        VALUES ( \
            %s, \
            ^"%s^", \
            ^"%s^", \
            ^"%s^" \
        );",
        routeId,
        players[id][userAuthid],
        players[id][userIP],
        players[id][userSafeName]
    );
}


public AddBanRegitryCallback(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    if (!RouteValidQuery("AddBanRegitryCallback", failstate, error, queuetime))
    {
        return;
    }

    new log[128];

    formatex(log, charsmax(log), "%L",
        LANG_SERVER,
        "ROUTES_LOG_BANNED",
        data[userName],
        data[userAuthid],
        data[userIP]
    );

    log_to_file(routeLogs, log);
    log_amx(log);
}


BanRoute(adminId, routeIp[], expireAt[] = "NULL")
{
    new data[QueryData];
    new log[128];

    data[queryPlayer] = adminId;


    if (equal(expireAt, "NULL"))
    {
        formatex(log, charsmax(log), "%L", LANG_SERVER,
            "ROUTES_ADMIN_BANNED_ROUTE",
            players[adminId][userName],
            players[adminId][userAuthid],
            players[adminId][userIP],
            routeIp
        );
    }
    else
    {
        formatex(log, charsmax(log), "%L", LANG_SERVER,
            "ROUTES_ADMIN_BANNED_ROUTE_TIME",
            players[adminId][userName],
            players[adminId][userAuthid],
            players[adminId][userIP],
            routeIp,
            floatround(float(get_systime() - str_to_num(expireAt)) / 60.0)
        );
    }

    console_print(adminId, "%L", adminId, "ROUTES_ADDING_BAN");


    RouteQueryData("BanRouteCallback", data,
        "INSERT INTO \
            routes (route, expire_at) \
        VALUES (^"%s^", %s);",
        routeIp,
        expireAt
    );


    log_to_file(routeLogs, log);
    log_amx(log);
}


public BanRouteCallback(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    new adminId = data[queryPlayer];

    if (!RouteValidQuery("BanRouteCallback", failstate, error, queuetime))
    {
        console_print(adminId, "%L", adminId, "ROUTES_BAN_FAILED");
        return;
    }

    CheckConnectedPlayers();

    console_print(adminId, "%L", adminId, "ROUTES_BAN_SUCCESS");
}


bool:LoadRouteSettings(error[], errorLength)
{
    new configsDir[MAX_RESOURCE_PATH_LENGTH];
    new configFile[MAX_RESOURCE_PATH_LENGTH];
    
    get_configsdir(configsDir, charsmax(configsDir));
    formatex(configFile, charsmax(configFile), "%s/%s", configsDir, ROUTES_CONFIG_FILE);


    new JSON:configs = json_parse(configFile, .is_file = true, .with_comments = true);

    if (!json_is_object(configs))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_INVALID_SETTINGS", configFile);
    }

    if (!json_object_has_value(configs, "driver", JSONString))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "driver");
    }

    if (!json_object_has_value(configs, "credentials.hostname", JSONString, .dot_not = true))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "credentials.hostname");
    }

    if (!json_object_has_value(configs, "credentials.username", JSONString, .dot_not = true))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "credentials.username");
    }

    if (!json_object_has_value(configs, "credentials.password", JSONString, .dot_not = true))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "credentials.password");
    }

    if (!json_object_has_value(configs, "credentials.database", JSONString, .dot_not = true))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "credentials.database");
    }

    if (!json_object_has_value(configs, "ban_previously", JSONBoolean))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_BOOL", "ban_previously");
    }

    if (!json_object_has_value(configs, "check_names", JSONBoolean))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_BOOL", "check_names");
    }

    if (!json_object_has_value(configs, "access_level", JSONString))
    {
        return !formatex(error, errorLength, "%L", LANG_SERVER, "ROUTES_ERROR_JSON_STRING", "access_level");
    }


    new driverName[6];
    new accessLevel[32];

    json_object_get_string(configs, "driver", driverName, charsmax(driverName));
    json_object_get_string(configs, "credentials.hostname", credentials[HOSTNAME], charsmax(credentials[HOSTNAME]), .dot_not = true);
    json_object_get_string(configs, "credentials.username", credentials[USERNAME], charsmax(credentials[USERNAME]), .dot_not = true);
    json_object_get_string(configs, "credentials.password", credentials[PASSWORD], charsmax(credentials[PASSWORD]), .dot_not = true);
    json_object_get_string(configs, "credentials.database", credentials[DATABASE], charsmax(credentials[DATABASE]), .dot_not = true);
    json_object_get_string(configs, "access_level", accessLevel, charsmax(accessLevel));

    rules[banPreviuosly] = json_object_get_bool(configs, "ban_previously");
    rules[checkNames] = json_object_get_bool(configs, "check_names");
    rules[accessLevelFlags] = read_flags(accessLevel);

    driver = equal(driverName, "mysql") ? MYSQL_DRIVER : SQLITE_DRIVER;

    json_free(configs);

    return true;
}


RouteQuery(const callback[], const query[], any:...)
{
    static queryBuffer[256];

    vformat(queryBuffer, charsmax(queryBuffer), query, 3);

    return SQL_ThreadQuery(database, callback, queryBuffer);
}


RouteQueryData(const callback[], data[QueryData], query[], any:...)
{
    static queryBuffer[256];

    vformat(queryBuffer, charsmax(queryBuffer), query, 4);

    return SQL_ThreadQuery(database, callback, queryBuffer, data, QueryData);
}


RouteQueryMultiData(const callback[], data[], dataSize, query[], any:...)
{
    static queryBuffer[256];

    vformat(queryBuffer, charsmax(queryBuffer), query, 5);

    return SQL_ThreadQuery(database, callback, queryBuffer, data, dataSize);
}


bool:RouteValidQuery(const callback[], failstate, error[], Float:queuetime)
{
    switch (failstate)
    {
        case TQUERY_SUCCESS:
        {
            return true;
        }

        case TQUERY_CONNECT_FAILED:
        {
            log_to_file(routeErrors, "%s: %L", callback, LANG_SERVER, "ROUTES_ERROR_QUERY_FAILED_CONNECT", queuetime, error);
        }

        case TQUERY_QUERY_FAILED:
        {
            log_to_file(routeErrors, "%s: %L", callback, LANG_SERVER, "ROUTES_ERROR_QUERY_FAILED", queuetime, error);
        }
    }

    return false;
}


CheckConnectedPlayers()
{
    for (new id = 1, Float:delay = 1.0; id <= MAX_PLAYERS; id++)
    {
        new taskId = id + CLIENT_AUTHORIZED_TASKID;

        if (is_user_connected(id) && !task_exists(taskId))
        {
            set_task(delay += 1.0, "client_authorized", taskId);
        }
    }
}


bool:hasRouteBanAccess(id)
{
    return get_user_flags(id) & rules[accessLevelFlags]
        ? true
        : false;
}


CompileIpValidationRegex()
{
    rules[ipValidation] = regex_compile_ex("^^(([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)\.){3}([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)$");
}


EscapeString(string[], dest[], length)
{
	copy(dest, length, string);

	replace_all(dest, length, "\\", "\\\\");
	replace_all(dest, length, "\0", "\\0");
	replace_all(dest, length, "\n", "\\n");
	replace_all(dest, length, "\r", "\\r");
	replace_all(dest, length, "\x1a", "\Z");
	replace_all(dest, length, "'", "\'");
	replace_all(dest, length, "`", "\`");
	replace_all(dest, length, "^"", "\^"");
}