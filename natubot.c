//TODO: command to fetch youtube links
//TODO: provide usage information and !help command
//TODO: give link to playlist with !playlist command
//TODO: multiple channel/admin support

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#else
#include <select.h>
#include <termios.h>
#endif

#include <libircclient.h>
#include <libirc_rfcnumeric.h>
#include <libspotify/api.h>
#include <curl/curl.h>
#include <json.h>

//twitch API settings
#define CLIENT_ID "clientidgoeshere"
#define CLIENT_SECRET "clientsecretgoeshere"
#define REDIRECT_URI "http://localhost"
#define TWITCH_SCOPES "channel_check_subscription+chat_login"

//misc settings
#define LOGFILE  "natubot.log"
#define CONFFILE "natubot.json"
#define DEFAULT_UNDO_TIMER 120
#define DEFAULT_MAX_SONG_COUNT 1
#define DEFAULT_BUF_SIZE 512


//macros
//used to dynamically resize arrays
#define RESIZE_BUF_FUNC(size) ((size)*2)

#if defined(_WIN32)
#define CURL_INIT_SETTING CURL_GLOBAL_WIN32 && CURL_GLOBAL_SSL
#else
#define CURL_INIT_SETTING CURL_GLOBAL_ALL
#endif


//spotify app key.
const uint8_t g_appkey[] = {
};
const size_t g_appkey_size = sizeof(g_appkey);

const json_settings default_json_settings = { 0 };


typedef struct natubot_conf {
    char * network;
    unsigned short port;
    char * nick;
    char * username;
    char * realname;
    char * channel;
    char * password;
    unsigned short undo_timer;
    unsigned short max_song_count;
    char * twitch_auth_code;
    char * spotify_playlist_uri;
} natubot_conf_t;

typedef struct nick_list {
    char * nick;
    sp_track * track;
    unsigned int song_count;
    struct nick_list * next;
} nick_list_t;

typedef struct natubot_ctx {
    natubot_conf_t * conf;
    nick_list_t * nick_list;
    sp_session * sp;
    sp_playlist * playlist;
    char * twitch_access_token;
    int shutdown_flag;
	char * playlist_url;
} natubot_ctx_t;

typedef struct sp_callback_data {
    irc_session_t * irc;
    sp_session * sp;
    char * nick;
    char * channel;
} sp_callback_data_t;

typedef struct curl_callback_data {
    char * buf;
    size_t buf_length;
    size_t buf_capacity;
} curl_callback_data_t;


void addlog (const char * fmt, ...)
{
    FILE * fp;
    char buf[1024];
    va_list va_alist;

    va_start (va_alist, fmt);
#if defined (_WIN32)
    _vsnprintf (buf, sizeof(buf), fmt, va_alist);
#else
    vsnprintf (buf, sizeof(buf), fmt, va_alist);
#endif
    va_end (va_alist);

    printf ("%s\n", buf);

    if ( (fp = fopen (LOGFILE, "ab")) != 0 )
    {
        fprintf (fp, "%s\r\n", buf);
        fclose (fp);
    }
}

void debuglog(const char * fmt, ...)
{
    FILE * fp;
    char buf[1024];
    va_list va_alist;

    va_start(va_alist, fmt);
#if defined (_WIN32)
    _vsnprintf(buf, sizeof(buf), fmt, va_alist);
#else
    vsnprintf(buf, sizeof(buf), fmt, va_alist);
#endif
    va_end(va_alist);

#ifdef DEBUG
    printf("%s\n", buf);
#endif

    if ((fp = fopen(LOGFILE, "ab")) != 0)
    {
        fprintf(fp, "%s\r\n", buf);
        fclose(fp);
    }
}



void free_natubot_conf(natubot_conf_t * conf) {
    if (conf != NULL) {
        free(conf->network);
		if (conf->username != conf->nick)
			free(conf->username);
		if (conf->realname != conf->nick)
			free(conf->realname);
        free(conf->nick);      
        free(conf->channel);
        free(conf->password);
        free(conf->twitch_auth_code);
        free(conf->spotify_playlist_uri);
        free(conf);
    }
}


natubot_conf_t * read_natubot_conf(const char * path) {
    FILE * fp;
    if ((fp = fopen(CONFFILE, "r"))) {
        long fsize;
        char * buf;
        json_value * json;
        natubot_conf_t * conf;
        char json_err_buf[DEFAULT_BUF_SIZE];

        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buf = malloc(fsize + 1);
        fread(buf, fsize, 1, fp);
        fclose(fp);
        buf[fsize] = '\0';

        json = json_parse_ex(&default_json_settings, buf, fsize, json_err_buf);
        if (NULL == json) {
            addlog("Error parsing conf file: %s", json_err_buf);
            return NULL;
        }
        conf = malloc(sizeof(natubot_conf_t));
        memset(conf, 0, sizeof(natubot_conf_t));
        if (json->type == json_object) {
            //extract configuration options
            for (int i = 0; i < json->u.object.length; ++i) {
                char * key = json->u.object.values[i].name;
                json_value * value = json->u.object.values[i].value;

				//load integer fields
#define _LOAD_JSON_INT(field_name, min_value, max_value)                                                                                                                             \
	if (!strcmp(key, #field_name)) {                                                                                                                                                 \
		if (value->type != json_integer) { addlog("Error reading %s: expected integer type for " #field_name, path); continue; }                                                      \
		if (min_value > value->u.integer || max_value < value->u.integer) { addlog("Error reading %s: value of integer " #field_name " not within expected range.", path); continue; } \
		conf->field_name = value->u.integer; continue;                                                                                                                                \
	}           
				_LOAD_JSON_INT(port, 0, USHRT_MAX);
				_LOAD_JSON_INT(undo_timer, 0, USHRT_MAX);
				_LOAD_JSON_INT(max_song_count, 0, USHRT_MAX);			

				//load string fields
                if (value->type != json_string) {
                    addlog("Error reading %s: expected string for %s. Value ignored.", path, key);
                    continue;
                }
#define _LOAD_JSON_STR(field_name) if(!strcmp(key, #field_name)) { conf->field_name = malloc(value->u.string.length + 1); strcpy(conf->field_name, value->u.string.ptr); continue; }
				_LOAD_JSON_STR(network)
				_LOAD_JSON_STR(nick)
				_LOAD_JSON_STR(username)
				_LOAD_JSON_STR(realname)
				_LOAD_JSON_STR(channel)
				_LOAD_JSON_STR(password)
				_LOAD_JSON_STR(twitch_auth_code)
				_LOAD_JSON_STR(spotify_playlist_uri)

                addlog("Unknown configuration option: %s", key);
            }
            //check that fields are defined
#define _CHECK_REQUIRED_FIELD(field_name) if(conf->field_name == 0) { addlog("Error in %s: " #field_name " not specified.", path); fatal_error = 1; }
#define _CHECK_DEFAULT_FIELD(field_name, default_value) if(conf->field_name == 0) { addlog("Optional configuration field " #field_name " not specified."); conf->field_name = default_value; }
			int fatal_error = 0;
			_CHECK_REQUIRED_FIELD(network)
			_CHECK_REQUIRED_FIELD(port)
			_CHECK_REQUIRED_FIELD(nick)
			_CHECK_REQUIRED_FIELD(channel)
			_CHECK_REQUIRED_FIELD(twitch_auth_code)
			_CHECK_REQUIRED_FIELD(spotify_playlist_uri)
			_CHECK_DEFAULT_FIELD(username, conf->nick)
			_CHECK_DEFAULT_FIELD(realname, conf->nick)
			_CHECK_DEFAULT_FIELD(undo_timer, DEFAULT_UNDO_TIMER)
			_CHECK_DEFAULT_FIELD(max_song_count, DEFAULT_MAX_SONG_COUNT)

			//cleanup and return
            json_value_free(json);
            if (fatal_error) {
                free_natubot_conf(conf);
                return NULL;
            }
            return conf;
        }
        addlog("Expected root json value to be type object in %s", path);
        return NULL;
    }
    addlog("Error opening file at %s", path);
    return NULL;
}


sp_callback_data_t * create_sp_callback_data(irc_session_t * session, sp_session * sp, const char * nick, const char * channel) {
    sp_callback_data_t * cb_data = malloc(sizeof(sp_callback_data_t));
    cb_data->irc = session;
    cb_data->sp = sp;
    cb_data->nick = malloc(DEFAULT_BUF_SIZE);
    cb_data->channel = malloc(DEFAULT_BUF_SIZE);
    strcpy(cb_data->nick, nick);
    strcpy(cb_data->channel, channel);
    return cb_data;
}

void free_sp_callback_data(sp_callback_data_t * cb_data) {
    free(cb_data->nick);
    free(cb_data->channel);
    free(cb_data);
}

nick_list_t * create_nick(const char * nick) {
    nick_list_t * new_nick_data = malloc(sizeof(nick_list_t));
    new_nick_data->nick = malloc(DEFAULT_BUF_SIZE);
    strcpy(new_nick_data->nick, nick);
    new_nick_data->song_count = 0;
    new_nick_data->track = NULL;
    new_nick_data->next = NULL;
    return new_nick_data;
}


nick_list_t * nick_search(natubot_ctx_t * ctx, const char * nick) {
    nick_list_t * ptr = ctx->nick_list;
    for( ptr = ctx->nick_list; ptr != NULL; ptr = ptr->next ) {
        if ( !strcmp(ptr->nick, nick) )
            return ptr;
    }
    return NULL;
}

nick_list_t * nick_add(natubot_ctx_t * ctx, const char * nick) {
        nick_list_t * new_nick = create_nick(nick);
        new_nick->next = ctx->nick_list;
        ctx->nick_list = new_nick;
        return new_nick;
}

//callback to handle data received from libcurl

size_t curl_write_function(char *ptr, size_t size, size_t nmemb, void * userdata) {
    curl_callback_data_t * write_data = userdata;
    // total number of bytes after copy
    size_t total_bytes_size = nmemb*size + write_data->buf_length;
    //if buffer not large enough, resize
    if (total_bytes_size >= write_data->buf_capacity) {
        size_t new_capacity = RESIZE_BUF_FUNC(write_data->buf_capacity);
        while (total_bytes_size >= new_capacity)
            new_capacity = RESIZE_BUF_FUNC(new_capacity);
        char * new_buf = realloc(write_data->buf, new_capacity);
        write_data->buf = new_buf;
        write_data->buf_capacity = new_capacity;
    }
    //copy new bytes into buffer
    memcpy(write_data->buf + write_data->buf_length, ptr, size*nmemb);
    write_data->buf_length = total_bytes_size;
    return size*nmemb;
}

//dummy curl write function
size_t curl_silent(char *ptr, size_t size, size_t nmemb, void * userdata) {
	return size*nmemb;
}

int nick_is_subscriber(natubot_ctx_t * ctx, const char * channel, const char * nick) {
    if (ctx->twitch_access_token == NULL) {
        addlog("error: nick_is_subscriber requires twitch access token but none initialized");
        return -1;
    }
    CURL *curl = curl_easy_init();
    char url_buf[DEFAULT_BUF_SIZE], err_buf[CURL_ERROR_SIZE];
    int result;
    sprintf(url_buf, "https://api.twitch.tv/kraken/channels/%s/subscriptions/%s?oauth_token=%s&client_id=%s", channel, nick, ctx->twitch_access_token, CLIENT_ID);
    curl_easy_setopt(curl, CURLOPT_URL, url_buf);
    curl_easy_setopt(curl, CURLOPT_HEADER, "Accept: application/vnd.twitchtv.v2+json");
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_buf);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
#ifdef DEBUG
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#else
	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_silent);
#endif
    CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_HTTP_RETURNED_ERROR)
        result = 0;
    else if (code != CURLE_OK) {
        addlog("Curl error: %s", err_buf);
        result = 0;
    }
    else
        result = 1;
    curl_easy_cleanup(curl);    
    return result;
}



int get_twitch_access_token(natubot_ctx_t * ctx) {
    CURL *curl = curl_easy_init();
    char post_buf[DEFAULT_BUF_SIZE], curl_err_buf[CURL_ERROR_SIZE], json_err_buf[DEFAULT_BUF_SIZE],
         * curl_buf = malloc(DEFAULT_BUF_SIZE);
    int result;
    json_value * json;
    curl_callback_data_t write_data = {
        .buf = curl_buf,
        .buf_capacity = DEFAULT_BUF_SIZE,
        .buf_length = 0 
    };
#if defined (_WIN32)
    _snprintf(post_buf, DEFAULT_BUF_SIZE, "client_id=%s&client_secret=%s&grant_type=authorization_code&redirect_uri=%s&code=%s", CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, ctx->conf->twitch_auth_code);
#else
    snprintf(post_buf, DEFAULT_BUF_SIZE, "client_id=%s&client_secret=%s&grant_type=authorization_code&redirect_uri=%s&code=%s", CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, AUTH_CODE);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.twitch.tv/kraken/oauth2/token");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_data);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_buf);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (curl_easy_perform(curl)) {
        addlog("Curl error: %s", curl_err_buf);
        result = 1;
    }
    else {
        json = json_parse_ex(&default_json_settings, write_data.buf, write_data.buf_length, json_err_buf);
        if (json == NULL) {
            addlog("JSON parse error in get_twitch_access_token: %s", json_err_buf);
            result = 1;
        }
        else {
            result = 1;
            if (json->type == json_object) {
                for (int i = 0; i < json->u.object.length; i++) {
                    if (!strcmp("access_token", json->u.object.values[i].name)) {
                        json_value * access_token = json->u.object.values[i].value;
                        if (access_token->type == json_string) {
                            ctx->twitch_access_token = realloc(ctx->twitch_access_token, access_token->u.string.length);
                            strcpy(ctx->twitch_access_token, access_token->u.string.ptr);
                            result = 0;
                        }
                        else {
                            addlog("JSON parse error in get_twitch_access_token: access_token is not type string");
                        }
                    }
                }
            }
            else {
                addlog("JSON parse error in get_twitch_access_token: root value is not object");
            }
            json_value_free(json);
        }
    }
    curl_easy_cleanup(curl);
    free(curl_buf);
    return result;
}

char * get_playlist_url(natubot_ctx_t * ctx) {
	if (ctx->playlist_url == NULL) {
		char buf[DEFAULT_BUF_SIZE], *user_name, *playlist_name;
		ctx->playlist_url = malloc(DEFAULT_BUF_SIZE);
		int scan_result = sscanf(ctx->conf->spotify_playlist_uri, "spotify:user:%s", &buf);
		if (scan_result == EOF || scan_result == 0) {
			addlog("Error parsing spotify URI into URL.");
			return NULL;
		}
		user_name = strtok(buf, ":");
		strtok(NULL, ":");
		playlist_name = strtok(NULL, ":");
		sprintf(ctx->playlist_url, "http://play.spotify.com/user/%s/playlist/%s", user_name, playlist_name);
	}
	return ctx->playlist_url;
}

//extract nick from IRC user string
void extract_nick(const char * user, char * out) {
    char *ptr;
    strcpy(out, user);
    for(ptr = out; *ptr && *ptr != '!'; ptr++);
    *ptr = '\0';
}

void natubot_shutdown(irc_session_t * s) {
    natubot_ctx_t * ctx = irc_get_ctx(s);
    ctx->shutdown_flag = 1;
}

//generic event logger
void dump_event (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
    char buf[DEFAULT_BUF_SIZE];
    unsigned int cnt;

    buf[0] = '\0';

    for ( cnt = 0; cnt < count; cnt++ )
    {
        if ( cnt )
            strcat (buf, "|");

        strcat (buf, params[cnt]);
    }


    debuglog ("Event \"%s\", origin: \"%s\", params: %d [%s]", event, origin ? origin : "NULL", cnt, buf);
}


//IRC connect event
void event_connect (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
    natubot_ctx_t * ctx = irc_get_ctx(session);
    dump_event (session, event, origin, params, count);
    addlog("Successfully connected to IRC");
    get_twitch_access_token(ctx);
    if ( irc_cmd_join (session, ctx->conf->channel, 0) ) {
        addlog("Error joining channel %s: %s", ctx->conf->channel, irc_strerror (irc_errno(session)));
    }
}

//IRC numeric event
void event_numeric (irc_session_t * session, unsigned int event, const char * origin, const char ** params, unsigned int count) {
    char buf[24];
    sprintf (buf, "%d", event);
    dump_event (session, buf, origin, params, count);
}


//IRC JOIN event
void event_join(irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count) {
    char nick[DEFAULT_BUF_SIZE];
    natubot_ctx_t *ctx = irc_get_ctx(session);
    extract_nick(origin, nick);
    //if we just joined the channel, send a greeting
    if (!strcmp(nick, ctx->conf->nick)) {
        addlog("Successfully joined channel %s", params[0]);
    }
}

//callback to handle spotify search results
void SP_CALLCONV sp_search_callback(sp_search * search, void * blob) {
    sp_callback_data_t * cb_data = blob;
    natubot_ctx_t * ctx = irc_get_ctx(cb_data->irc);
    char buf[DEFAULT_BUF_SIZE];
    if(SP_ERROR_OK != sp_search_error(search)) {
        sprintf(buf, "Sorry %s, something went wrong with Spotify.", cb_data->nick);
        irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
    }
    else if (sp_search_num_tracks(search) == 0) {
        sprintf(buf, "Sorry %s, nothing on Spotify matches that search.", cb_data->nick);
        irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
    }
    else if (ctx->playlist == NULL || !sp_playlist_is_loaded(ctx->playlist)) {
        sprintf(buf, "No Spotify playlist loaded yet.");
        irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
    }
    else {    
        sp_track * track = sp_search_track(search, 0);
        sp_artist * artist = sp_track_artist(track, 0);
        sp_album * album = sp_track_album(track);
        int num_tracks = sp_playlist_num_tracks(ctx->playlist);
        int found_duplicate = 0;
        for (int i = 0; i < num_tracks; ++i) {
            if (sp_playlist_track(ctx->playlist, i) == track) {
                sprintf(buf, "Sorry %s, that song has already been requested.", cb_data->nick);
                irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
                found_duplicate = 1;
                break;
            }
        }
        if (!found_duplicate) {
            sp_error error = sp_playlist_add_tracks(ctx->playlist, &track, 1, sp_playlist_num_tracks(ctx->playlist), cb_data->sp);
            if (SP_ERROR_OK != error) {
                addlog("Error adding track to playlist: %s", sp_error_message(error));
                sprintf(buf, "Sorry %s, something went wrong with Spotify. BibleThump", cb_data->nick);
                irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
            }
            else {
                sprintf(buf, "Requested by %s:\n\ttrack: %s\n\tartist: %s\n\talbum: %s",
                    cb_data->nick, sp_track_name(track), sp_artist_name(artist), sp_album_name(album));
                addlog(buf);
                sprintf(buf, "Requested by %s | track: %s | artist: %s | album: %s | type !undo in the next %d seconds if this isn't the song you wanted",
                    cb_data->nick, sp_track_name(track), sp_artist_name(artist), sp_album_name(album), ctx->conf->undo_timer);
                irc_cmd_msg(cb_data->irc, cb_data->channel, buf);
                nick_list_t * nick_data = nick_search(ctx, cb_data->nick);
                if (nick_data == NULL)
                    nick_data = nick_add(ctx, cb_data->nick);
                if (nick_data->track != NULL)
                    sp_track_release(nick_data->track);
                sp_track_add_ref(track);
                nick_data->track = track;
                nick_data->song_count++;
            }
        }
    }
    free_sp_callback_data(cb_data);
    sp_search_release(search);
}

//IRC channel PRIVMSG event
void event_channel (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count) {
    dump_event (session, event, origin, params, count);
    char cmd[DEFAULT_BUF_SIZE], *msg, *ptr, buf[DEFAULT_BUF_SIZE], nick[DEFAULT_BUF_SIZE];
    const char *channel = params[0];
    natubot_ctx_t * ctx = irc_get_ctx(session);
    
    strcpy(cmd, params[1]);
    //trim leading spaces
    for( ptr = cmd; *ptr == ' '; ptr++);
    //extract command prefix
    while (*ptr && *ptr != ' ') ptr++;
    *ptr = '\0';
    msg = ptr+1;
    //addlog("cmd: %s msg: %s\n", cmd, msg);    
    if(!strcmp(cmd, "!song")) {
        extract_nick(origin, nick);
        if (nick_is_subscriber(ctx, channel+1, nick) ) {
            nick_list_t * nick_data = nick_search(ctx, nick);
            if(nick_data == NULL)
                nick_data = nick_add(ctx, nick);
            else if (nick_data->song_count >= ctx->conf->max_song_count) {
                sprintf(buf, "Sorry %s, only %hu request per stream.", nick, ctx->conf->max_song_count);
                irc_cmd_msg(session, channel, buf);
                return;
            }
            sp_callback_data_t * cb_data = create_sp_callback_data(session, ctx->sp, nick, channel);
            sp_search * search = sp_search_create(ctx->sp, msg, 0, 1, 0, 1, 0, 1, 0, 1, SP_SEARCH_STANDARD, sp_search_callback, cb_data);
        }
        else {
            sprintf(buf, "Song requests are a subscriber perk %s!", nick);
            irc_cmd_msg(session, channel, buf);
        }
    }
    else if (!strcmp(cmd, "!undo")) {
        extract_nick(origin, nick);
        nick_list_t * nick_data = nick_search(ctx, nick);
        if (nick_data == NULL || nick_data->track == NULL) {
            sprintf(buf, "Silly %s, you haven't requested a song.", nick);
            irc_cmd_msg(session, channel, buf);
        }
        else {
            int num_tracks = sp_playlist_num_tracks(ctx->playlist);
            for (int i = 0; i < num_tracks; i++) {
                if (sp_playlist_track(ctx->playlist, i) == nick_data->track) {
                    if (time(NULL) - sp_playlist_track_create_time(ctx->playlist, i) > ctx->conf->undo_timer) {
                        sprintf(buf, "Sorry %s, it's been more than %d seconds since you requested that song.", nick, ctx->conf->undo_timer);
                        irc_cmd_msg(session, channel, buf);
                        break;
                    }
                    sp_error error = sp_playlist_remove_tracks(ctx->playlist, &i, 1);
                    if (SP_ERROR_OK != error) {
                        addlog("Error removing track from spotify: %s", sp_error_message(error));
                    }
                    nick_data->song_count--;			
                    sprintf(buf, "Removed %s's track from playlist.", nick);
                    irc_cmd_msg(session, channel, buf);
                    addlog("Deleted %s's track from playlist.", nick);
                    sp_track_release(nick_data->track);
                    nick_data->track = NULL;			
                }
            }
        }
    }
	else if (!strcmp(cmd, "!playlist")) {
		char * url = get_playlist_url(ctx);
		if (url != NULL) {
			sprintf(buf, "Subscriber playlist: %s", url);
			irc_cmd_msg(session, channel, buf);
		}
	}
    else if (!strcmp(cmd, "!forget")) {
        extract_nick(origin, nick);
        if (!strcmp(nick, channel + 1)) {
            char target[DEFAULT_BUF_SIZE], *ptr;
            strcpy(target, msg);
            for (ptr = target; *ptr && *ptr != ' '; ptr++);
            *ptr = '\0';
            nick_list_t * nick_data = nick_search(ctx, target);
            if (nick_data == NULL) {
                sprintf(buf, "User %s not found.", target);
                irc_cmd_msg(session, channel, buf);
            }
            else {
                sprintf(buf, "Forgetting %s.", target);
                irc_cmd_msg(session, channel, buf);
                nick_data->song_count = 0;
                if (nick_data->track != NULL) {
                    sp_track_release(nick_data->track);
                    nick_data->track = NULL;
                }
            }
        }
    }
}

//sp login prompt
void sp_login(sp_session * sp) {
    if (SP_ERROR_OK == sp_session_relogin(sp)) {
        addlog("Relogin to spotify using stored credentials");
        return;
    }
    char username[DEFAULT_BUF_SIZE], password[DEFAULT_BUF_SIZE];
    printf("----Spotify Login----\nUsername: ");
    gets(username);
    printf("Password: ");

    //stop console echo for password prompt
#ifdef _WIN32
    HANDLE h_stdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(h_stdin, &mode);
    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(h_stdin, mode);
    gets(password);
    mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(h_stdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ~ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    gets(password);
    tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
    
    sp_session_login(sp, username, password, 1, NULL);
}

void SP_CALLCONV sp_login_event(sp_session * sp, sp_error error) {
    sp_link * playlist_link;
    natubot_ctx_t * ctx;
    if (SP_ERROR_OK != error) {
        addlog("Error logging into Spotify: %s", sp_error_message(error));
        sp_login(sp);
        return;
    }
    addlog("Spotify login successful.");
    ctx = sp_session_userdata(sp);
    if (ctx->playlist != NULL)
        sp_playlist_release(ctx->playlist);
    playlist_link = sp_link_create_from_string(ctx->conf->spotify_playlist_uri);
    if (playlist_link == NULL) {
        addlog("Failed to parse the spotify playlist URL.");
    }
    else {
        if (NULL == (ctx->playlist = sp_playlist_create(sp, playlist_link)))
            addlog("Unable to find playlist.");
        else
            addlog("Playlist loaded successfully.");
        sp_link_release(playlist_link);
    }
}

int main() {
    irc_callbacks_t	callbacks = { NULL };
    irc_session_t * irc;
    natubot_ctx_t ctx = { NULL };
    natubot_conf_t * conf;
    sp_session * sp = NULL;
    sp_session_callbacks sp_callbacks = { NULL };
    sp_error sp_error;
    char spotify_cache_location[DEFAULT_BUF_SIZE];

    //read natubot conf file
    if (NULL == (conf = read_natubot_conf(CONFFILE)))
        return 1;
    addlog("%s loaded successfully.", CONFFILE);

    //build path to spotify cache
#if defined (_WIN32)
    sprintf(spotify_cache_location, "%s\\AppData\\Local\\Spotify\\Storage", getenv("USERPROFILE"));
#else
    spotify_cache_location = "tmp";
#endif

    //spotify config
    const sp_session_config sp_config = {
        .api_version = SPOTIFY_API_VERSION,
        .cache_location = spotify_cache_location,
        .settings_location = spotify_cache_location,
        .user_agent = conf->nick,
        .application_key = g_appkey,
        .application_key_size = g_appkey_size,
        .userdata = &ctx,
        .callbacks = &sp_callbacks,
    };

    //spotify callbacks
    sp_callbacks.logged_in = sp_login_event;
    
    //initialize CURL
    if (curl_global_init(CURL_INIT_SETTING)) {
        addlog("Error initializing curl.");
        return 1;
    }

    //initialize spotify session
    if(SP_ERROR_OK != (sp_error = sp_session_create(&sp_config, &sp))) {
        addlog("Spotify session could not be created: %s", sp_error_message(sp_error));
        return 1;
    }
    //prompt for Spotify login credentials
    sp_login(sp);

    //initialize IRC callbacks
    callbacks.event_connect = event_connect;
    callbacks.event_join = event_join;
    callbacks.event_nick = dump_event;
    callbacks.event_quit = dump_event;
    callbacks.event_part = dump_event;
    callbacks.event_mode = dump_event;
    callbacks.event_topic = dump_event;
    callbacks.event_kick = dump_event;
    callbacks.event_channel = event_channel;
    callbacks.event_privmsg = dump_event;
    callbacks.event_notice = dump_event;
    callbacks.event_invite = dump_event;
    callbacks.event_umode = dump_event;
    callbacks.event_ctcp_rep = dump_event;
    callbacks.event_ctcp_action = dump_event;
    callbacks.event_unknown = dump_event;
    callbacks.event_numeric = event_numeric;

    //create IRC session
    if ( !(irc = irc_create_session(&callbacks)) ) {
        addlog("Error: Could not create IRC session.\n");
        return 1;
    }
    //initialize IRC context
    ctx.sp = sp;
    ctx.conf = conf;
    irc_set_ctx(irc, &ctx);

    // run IRC/spotify event loop
    while (!ctx.shutdown_flag) {
        struct timeval tv;
        fd_set in_set, out_set;
        int maxfd, sp_timeout;
        clock_t sp_last = 0;

        if (!irc_is_connected(irc)) {
            addlog("Connecting to IRC...");
            if (irc_connect(irc, conf->network, conf->port, conf->password, conf->nick, conf->username, conf->realname)) {
                addlog("Error: Could not connect: %s\n", irc_strerror(irc_errno(irc)));
                continue;
            }
        }
        maxfd = 0;
        tv.tv_usec = 250000;
        tv.tv_sec = 0;

        FD_ZERO(&in_set);
        FD_ZERO(&out_set);

        //add the IRC session descriptors
        irc_add_select_descriptors(irc, &in_set, &out_set, &maxfd);

        if (select(maxfd, &in_set, &out_set, 0, &tv) < 0) {
            addlog("Error: select failed");
        }

        //process libircclient events
        if (irc_process_select_descriptors(irc, &in_set, &out_set)) {
            addlog("Connection failed or server disconnect.");
        }

        if (sp_last == 0 || sp_last - clock() >= sp_timeout) {
            //process spotify events
            sp_session_process_events(sp, &sp_timeout);
            sp_last = clock();
        }
    }
    //cleanup
    irc_destroy_session(irc);
    sp_session_release(sp);
    curl_global_cleanup();

    return 0;
}