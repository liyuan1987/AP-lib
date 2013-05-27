#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "airplay.h"
#include "airplay_rtp.h"
#include "rsakey.h"
#include "digest.h"
#include "httpd.h"
#include "sdp.h"

#include "global.h"
#include "utils.h"
#include "netutils.h"
#include "logger.h"
#include "compat.h"

#define STRLEN(s) (sizeof(s)-1)

//liyuan-doubt airplay port is 6000?
enum {
   STATUS_OK=200, STATUS_SWITCHING_PROTOCOLS=101, STATUS_NOT_IMPLEMENTED=501,
};

static const char *http_status_string(int status)
{
   if (status == STATUS_OK) return "OK";
   else if (status == STATUS_NOT_IMPLEMENTED) return "Not Implemented";
   else if (status == STATUS_SWITCHING_PROTOCOLS) return "Switching Protocols";
   assert(0);
   return "Unknown";
}

struct airplay_s {
	/* Callbacks for audio */
	//raop_callbacks_t callbacks;

	/* Logger instance */
	logger_t *logger;

	/* HTTP daemon and RSA key */
	httpd_t *httpd;
	//rsakey_t *rsakey;

	/* Hardware address information */
	unsigned char hwaddr[MAX_HWADDR_LEN];
	int hwaddrlen;

	/* Password information */
	char password[MAX_PASSWORD_LEN+1];
};

airplay_t *
airplay_init(int max_clients, airplay_callbacks_t *callbacks, int *error)
{
	airplay_t *airplay;
	httpd_t *httpd;
	httpd_callbacks_t httpd_cbs;

	assert(callbacks);
	assert(max_clients > 0);
	assert(max_clients < 100);

	/* Initialize the network */
	if (netutils_init() < 0) {
		return NULL;
	}

	/* Validate the callbacks structure */
	//liyuan-doubt
	if (!callbacks->audio_init ||
	    !callbacks->audio_process ||
	    !callbacks->audio_destroy) {
		return NULL;
	}

	/* Allocate the raop_t structure */
	airplay = calloc(1, sizeof(airplay_t));
	if (!airplay) {
		return NULL;
	}

	/* Initialize the logger */
	//liyuan-doubt
	airplay->logger = logger_init();

	/* Set HTTP callbacks to our handlers */
	memset(&httpd_cbs, 0, sizeof(httpd_cbs));
	httpd_cbs.opaque = airplay;
	//liyuan-doubt
	httpd_cbs.conn_init = &airplay_conn_init;
	httpd_cbs.conn_request = &airplay_conn_request;
	httpd_cbs.conn_destroy = &airplay_conn_destroy;

	/* Initialize the http daemon */
	httpd = httpd_init(airplay->logger, &httpd_cbs, max_clients);
	if (!httpd) {
		free(airplay);
		return NULL;
	}

	/* Copy callbacks structure */
	memcpy(&airplay->callbacks, callbacks, sizeof(airplay_callbacks_t));

	/* Initialize RSA key handler */
	/*
	rsakey = rsakey_init_pem(pemkey);
	if (!rsakey) {
		free(httpd);
		free(raop);
		return NULL;
	}
	*/

	airplay->httpd = httpd;
	//raop->rsakey = rsakey;

	return airplay;
}

int
airplay_start(airplay_t *airplay, unsigned short *port, const char *hwaddr, int hwaddrlen)
{
	assert(airplay);
	assert(port);
	assert(hwaddr);

	/* Validate hardware address */
	if (hwaddrlen > MAX_HWADDR_LEN) {
		return -1;
	}

	/* Copy hwaddr to the raop structure */
	memcpy(airplay->hwaddr, hwaddr, hwaddrlen);
	airplay->hwaddrlen = hwaddrlen;

	return httpd_start(airplay->httpd, port);
}

struct airplay_conn_s {
	airplay_t *airplay;
	//airplay_rtp_t *airplay_rtp;

	unsigned char *local;
	int locallen;

	unsigned char *remote;
	int remotelen;

	char nonce[MAX_NONCE_LEN+1];
};
typedef struct airplay_conn_s airplay_conn_t;

static void *
airplay_conn_init(void *opaque, unsigned char *local, int locallen, unsigned char *remote, int remotelen)
{
	airplay_conn_t *conn;

	conn = calloc(1, sizeof(airplay_conn_t));
	if (!conn) {
		return NULL;
	}
	conn->airplay = opaque;
	//conn->airplay_rtp = NULL;

	if (locallen == 4) {
		logger_log(conn->airplay->logger, LOGGER_INFO,
		           "Local: %d.%d.%d.%d",
		           local[0], local[1], local[2], local[3]);
	} else if (locallen == 16) {
		logger_log(conn->airplay->logger, LOGGER_INFO,
		           "Local: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		           local[0], local[1], local[2], local[3], local[4], local[5], local[6], local[7],
		           local[8], local[9], local[10], local[11], local[12], local[13], local[14], local[15]);
	}
	if (remotelen == 4) {
		logger_log(conn->airplay->logger, LOGGER_INFO,
		           "Remote: %d.%d.%d.%d",
		           remote[0], remote[1], remote[2], remote[3]);
	} else if (remotelen == 16) {
		logger_log(conn->airplay->logger, LOGGER_INFO,
		           "Remote: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		           remote[0], remote[1], remote[2], remote[3], remote[4], remote[5], remote[6], remote[7],
		           remote[8], remote[9], remote[10], remote[11], remote[12], remote[13], remote[14], remote[15]);
	}

	conn->local = malloc(locallen);
	assert(conn->local);
	memcpy(conn->local, local, locallen);

	conn->remote = malloc(remotelen);
	assert(conn->remote);
	memcpy(conn->remote, remote, remotelen);

	conn->locallen = locallen;
	conn->remotelen = remotelen;

	//liyuan-doubt need?
	digest_generate_nonce(conn->nonce, sizeof(conn->nonce));
	return conn;
}


static void
airplay_conn_request(void *ptr, http_request_t *request, http_response_t **response)
{
	raop_conn_t *conn = ptr;
	raop_t *raop = conn->raop;

	http_response_t *res;
	const char *method;
	const char *url;
	int status = STATUS_OK;
	char *found;
	//const char *cseq;
	//const char *challenge;
	//int require_auth = 0;

	method = http_request_get_method(request);
	//cseq = http_request_get_header(request, "CSeq");
	if (!method) {
		return;
	}

	//res = http_response_init("HTTP/1.1", 200, "OK");
	url = http_request_get_url(request);
#if 0
	if (strlen(raop->password)) {
		const char *authorization;

		authorization = http_request_get_header(request, "Authorization");
		if (authorization) {
			logger_log(conn->raop->logger, LOGGER_DEBUG, "Our nonce: %s", conn->nonce);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "Authorization: %s", authorization);
		}
		if (!digest_is_valid("AppleTV", raop->password, conn->nonce, method, http_request_get_url(request), authorization)) {
			char *authstr;
			int authstrlen;

			/* Allocate the authenticate string */
			authstrlen = sizeof("Digest realm=\"AppleTV\", nonce=\"\"") + sizeof(conn->nonce) + 1;
			authstr = malloc(authstrlen);

			/* Concatenate the authenticate string */
			memset(authstr, 0, authstrlen);
			strcat(authstr, "Digest realm=\"AppleTV\", nonce=\"");
			strcat(authstr, conn->nonce);
			strcat(authstr, "\"");

			/* Construct a new response */
			require_auth = 1;
			http_response_destroy(res);
			res = http_response_init("RTSP/1.0", 401, "Unauthorized");
			http_response_add_header(res, "WWW-Authenticate", authstr);
			free(authstr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "Authentication unsuccessful, sending Unauthorized");
		} else {
			logger_log(conn->raop->logger, LOGGER_DEBUG, "Authentication successful!");
		}
	}
#endif
	//http_response_add_header(res, "CSeq", cseq);
	//http_response_add_header(res, "Apple-Jack-Status", "connected; type=analog");

	//challenge = http_request_get_header(request, "Apple-Challenge");
#if 0
	if (!require_auth && challenge) {
		char signature[MAX_SIGNATURE_LEN];

		memset(signature, 0, sizeof(signature));
		rsakey_sign(raop->rsakey, signature, sizeof(signature), challenge,
		            conn->local, conn->locallen, raop->hwaddr, raop->hwaddrlen);
		http_response_add_header(res, "Apple-Response", signature);

		logger_log(conn->raop->logger, LOGGER_DEBUG, "Got challenge: %s", challenge);
		logger_log(conn->raop->logger, LOGGER_DEBUG, "Got response: %s", signature);
	}
	if (!strcmp(method, "OPTIONS")) {
		http_response_add_header(res, "Public", "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER");
	} else if (!strcmp(method, "ANNOUNCE")) {
		const char *data;
		int datalen;

		unsigned char aeskey[16];
		unsigned char aesiv[16];
		int aeskeylen, aesivlen;

		data = http_request_get_data(request, &datalen);
		if (data) {
			sdp_t *sdp;
			const char *remotestr, *rtpmapstr, *fmtpstr, *aeskeystr, *aesivstr;

			sdp = sdp_init(data, datalen);
			remotestr = sdp_get_connection(sdp);
			rtpmapstr = sdp_get_rtpmap(sdp);
			fmtpstr = sdp_get_fmtp(sdp);
			aeskeystr = sdp_get_rsaaeskey(sdp);
			aesivstr = sdp_get_aesiv(sdp);

			logger_log(conn->raop->logger, LOGGER_DEBUG, "connection: %s", remotestr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "rtpmap: %s", rtpmapstr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "fmtp: %s", fmtpstr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "rsaaeskey: %s", aeskeystr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "aesiv: %s", aesivstr);

			aeskeylen = rsakey_decrypt(raop->rsakey, aeskey, sizeof(aeskey), aeskeystr);
			aesivlen = rsakey_parseiv(raop->rsakey, aesiv, sizeof(aesiv), aesivstr);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "aeskeylen: %d", aeskeylen);
			logger_log(conn->raop->logger, LOGGER_DEBUG, "aesivlen: %d", aesivlen);

			if (conn->raop_rtp) {
				/* This should never happen */
				raop_rtp_destroy(conn->raop_rtp);
				conn->raop_rtp = NULL;
			}
			conn->raop_rtp = raop_rtp_init(raop->logger, &raop->callbacks, remotestr, rtpmapstr, fmtpstr, aeskey, aesiv);
			if (!conn->raop_rtp) {
				logger_log(conn->raop->logger, LOGGER_ERR, "Error initializing the audio decoder");
				http_response_set_disconnect(res, 1);
			}
			sdp_destroy(sdp);
		}
	} else if (!strcmp(method, "SETUP")) {
		unsigned short remote_cport=0, remote_tport=0;
		unsigned short cport=0, tport=0, dport=0;
		const char *transport;
		char buffer[1024];
		int use_udp;

		transport = http_request_get_header(request, "Transport");
		assert(transport);

		logger_log(conn->raop->logger, LOGGER_INFO, "Transport: %s", transport);
		use_udp = strncmp(transport, "RTP/AVP/TCP", 11);
		if (use_udp) {
			char *original, *current, *tmpstr;

			current = original = strdup(transport);
			if (original) {
				while ((tmpstr = utils_strsep(&current, ";")) != NULL) {
					unsigned short value;
					int ret;

					ret = sscanf(tmpstr, "control_port=%hu", &value);
					if (ret == 1) {
						logger_log(conn->raop->logger, LOGGER_DEBUG, "Found remote control port: %hu", value);
						remote_cport = value;
					}
					ret = sscanf(tmpstr, "timing_port=%hu", &value);
					if (ret == 1) {
						logger_log(conn->raop->logger, LOGGER_DEBUG, "Found remote timing port: %hu", value);
						remote_tport = value;
					}
				}
			}
			free(original);
		}
		if (conn->raop_rtp) {
			raop_rtp_start(conn->raop_rtp, use_udp, remote_cport, remote_tport, &cport, &tport, &dport);
		} else {
			logger_log(conn->raop->logger, LOGGER_ERR, "RAOP not initialized at SETUP, playing will fail!");
			http_response_set_disconnect(res, 1);
		}

		memset(buffer, 0, sizeof(buffer));
		if (use_udp) {
			snprintf(buffer, sizeof(buffer)-1,
			         "RTP/AVP/UDP;unicast;mode=record;timing_port=%hu;events;control_port=%hu;server_port=%hu",
			         tport, cport, dport);
		} else {
			snprintf(buffer, sizeof(buffer)-1,
			         "RTP/AVP/TCP;unicast;interleaved=0-1;mode=record;server_port=%u",
			         dport);
		}
		logger_log(conn->raop->logger, LOGGER_INFO, "Responding with %s", buffer);
		http_response_add_header(res, "Transport", buffer);
		http_response_add_header(res, "Session", "DEADBEEF");
	} else if (!strcmp(method, "SET_PARAMETER")) {
		const char *content_type;
		const char *data;
		int datalen;

		content_type = http_request_get_header(request, "Content-Type");
		data = http_request_get_data(request, &datalen);
		if (!strcmp(content_type, "text/parameters")) {
			char *datastr;
			datastr = calloc(1, datalen+1);
			if (data && datastr && conn->raop_rtp) {
				memcpy(datastr, data, datalen);
				if (!strncmp(datastr, "volume: ", 8)) {
					float vol = 0.0;
					sscanf(datastr+8, "%f", &vol);
					raop_rtp_set_volume(conn->raop_rtp, vol);
				}
			} else if (!conn->raop_rtp) {
				logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER volume");
			}
			free(datastr);
		} else if (!strcmp(content_type, "image/jpeg")) {
			logger_log(conn->raop->logger, LOGGER_INFO, "Got image data of %d bytes", datalen);
			if (conn->raop_rtp) {
				raop_rtp_set_coverart(conn->raop_rtp, data, datalen);
			} else {
				logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER coverart");
			}
		} else if (!strcmp(content_type, "application/x-dmap-tagged")) {
			logger_log(conn->raop->logger, LOGGER_INFO, "Got metadata of %d bytes", datalen);
			if (conn->raop_rtp) {
				raop_rtp_set_metadata(conn->raop_rtp, data, datalen);
			} else {
				logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER metadata");
			}
		}
	} else if (!strcmp(method, "FLUSH")) {
		const char *rtpinfo;
		int next_seq = -1;

		rtpinfo = http_request_get_header(request, "RTP-Info");
		if (rtpinfo) {
			logger_log(conn->raop->logger, LOGGER_INFO, "Flush with RTP-Info: %s", rtpinfo);
			if (!strncmp(rtpinfo, "seq=", 4)) {
				next_seq = strtol(rtpinfo+4, NULL, 10);
			}
		}
		if (conn->raop_rtp) {
			raop_rtp_flush(conn->raop_rtp, next_seq);
		} else {
			logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at FLUSH");
		}
	} else if (!strcmp(method, "TEARDOWN")) {
		http_response_add_header(res, "Connection", "close");
		if (conn->raop_rtp) {
			/* Destroy our RTP session */
			raop_rtp_stop(conn->raop_rtp);
			raop_rtp_destroy(conn->raop_rtp);
			conn->raop_rtp = NULL;
		}
	}
#endif

	if (!strcmp(url, "/reverse")) {
		status = STATUS_SWITCHING_PROTOCOLS;
		res = http_response_init("HTTP/1.1", status, http_status_string(status));
		http_response_add_header(res, "Upgrade", "PTTH/1.0");
		http_response_add_header(res, "Connection", "Upgrade");
		//sprintf(content, "*Upgrade: PTTH/1.0"NL"Connection: Upgrade"NL);
	} else if (!strcmp(url, "/rate")) {
		found = strstr(url, "?value=");
		int rate = found ? (int)(atof(found+STRLEN("?value="))+0.5f):0;
		//liyuan set_rate
		printf("/rate;rate:%d\n", rate);
		/*
		fprintf (stderr, "Found rate call, rate=%d\n", rate);
		set_media_mode(rate ? MEDIA_RESUME:MEDIA_PAUSE);
		if (rate && last_scrub >= 0) {
			set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
			last_position = last_scrub;
			last_scrub = -1;
		}
		*/
		res = http_response_init("HTTP/1.1", status, http_status_string(status));
	} else if (!strcmp(url, "/play ")) {
		const char *content_type;
		content_type = http_request_get_header(request, "Content-Type");
		if (content_type) {
			if (!strncmp(content_type, "application/x-apple-binary-plist", 4)) {
				next_seq = strtol(rtpinfo+4, NULL, 10);
			}
		}
		int binaryplist = strstr(buffer, "application/x-apple-binary-plist") != 0;
		float fposition = 0.0f;
		//iTunes
		if (!binaryplist) {
			if (found = strstr(buffer, "Start-Position: "), found) {
				found += STRLEN("Start-Position: ");
				fposition = atof(found);
			}
			if (found = strstr(buffer, "Content-Location: "), found) {
				found += STRLEN("Content-Location: ");
				char *newline = strchr(found, '\n');
			if (newline) *newline = '\0';
			else found = 0;
			}
		} else {//iPhone
			int length=0;
			char *end = NULL;
			found = bplist_find_content(body, body_size, &end, &fposition);
			if (found) {
				if (end) *end = '\0';
				else found = 0;
			}
		}
		if (found && !media_supported(found)) {
			load_html( HTML_REPORT_ERRROR2, "Media type not supported:", found);
			found = 0;
		}
		if (found) {
			int proxy= requires_proxy(filedes, found);
			fprintf (stderr, "Found content: %s (%d) (%f)\n", found, proxy, fposition);
			UrlMangle(found, airplay_url, sizeof airplay_url, (proxy | proxyon) & ~proxyoff);
#ifdef A100
			set_bookmark(airplay_url, last_scrub);
			set_media_mode_url(MEDIA_PLAY, airplay_url);
			last_position = last_scrub;
			last_scrub = -1;

#else
			if (last_scrub >= 0) {
				set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
				last_position = last_scrub;
				last_scrub = -1;
			}
#endif
		} else {
			fprintf (stderr, "Content not found: [%s]\n", buffer);
		}
		if (!found) status = STATUS_NOT_IMPLEMENTED;
   } else if (!strcmp(url, "/scrub")) {
      int position = 0, seek_offset = -1, duration = 0;
      int itunes = 0;
      found = strstr(buffer, "User-Agent: ");
      if (found) {
         found += STRLEN("User-Agent: ");
         if (strncmp(found, "iTunes", STRLEN("iTunes"))==0)
            itunes=1;
      }
      found = strstr(buffer, "?position=");
      if (found) seek_offset = (int)(atof(found+STRLEN("?position="))+0.0f);
      if (seek_offset >= 0) {
         fprintf (stderr, "Found scrub call, position=%d\n", seek_offset);
      }
      if (seek_offset >= 0) {
         last_scrub = last_position = position = seek_offset;
         duration = 0;//last_duration;
      } else {
         int playing=0, paused=0, stopped=0, buffering=0, seekable=0;
         int media_status = get_media_info(&position, &duration, &playing, &paused, &stopped, &buffering, &seekable);
         if (media_status != 0 || !playing || paused) {
            position = last_position;
            duration = last_duration;
         } else {
#ifndef A100
            last_duration = duration;
            last_position = position;
#endif
         }
      }
      if (itunes && last_scrub >= 0) {
         set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
         last_position = last_scrub;
         last_scrub = -1;
      }
      if (duration) sprintf(content, "duration: %f"NL"position: %f", (double)duration, (double)position);
   } else if (!strcmp(url, "/stop")) {
      fprintf (stderr, "Stop request\n");
      set_media_mode(MEDIA_STOP);
   } else if (!strcmp(url, "/photo")) {
      fprintf (stderr, "Found photo call retrieve content address\n");
      int s;
      if (body_size && body) {
         char *photo = malloc(body_size);
         const int header_size = body-buffer;
         const int already_got = nbytes-header_size;
         assert(already_got >= 0);
         assert(photo);
         memcpy(photo, body, already_got);
         s = socket_read(LOG_MAIN, filedes, photo+already_got, body_size-already_got);
         assert(s==body_size-already_got);
         FILE *fp = fopen("/tmp/airplay_photo.jpg", "wb");
         assert(fp);
         s = fwrite(photo, 1, body_size, fp);
         assert(s==body_size);
         fclose(fp);
         free(photo);
         set_media_mode_url(MEDIA_PHOTO, "file:///tmp/airplay_photo.jpg");
      }
   } else if (!strcmp(url, "/volume")) {
      // ignore
   } else if (!strcmp(url, "/server-info")) {
      sprintf(content, SERVER_INFO, get_mac_addr());
      sprintf(header, "Content-Type: text/x-apple-plist+xml"NL);
   } else if (!strcmp(url, "/playback-info")) {
		int position=0, duration=0;
      int playing=0, paused=0, stopped=0, buffering=0, seekable=0;
      int media_status = get_media_info(&position, &duration, &playing, &paused, &stopped, &buffering, &seekable);
      if (media_status != 0 || !playing || paused) {
         position = last_position;
         duration = last_duration;
      } else {
#ifndef A100
         last_duration = duration;
         last_position = position;
#endif
      }
      sprintf(content, PLAYBACK_INFO, (float)duration, (float)duration, (float)position, playing, (float)duration);
      sprintf(header, "Content-Type: text/x-apple-plist+xml"NL);
   } else if (!strcmp(url, "/slideshow-features")) {
      status = STATUS_NOT_IMPLEMENTED;
   } else if (!strcmp(url, "/authorize")) {
      load_html( HTML_REPORT_ERRROR2, "DRM protected content not supported", "");
      status = STATUS_NOT_IMPLEMENTED;
   } else if (!strcmp(url, "/setProperty")) {
      // just silently ignore for now
   } else if (!strcmp(url, "/getProperty")) {
      // just silently ignore for now
   } else {
      fprintf (stderr, "Unhandled [%s]\n", buffer);
      status = STATUS_NOT_IMPLEMENTED;
   }
	http_response_finish(res, NULL, 0);

	logger_log(conn->raop->logger, LOGGER_DEBUG, "Handled request %s with URL %s", method, http_request_get_url(request));
	*response = res;
}

static void
airplay_conn_destroy(void *ptr)
{
	raop_conn_t *conn = ptr;

	free(conn->local);
	free(conn->remote);
	free(conn);
}


static int read_from_client(int filedes)
{
   char *buffer = malloc(MAX_HEADER+1); // allow null on end
   char *content = malloc(MAX_RESPONSE);
   char *header = malloc(MAX_RESPONSE);
   int nbytes;
   char *found;
   int status = STATUS_OK;
   char *body=0; int body_size = 0;
   assert(buffer && content && header);
   content[0] = '\0';
   header[0] = '\0';

   nbytes = http_read_header(LOG_MAIN, filedes, buffer, MAX_HEADER, &body, &body_size);
   if (nbytes > 0) {
      buffer[nbytes] = '\0';
   } else {
      /* End-of-file. */
      assert(nbytes == 0);
      status = 1;
      goto fail;
   }
   if (found = strstr(buffer,"/reverse"), found) {
      status = STATUS_SWITCHING_PROTOCOLS;
      sprintf(content, "*Upgrade: PTTH/1.0"NL"Connection: Upgrade"NL);
   } else if (found = strstr(buffer,"/rate"), found) {
      found = strstr(found, "?value=");
      int rate = found ? (int)(atof(found+STRLEN("?value="))+0.5f):0;
      fprintf (stderr, "Found rate call, rate=%d\n", rate);
      set_media_mode(rate ? MEDIA_RESUME:MEDIA_PAUSE);
      if (rate && last_scrub >= 0) {
         set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
         last_position = last_scrub;
         last_scrub = -1;
      }
   } else if (found = strstr(buffer,"/play "), found) {
      int binaryplist = strstr(buffer, "application/x-apple-binary-plist") != 0;
      float fposition = 0.0f;
      if (!binaryplist) {
         if (found = strstr(buffer, "Start-Position: "), found) {
            found += STRLEN("Start-Position: ");
            fposition = atof(found);
         }
         if (found = strstr(buffer, "Content-Location: "), found) {
            found += STRLEN("Content-Location: ");
            char *newline = strchr(found, '\n');
            if (newline) *newline = '\0';
            else found = 0;
         }
      } else {
         int length=0;
         char *end = NULL;
         found = bplist_find_content(body, body_size, &end, &fposition);
         if (found) {
            if (end) *end = '\0';
            else found = 0;
         }
      }
      if (found && !media_supported(found)) {
         load_html( HTML_REPORT_ERRROR2, "Media type not supported:", found);
         found = 0;
      }
      if (found) {
         int proxy= requires_proxy(filedes, found);
         fprintf (stderr, "Found content: %s (%d) (%f)\n", found, proxy, fposition);
         UrlMangle(found, airplay_url, sizeof airplay_url, (proxy | proxyon) & ~proxyoff);
#ifdef A100
         set_bookmark(airplay_url, last_scrub);
         set_media_mode_url(MEDIA_PLAY, airplay_url);
         last_position = last_scrub;
         last_scrub = -1;

#else
         if (last_scrub >= 0) {
            set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
            last_position = last_scrub;
            last_scrub = -1;
         }
#endif
      } else {
         fprintf (stderr, "Content not found: [%s]\n", buffer);
      }
      if (!found) status = STATUS_NOT_IMPLEMENTED;
   } else if (found = strstr(buffer,"/scrub"), found) {
      int position = 0, seek_offset = -1, duration = 0;
      int itunes = 0;
      found = strstr(buffer, "User-Agent: ");
      if (found) {
         found += STRLEN("User-Agent: ");
         if (strncmp(found, "iTunes", STRLEN("iTunes"))==0)
            itunes=1;
      }
      found = strstr(buffer, "?position=");
      if (found) seek_offset = (int)(atof(found+STRLEN("?position="))+0.0f);
      if (seek_offset >= 0) {
         fprintf (stderr, "Found scrub call, position=%d\n", seek_offset);
      }
      if (seek_offset >= 0) {
         last_scrub = last_position = position = seek_offset;
         duration = 0;//last_duration;
      } else {
         int playing=0, paused=0, stopped=0, buffering=0, seekable=0;
         int media_status = get_media_info(&position, &duration, &playing, &paused, &stopped, &buffering, &seekable);
         if (media_status != 0 || !playing || paused) {
            position = last_position;
            duration = last_duration;
         } else {
#ifndef A100
            last_duration = duration;
            last_position = position;
#endif
         }
      }
      if (itunes && last_scrub >= 0) {
         set_media_mode_ex(MEDIA_SEEK, NULL, last_scrub, NULL, NULL);
         last_position = last_scrub;
         last_scrub = -1;
      }
      if (duration) sprintf(content, "duration: %f"NL"position: %f", (double)duration, (double)position);
   } else if (found = strstr(buffer,"/stop"), found) {
      fprintf (stderr, "Stop request\n");
      set_media_mode(MEDIA_STOP);
   } else if (found = strstr(buffer,"/photo"), found) {
      fprintf (stderr, "Found photo call retrieve content address\n");
      int s;
      if (body_size && body) {
         char *photo = malloc(body_size);
         const int header_size = body-buffer;
         const int already_got = nbytes-header_size;
         assert(already_got >= 0);
         assert(photo);
         memcpy(photo, body, already_got);
         s = socket_read(LOG_MAIN, filedes, photo+already_got, body_size-already_got);
         assert(s==body_size-already_got);
         FILE *fp = fopen("/tmp/airplay_photo.jpg", "wb");
         assert(fp);
         s = fwrite(photo, 1, body_size, fp);
         assert(s==body_size);
         fclose(fp);
         free(photo);
         set_media_mode_url(MEDIA_PHOTO, "file:///tmp/airplay_photo.jpg");
      }
   } else if (found = strstr(buffer,"/volume"), found) {
      // ignore
   } else if (found = strstr(buffer,"/server-info"), found) {
      sprintf(content, SERVER_INFO, get_mac_addr());
      sprintf(header, "Content-Type: text/x-apple-plist+xml"NL);
   } else if (found = strstr(buffer,"/playback-info"), found) {
      int position=0, duration=0;
      int playing=0, paused=0, stopped=0, buffering=0, seekable=0;
      int media_status = get_media_info(&position, &duration, &playing, &paused, &stopped, &buffering, &seekable);
      if (media_status != 0 || !playing || paused) {
         position = last_position;
         duration = last_duration;
      } else {
#ifndef A100
         last_duration = duration;
         last_position = position;
#endif
      }
      sprintf(content, PLAYBACK_INFO, (float)duration, (float)duration, (float)position, playing, (float)duration);
      sprintf(header, "Content-Type: text/x-apple-plist+xml"NL);
   } else if (found = strstr(buffer,"/slideshow-features"), found) {
      status = STATUS_NOT_IMPLEMENTED;
   } else if (found = strstr(buffer,"/authorize"), found) {
      load_html( HTML_REPORT_ERRROR2, "DRM protected content not supported", "");
      status = STATUS_NOT_IMPLEMENTED;
   } else if (found = strstr(buffer,"/setProperty"), found) {
      // just silently ignore for now
   } else if (found = strstr(buffer,"/getProperty"), found) {
      // just silently ignore for now
   } else {
      fprintf (stderr, "Unhandled [%s]\n", buffer);
      status = STATUS_NOT_IMPLEMENTED;
   }
   if (status) http_response(LOG_MAIN, filedes, status, http_status_string(status), content[0] ? content:NULL, header[0] ? header:NULL);
   fail:
   if (buffer) free(buffer);
   if (content) free(content);
   if (header) free(header);
   return status==STATUS_OK || status==STATUS_SWITCHING_PROTOCOLS ? 0:-status;
}

