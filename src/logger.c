/*
    logger.c -- logging code
    Copyright (C) 2003 Guus Sliepen <guus@sliepen.eu.org>
                  2003 Ivo Timmermans <ivo@o2w.nl>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: logger.c,v 1.1.2.7 2003/07/29 10:50:15 guus Exp $
*/

#include "system.h"

#include "conf.h"
#include "logger.h"

debug_t debug_level = DEBUG_NOTHING;
static logmode_t logmode = LOGMODE_STDERR;
static pid_t logpid;
extern char *logfilename;
static FILE *logfile = NULL;
static const char *logident = NULL;

void openlogger(const char *ident, logmode_t mode) {
	logident = ident;
	logmode = mode;
	
	switch(mode) {
		case LOGMODE_STDERR:
			logpid = getpid();
			break;
		case LOGMODE_FILE:
			logpid = getpid();
			logfile = fopen(logfilename, "a");
			if(!logfile)
				logmode = LOGMODE_NULL;
			break;
		case LOGMODE_SYSLOG:
#ifdef HAVE_SYSLOG_H
			openlog(logident, LOG_CONS | LOG_PID, LOG_DAEMON);
			break;
#endif
		case LOGMODE_NULL:
			break;
	}
}

void logger(int priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);

	switch(logmode) {
		case LOGMODE_STDERR:
			vfprintf(stderr, format, ap);
			fprintf(stderr, "\n");
			break;
		case LOGMODE_FILE:
			fprintf(logfile, "%ld %s[%d]: ", time(NULL), logident, logpid);
			vfprintf(logfile, format, ap);
			fprintf(logfile, "\n");
			break;
		case LOGMODE_SYSLOG:
#ifdef HAVE_SYSLOG_H
#ifdef HAVE_VSYSLOG
			vsyslog(priority, format, ap);
#else
			{
				char message[4096];
				vsnprintf(message, sizeof(message), format, ap);
				syslog(priority, "%s", message);
			}
#endif
			break;
#endif
		case LOGMODE_NULL:
			break;
	}

	va_end(ap);
}

void closelogger(void) {
	switch(logmode) {
		case LOGMODE_FILE:
			fclose(logfile);
			break;
		case LOGMODE_SYSLOG:
#ifdef HAVE_SYSLOG_H
			closelog();
			break;
#endif
		case LOGMODE_NULL:
		case LOGMODE_STDERR:
			break;
			break;
	}
}