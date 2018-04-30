#include"apue.h"
#if defined(SOLARIS)
#include<netinet/in.h>
#endif
#include<netdb.h>
#include<arpa/inet.h>
#if defined(BSD)
#include<sys/socket.h>
#include<netinet/in.h>
#endif

#define MAXSLEEP 128

#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/wait.h>
#define BUFLEN 128
#define QLEN 10

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#include <fcntl.h>
#include <stdarg.h>

#include <sys/resource.h>
#define doit(name) pr_limits(#name, name)

static void pr_limits(char *, int);

extern int initserver(int, const struct sockaddr *, socklen_t, int);

uint32_t htonl(uint32_t hostint32); //네트워크 바이트 순서의 32비트 정수
uint16_t htons(uint16_t hostint16); //네트워크 바이트 순서의 16비트 정수
uint32_t ntohl(uint32_t netint32); //호스트 바이트 순서의 32비트 정수
uint16_t ntohs(uint16_t netint16); //호스트 바이트 순서의 16비트 정수

int main(int argc, char *argv[])
{
	struct addrinfo *ailist, *aip;
	struct addrinfo hint;
	struct sockaddr_in *sinp;
	const char *addr;
	int sockfd;
	int err;
	int n;
	char abuf[16];
	char *host;

	if (argc != 1)
		err_quit("usage: ruptimed");
	if ((n = sysconf(_SC_HOST_NAME_MAX)) < 0)
		n = HOST_NAME_MAX; /* best guess */
	if ((host = malloc(n)) == NULL)
		err_sys("malloc error");
	if (gethostname(host, n) < 0)
		err_sys("gethostname error");
	daemonize("ruptimed");
	memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_CANONNAME;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_canonname = NULL;
	hint.ai_addr = NULL;
	hint.ai_next = NULL;

	if ((err = getaddrinfo(host, "ruptime", &hint, &ailist)) != 0) {
		syslog(LOG_ERR, "ruptimed: getaddrinfo error: %s", gai_strerror(err));
		exit(1);
	}

	for (aip = ailist; aip != NULL; aip = aip->ai_next) {
		if ((sockfd = initserver(SOCK_STREAM, aip->ai_addr, aip->ai_addrlen, QLEN)) >= 0) {
			serve(sockfd);
			exit(0);
		}
	}

	exit(1);

	if (argc != 3)
		err_quit("usage: %s nodename service", argv[0]);
	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = 0;
	hint.ai_socktype = 0;
	hint.ai_protocol = 0;
	hint.ai_addrlen = 0;
	hint.ai_canonname = NULL;
	hint.ai_addr = NULL;
	hint.ai_next = NULL;

	if ((err = getaddrinfo(argv[1], argv[2], &hint, &ailist)) != 0)
		err_quit("getaddrinfo error : %s", gai_strerror(err));
	for (aip = ailist; aip != NULL; aip = aip->ai_next) {
		print_flags(aip);
		print_family(aip);
		print_type(aip);
		print_protocol(aip);
		printf("\n\thost %s", aip->ai_canonname ? aip->ai_canonname : "-");

		if (aip->ai_family == AF_INET) {
			sinp = (struct sockaddr_in *)aip->ai_addr;
			addr = inet_ntop(AF_INET, &sinp->sin_addr, abuf, 16);
			printf(" address %s", addr ? addr : "unknown");
			printf(" port %d", ntohs(sinp->sin_port));
		}
		printf("\n");
	}
	exit(0);
}

static void err_doit(int, int, const char *, va_list);
/*
* Nonfatal error related to a system call.
* Print a message and return.
*/

void err_ret(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
}
/*
* Fatal error related to a system call.
* Print a message and terminate.
*/
void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
	exit(1);
}
/*
* Nonfatal error unrelated to a system call.
* Error code passed as explict parameter.
* Print a message and return.
*/
void err_cont(int error, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, error, fmt, ap);
	va_end(ap);
}
/*
* Fatal error unrelated to a system call.
* Error code passed as explict parameter.
* Print a message and terminate.
*/
void err_exit(int error, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, error, fmt, ap);
	va_end(ap);
	exit(1);
}
/*
* Fatal error related to a system call.
* Print a message, dump core, and terminate.
*/
void err_dump(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
	abort(); /* dump core and terminate */
	exit(1); /* shouldn’t get here */
}
/*
* Nonfatal error unrelated to a system call.
* Print a message and return.
*/
void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, 0, fmt, ap);
	va_end(ap);
}
/*
* Fatal error unrelated to a system call.
* Print a message and terminate.
*/
void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, 0, fmt, ap);
	va_end(ap);
	exit(1);
}
/*
* Print a message and return to caller.
* Caller specifies "errnoflag".
*/
static void err_doit(int errnoflag, int error, const char *fmt, va_list ap)
{
	char buf[MAXLINE];
	vsnprintf(buf, MAXLINE - 1, fmt, ap);
	if (errnoflag)
		snprintf(buf + strlen(buf), MAXLINE - strlen(buf) - 1, ": %s",
			strerror(error));
	strcat(buf, "\n");
	fflush(stdout); /* in case stdout and stderr are the same */
	fputs(buf, stderr);
	fflush(NULL); /* flushes all stdio output streams */
}

void daemonize(const char *cmd)
{
	int i, fd0, fd1, fd2;
	pid_t pid;
	struct rlimit rl;
	struct sigaction sa;
	/*
	* Clear file creation mask.
	*/
	umask(0);
	/*
	* Get maximum number of file descriptors.
	*/
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		err_quit("%s: can’t get file limit", cmd);
	/*
	* Become a session leader to lose controlling TTY.
	*/
	if ((pid = fork()) < 0)
		err_quit("%s: can’t fork", cmd);
	else if (pid != 0) /* parent */
		exit(0);
	setsid();
	/*
	* Ensure future opens won’t allocate controlling TTYs.
	*/
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		err_quit("%s: can’t ignore SIGHUP", cmd);
	if ((pid = fork()) < 0)
		err_quit("%s: can’t fork", cmd);
	else if (pid != 0) /* parent */
		exit(0);
	/*
	* Change the current working directory to the root so
	* we won’t prevent file systems from being unmounted.
	*/
	if (chdir("/") < 0)
		err_quit("%s: can’t change directory to /", cmd);
	/*
	* Close all open file descriptors.
	*/
	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;
	for (i = 0; i < rl.rlim_max; i++)
		close(i);
	/*
	* Attach file descriptors 0, 1, and 2 to /dev/null.
	*/
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);
	/*
	* Initialize the log file.
	*/
	openlog(cmd, LOG_CONS, LOG_DAEMON);
	if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
		syslog(LOG_ERR, "unexpected file descriptors %d %d %d",
			fd0, fd1, fd2);
		exit(1);
	}
}


static void pr_limits(char *name, int resource)
{
	struct rlimit limit;
	unsigned long long lim;
	if (getrlimit(resource, &limit) < 0)
		err_sys("getrlimit error for %s", name);
	printf("%-14s ", name);
	if (limit.rlim_cur == RLIM_INFINITY) {
		printf("(infinite) ");
	}
	else {
		lim = limit.rlim_cur;
		printf("%10lld ", lim);
	}
	if (limit.rlim_max == RLIM_INFINITY) {
		printf("(infinite)");
	}
	else {
		lim = limit.rlim_max;
		printf("%10lld", lim);
	}
	putchar((int) '\n');
}




int set_cloexec(int fd)
{
	int val;
	if ((val = fcntl(fd, F_GETFD, 0)) < 0)
		return(-1);
	val |= FD_CLOEXEC; /* enable close-on-exec */
	return(fcntl(fd, F_SETFD, val));
}

int initserver(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
	int fd;
	int err = 0;
	if ((fd = socket(addr->sa_family, type, 0)) < 0)
		return(-1);
	if (bind(fd, addr, alen) < 0)
		goto errout;
	if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
		if (listen(fd, qlen) < 0)
			goto errout;
	}
	return(fd);

errout:
	err = errno;
	close(fd);
	errno = err;
	return(-1);
}

void print_family(struct addrinfo *aip)
{
	printf(" family ");
	switch (aip->ai_family) {
	case AF_INET:
		printf("inet");
		break;
	case AF_INET6:
		printf("inet6");
		break;
	case AF_UNIX:
		printf("unix");
		break;
	case AF_UNSPEC:
		printf("unspec");
		break;
	default:
		printf("unknown");
	}
}

void print_type(struct addrinfo *aip)
{
	printf(" type ");
	switch (aip->ai_socktype) {
	case SOCK_STREAM:
		printf("stream");
		break;
	case SOCK_DGRAM:
		printf("datagram");
		break;
	case SOCK_SEQPACKET:
		printf("seqpacket");
		break;
	case SOCK_RAW:
		printf("raw");
		break;
	default:
		printf("unknown (%d)", aip->ai_socktype);
	}
}

void print_protocol(struct addrinfo *aip)
{
	printf(" protocol ");
	switch (aip->ai_protocol) {
	case 0:
		printf("default");
		break;
	case IPPROTO_TCP:
		printf("TCP");
		break;
	case IPPROTO_UDP:
		printf("UDP");
		break;
	case IPPROTO_RAW:
		printf("raw");
		break;
	default:
		printf("unknow (%d)", aip->ai_protocol);
	}
}

void print_flags(struct addrinfo *aip)
{
	printf("flags");
	if (aip->ai_flags == 0) {
		printf(" 0");
	}
	else {
		if (aip->ai_flags & AI_PASSIVE)
			printf(" passive");
		if (aip->ai_flags & AI_CANONNAME)
			printf(" canon");
		if (aip->ai_flags & AI_NUMERICHOST)
			printf(" numhost");
		if (aip->ai_flags & AI_NUMERICSERV)
			printf(" numserv");
		if (aip->ai_flags & AI_V4MAPPED)
			printf(" v4mapped");
		if (aip->ai_flags & AI_ALL)
			printf(" all");
	}
}

int connect_retry(int domain, int type, int protocol, const struct sockaddr *addr, socklen_t alen)	//연결을 재시도한다.
{
	int numsec, fd;

	for (numsec = 1; numsec <= MAXSLEEP; numsec <<= 1) {
		if ((fd = socket(domain, type, protocol)) < 0)
			return(-1);
		if (connect(fd, addr, alen) == 0) {
			return(fd);
		}//연결 수락
		close(fd);
		if (numsec <= MAXSLEEP / 2)
			sleep(numsec); //MAXSLEEP / 2의 시간이 지나고 연결을 재시도한다.
	}
	return(-1);
}

void serve(int sockfd)
{
	int clfd, status;
	pid_t pid;
	set_cloexec(sockfd);
	for (;;) {
		if ((clfd = accept(sockfd, NULL, NULL)) < 0) {
			syslog(LOG_ERR, "ruptimed: accept error: %s",
				strerror(errno));
			exit(1);
		}
		if ((pid = fork()) < 0) {
			syslog(LOG_ERR, "ruptimed: fork error: %s",
				strerror(errno));
			exit(1);
		}
		else if (pid == 0) { /* child */
							 /*
							 * The parent called daemonize (Figure 13.1), so
							 * STDIN_FILENO, STDOUT_FILENO, and STDERR_FILENO
							 * are already open to /dev/null. Thus, the call to
							 * close doesn’t need to be protected by checks that
							 * clfd isn’t already equal to one of these values.
							 */
			if (dup2(clfd, STDOUT_FILENO) != STDOUT_FILENO ||
				dup2(clfd, STDERR_FILENO) != STDERR_FILENO) {
				syslog(LOG_ERR, "ruptimed: unexpected error");
				exit(1);
			}
			close(clfd);
			execl("/usr/bin/uptime", "uptime", (char *)0);
			syslog(LOG_ERR, "ruptimed: unexpected return from exec: %s",
				strerror(errno));
		}
		else { /* parent */
			close(clfd);
			waitpid(pid, &status, 0);
		}
	}
}



