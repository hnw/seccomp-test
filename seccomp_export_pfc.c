#include <stdio.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <unistd.h>
#include <seccomp.h>

int main(int argc, char *argv[])
{
	int rc = -1;
	scmp_filter_ctx ctx;
	int filter_fd;

	ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	if (ctx == NULL)
		goto seccomp_failure;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 2,
						  SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)0),
						  SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t)SEEK_END)
						  );
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	if (rc < 0)
		goto seccomp_failure;

	rc = seccomp_load(ctx);
	if (rc < 0)
		goto seccomp_failure;

	filter_fd = open("/tmp/seccomp_filter.pfc", O_WRONLY);
	if (filter_fd == -1) {
		rc = -errno;
		goto seccomp_failure;
	}
	rc = seccomp_export_pfc(ctx, filter_fd);
	if (rc < 0) {
		close(filter_fd);
		goto seccomp_failure;
	}
	close(filter_fd);
 seccomp_failure:	 
	seccomp_release(ctx);
	return -rc;
}

