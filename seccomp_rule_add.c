/*
  作業時コメント：
  どうやらシステムコールの1引数に2つ以上の条件は作れない模様。
  openの第一引数は&etext以下&edata以上と指定したかったのだが、
  どうもうまく動かなかった。
  BPF的には指定できそうな気がするので、libseccompの制約だろうか？
*/

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <unistd.h>
#include <seccomp.h>

extern void *edata, *etext;

void string_literal_func(void) {
	asm volatile (
				  "add $0x0,%al\t\n"
				  "add $0x0,%al\t\n"
				  "add $0x0,%al\t\n"
				  "add $0x0,%al\t\n"
				  "add %al,(%eax)\t\n"
				  "nop\t\n"
				  "nop\t\n"
				  "nop\t\n"
				  "nop\t\n"
				  );
	return;
}

int main(int argc, char *argv[])
{
	int rc = -1;
	scmp_filter_ctx ctx;
	FILE *fp;
	char buf[1024];
	strcpy(buf, "/tmp/seccomp_rule_add.txt");
	
	ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	if (ctx == NULL)
		goto seccomp_failure;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
						  SCMP_A1(SCMP_CMP_MASKED_EQ, (scmp_datum_t)O_WRONLY, (scmp_datum_t)O_WRONLY)
						  );
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EDOM), SCMP_SYS(open), 1,
						  SCMP_A0(SCMP_CMP_GE, (scmp_datum_t)&edata)
						  );
	if (rc < 0)
		goto seccomp_failure;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ERANGE), SCMP_SYS(open), 1,
						  SCMP_A0(SCMP_CMP_LE, (scmp_datum_t)&etext)
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

	fp = fopen(buf, "w");
	if (fp == NULL) {
		fprintf(stderr, "fopen() failure (expected behavior)\n");
		// do nothing
	} else {
		fclose(fp);
	}
	fprintf(stderr, "string_literal_func=%p\n", string_literal_func);
	fprintf(stderr, "edata=%p, etext=%p\n", &edata, &etext);
	
	fp = fopen((char *)string_literal_func, "w");
	if (fp == NULL) {
		fprintf(stderr, "fopen() failure (expected behavior)\n");
		// do nothing
	} else {
		fclose(fp);
	}
	
	fp = fopen("/tmp/seccomp_rule_add.txt", "w");
	if (fp == NULL) {
		rc = -errno;
		goto seccomp_failure;
	}
	rc = fputs("foobar\n", fp);
	if (rc < 0)
		goto seccomp_failure;
	rc = fclose(fp);
	if (rc < 0)
		goto seccomp_failure;

 seccomp_failure:	 
	seccomp_release(ctx);
	return -rc;
}
