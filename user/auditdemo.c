#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// Must match kernel/audit.c struct
struct audit_entry {
  int pid;
  int uid;
  int trapno;
  int tick;
  char desc[32];
};

// ✅ Use smaller buffer to avoid stack overflow
#define MAX_ENTRIES 50

struct audit_entry entries[MAX_ENTRIES];  // global = not on stack

int
main(void)
{
  int n;

  printf("=== Audit Log Demo ===\n\n");

  // ─────────────────────────────────────────
  // 3.4 — Step 1: patient attempts failed access
  // ─────────────────────────────────────────
  printf("Step 1: patient attempts to read /device/config...\n");
  if(login("patient", "patient123") == 0){
    int fd = open("/device/config", O_RDONLY);
    if(fd < 0){
      printf("  [Expected] Access denied to patient\n");
    } else {
      printf("  [Unexpected] Access granted!\n");
      close(fd);
    }
  } else {
    printf("  [Error] Patient login failed\n");
  }

  // ─────────────────────────────────────────
  // 3.4 — Step 2: doctor successful write
  // ─────────────────────────────────────────
  printf("\nStep 2: doctor writes to /dosage/insulin.log...\n");
  if(login("doctor", "doctor123") == 0){
    int fd = open("/dosage/insulin.log", O_WRONLY);
    if(fd >= 0){
      write(fd, "10units\n", 8);
      printf("  [Expected] Doctor write succeeded\n");
      close(fd);
    } else {
      printf("  [Unexpected] Doctor write failed\n");
    }
  } else {
    printf("  [Error] Doctor login failed\n");
  }

  // ─────────────────────────────────────────
  // 3.3 — Step 3: non-admin denied audit_read
  // ─────────────────────────────────────────
  printf("\nStep 3: patient tries to read audit log...\n");
  if(login("patient", "patient123") == 0){
    n = audit_read(entries, MAX_ENTRIES);
    if(n < 0){
      printf("  [PASS] audit_read correctly returned EPERM\n");
    } else {
      printf("  [FAIL] patient read audit log!\n");
    }
  }

  // ─────────────────────────────────────────
  // 3.3 — Step 4: admin reads audit log
  // ─────────────────────────────────────────
  printf("\nStep 4: admin reads audit log...\n");
  if(login("admin", "admin123") == 0){
    n = audit_read(entries, MAX_ENTRIES);
    if(n < 0){
      printf("  [FAIL] audit_read returned error\n");
    } else {
      printf("  [PASS] Admin read %d audit entries\n\n", n);
      printf("  Recent entries:\n");
      for(int i = 0; i < n; i++){
        printf("  [%d] PID=%d UID=%d TRAP=%d TICK=%d DESC=%s\n",
               i,
               entries[i].pid,
               entries[i].uid,
               entries[i].trapno,
               entries[i].tick,
               entries[i].desc);
      }
    }
  }

  printf("\n=== Audit Demo Complete ===\n");
  exit(0);
}
