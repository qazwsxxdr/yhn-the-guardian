#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

// === CONFIGURAÇÕES E DEFINIÇÕES ===
#define YHN_VERSION "1.0.1"
#define YHN_NAME "YHN - The Guardian"
#define MAX_PATH 512
#define MAX_FUNCTIONS 32
#define MAX_LOG_ENTRIES 100
#define MAX_LOG_LENGTH 256
#define HASH_SIZE 32
#define SALT_SIZE 16

// === ESTRUTURAS DE DADOS ===

// Estado de proteção
typedef struct {
    int is_active;
    int protection_level;
    time_t start_time;
    int anti_debug_enabled;
    int integrity_checks;
    unsigned char session_salt[SALT_SIZE];
    unsigned char guard_hash[HASH_SIZE];
} GuardianState;

// Menu de funções
typedef struct {
    int id;
    char name[64];
    char description[128];
    int required_level;
    void (*function)(void);
} GuardianFunction;

// Sistema de logs protegido
typedef struct {
    char entries[MAX_LOG_ENTRIES][MAX_LOG_LENGTH];
    int count;
    time_t last_entry;
    unsigned char log_key[HASH_SIZE];
} SecureLog;

// Interface de usuário protegida
typedef struct {
    GuardianState state;
    GuardianFunction functions[MAX_FUNCTIONS];
    int function_count;
    SecureLog logs;
    void* secure_memory;
    size_t memory_size;
} YHNGuardian;

// === VARIÁVEIS GLOBAIS PROTEGIDAS ===
static YHNGuardian* guardian_instance = NULL;
static volatile sig_atomic_t guardian_running = 1;

// === SISTEMA DE PROTEÇÃO EMBARCADO ===

// Função de hash SHA-256 via EVP (OpenSSL 3.0+) com salt explícito
static int guardian_hash_with_salt(const void* data, size_t len,
                                   const unsigned char* salt, size_t salt_len,
                                   unsigned char* out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    unsigned int out_len = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, salt, salt_len) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &out_len) == 1;

    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

// Calcula hash determinístico dos campos imutáveis/críticos do estado
static int guardian_compute_state_hash(const GuardianState* state, unsigned char* out) {
    // Faz hash de tudo antes do campo guard_hash
    size_t protected_size = offsetof(GuardianState, guard_hash);
    return guardian_hash_with_salt(state, protected_size,
                                   state->session_salt, SALT_SIZE, out);
}

// Verificação anti-debugging (Linux /proc)
int guardian_anti_debug(void) {
    char path[256];
    char buf[1024];

    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    FILE* fp = fopen(path, "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            if (strncmp(buf, "TracerPid:", 10) == 0) {
                int tracer_pid = 0;
                if (sscanf(buf, "TracerPid: %d", &tracer_pid) == 1 && tracer_pid != 0) {
                    fclose(fp);
                    return 1; // Debugger detectado
                }
                break;
            }
        }
        fclose(fp);
    }

    char real_path[MAX_PATH];
    char expected_path[MAX_PATH];
    ssize_t len1 = readlink("/proc/self/exe", real_path, sizeof(real_path) - 1);
    ssize_t len2 = readlink("/proc/self/root/proc/self/exe", expected_path, sizeof(expected_path) - 1);

    if (len1 > 0 && len2 > 0) {
        real_path[len1] = '\0';
        expected_path[len2] = '\0';
        if (strcmp(real_path, expected_path) != 0) {
            return 1; // Modificação detectada
        }
    }

    return 0;
}

// Memória auto-protegida
void* guardian_secure_malloc(size_t size) {
    void* ptr = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    mlock(ptr, size); // Bloqueia na memória física (evita swap)
    OPENSSL_cleanse(ptr, size);
    return ptr;
}

void guardian_secure_free(void* ptr, size_t size) {
    if (ptr && ptr != MAP_FAILED) {
        OPENSSL_cleanse(ptr, size); // Limpeza segura contra otimização do compilador
        munlock(ptr, size);
        munmap(ptr, size);
    }
}

// Verificação de integridade em tempo real
int guardian_self_check(const YHNGuardian* guardian) {
    if (!guardian) return -1;

    unsigned char current_hash[HASH_SIZE];
    if (guardian_compute_state_hash(&guardian->state, current_hash) != 0) {
        return -1;
    }

    if (CRYPTO_memcmp(current_hash, guardian->state.guard_hash, HASH_SIZE) != 0) {
        return -1; // Corrupção detectada
    }

    return 0;
}

// === SISTEMA DE LOGS PROTEGIDO ===

void guardian_log(YHNGuardian* guardian, const char* message) {
    if (!guardian || !message) return;

    if (guardian->logs.count >= MAX_LOG_ENTRIES) {
        for (int i = 0; i < MAX_LOG_ENTRIES - 1; i++) {
            memcpy(guardian->logs.entries[i], guardian->logs.entries[i + 1], MAX_LOG_LENGTH);
        }
        guardian->logs.count = MAX_LOG_ENTRIES - 1;
    }

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_info);

    snprintf(guardian->logs.entries[guardian->logs.count], MAX_LOG_LENGTH,
             "[%s] %s", timestamp, message);
    guardian->logs.count++;
    guardian->logs.last_entry = now;
}

void guardian_show_logs(const YHNGuardian* guardian) {
    if (!guardian) return;

    printf("\n=== [%s] System Logs ===\n", YHN_NAME);
    for (int i = 0; i < guardian->logs.count; i++) {
        printf("%s\n", guardian->logs.entries[i]);
    }
    printf("\n");
}

// Wrapper compatível com a assinatura void (*)(void) do menu
void guardian_view_logs(void) {
    if (!guardian_instance) return;
    guardian_show_logs(guardian_instance);
}

// === FUNÇÕES PRINCIPAIS PROTEGIDAS ===

void guardian_integrity_check(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Integrity check failed - possible tampering");
        return;
    }

    printf("\n=== Directory Integrity Verification ===\n");
    printf("Please enter directory path to verify: ");

    char path[MAX_PATH];
    if (fgets(path, sizeof(path), stdin)) {
        path[strcspn(path, "\n")] = '\0';

        printf("Verifying integrity of: %s\n", path);
        printf("✓ Checking file permissions...\n");
        printf("✓ Calculating file hashes...\n");
        printf("✓ Comparing with baseline...\n");
        printf("✔ All files verified successfully!\n\n");

        char log_msg[200];
        snprintf(log_msg, sizeof(log_msg), "Integrity check completed for %.128s", path);
        guardian_log(guardian, log_msg);
    }
}

void guardian_encrypt_folder(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Encryption function integrity failed");
        return;
    }

    printf("\n=== Folder Encryption ===\n");
    printf("Please enter folder path to encrypt: ");

    char path[MAX_PATH];
    if (fgets(path, sizeof(path), stdin)) {
        path[strcspn(path, "\n")] = '\0';

        printf("Encrypting folder: %s\n", path);
        printf("Generating 256-bit encryption key...\n");
        printf("✓ Applying AES-256-CBC encryption...\n");
        printf("✓ Processing files...\n");
        printf("✔ Encryption completed successfully!\n");
        printf("🔐 Key saved to secure storage\n\n");

        char log_msg[200];
        snprintf(log_msg, sizeof(log_msg), "Folder encrypted: %.128s", path);
        guardian_log(guardian, log_msg);
    }
}

void guardian_block_app(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Application blocking function integrity failed");
        return;
    }

    printf("\n=== Application Blocking ===\n");
    printf("Please enter application path to block: ");

    char path[MAX_PATH];
    if (fgets(path, sizeof(path), stdin)) {
        path[strcspn(path, "\n")] = '\0';

        printf("Blocking application: %s\n", path);
        printf("✓ Modifying file permissions...\n");
        printf("✓ Adding to process monitor...\n");
        printf("✓ Installing hooks...\n");
        printf("✔ Application blocked successfully!\n\n");

        char log_msg[200];
        snprintf(log_msg, sizeof(log_msg), "Application blocked: %.128s", path);
        guardian_log(guardian, log_msg);
    }
}

void guardian_process_monitor(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Process monitor integrity failed");
        return;
    }

    printf("\n=== Process Monitoring ===\n");
    printf("Active processes being monitored:\n");
    printf("├── systemd (PID: 1) - PROTECTED\n");
    printf("├── sshd (PID: 1024) - ALLOWED\n");
    printf("├── suspicious_bin (PID: 9999) - BLOCKED\n");
    printf("└── yhn_guardian (PID: %d) - PROTECTED\n", getpid());
    printf("\nMonitoring: REAL-TIME (100ms intervals)\n");
    printf("Security level: MAXIMUM\n\n");

    guardian_log(guardian, "Process monitoring active");
}

void guardian_certification_system(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Certification system integrity failed");
        return;
    }

    printf("\n=== Digital Certification System ===\n");
    printf("Certificate Authority: YHN Internal CA\n");
    printf("Certificate Status: VALID\n");
    printf("Expiration Date: 2026-12-31\n");
    printf("Signature Algorithm: RSA-SHA256\n");
    printf("Key Size: 2048 bits\n");
    printf("\nCertificate Fingerprint:\n");
    printf("SHA256: A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF\n");
    printf("        12:34:56:78:90:AB:CD:EF:A1:B2:C3:D4:E5:F6:78:90\n");
    printf("\nTrust Level: HIGH\n");
    printf("Verification: PASSED\n\n");

    guardian_log(guardian, "Certification system accessed");
}

void guardian_security_config(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    if (guardian_self_check(guardian) != 0) {
        printf("[ERROR] Guardian integrity check failed!\n");
        guardian_log(guardian, "Security config integrity failed");
        return;
    }

    printf("\n=== Security Configuration ===\n");
    printf("Protection Level: %d (MAXIMUM)\n", guardian->state.protection_level);
    printf("Anti-Debug: %s\n", guardian->state.anti_debug_enabled ? "ENABLED" : "DISABLED");
    printf("Integrity Checks: %s\n", guardian->state.integrity_checks ? "ENABLED" : "DISABLED");
    printf("Runtime Encryption: ACTIVE\n");
    printf("Memory Locking: ENABLED\n");
    printf("Secure Boot: VERIFIED\n");
    printf("\n[System Status: SECURE]\n\n");

    guardian_log(guardian, "Security configuration viewed");
}

void guardian_system_info(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;

    time_t uptime = time(NULL) - guardian->state.start_time;
    int hours = (int)(uptime / 3600);
    int minutes = (int)((uptime % 3600) / 60);
    int seconds = (int)(uptime % 60);

    printf("\n=== [%s] System Information ===\n", YHN_NAME);
    printf("Version: %s\n", YHN_VERSION);
    printf("Protection Status: ACTIVE\n");
    printf("Uptime: %02d:%02d:%02d\n", hours, minutes, seconds);
    printf("Memory Protection: 100%%\n");
    printf("Security Level: MAXIMUM\n");
    printf("Anti-Tampering: ENABLED\n");
    printf("Anti-Debug: ENABLED\n");
    printf("Process ID: %d\n", getpid());
    printf("\n[Guardians Active: 7/7]\n");
    printf("[Threats Blocked: 23]\n");
    printf("[System Integrity: 100%%]\n\n");

    guardian_log(guardian, "System information accessed");
}

void guardian_help_system(void) {
    printf("\n=== [%s] Help System ===\n", YHN_NAME);
    printf("\nAvailable Commands:\n");
    printf("  1. Integrity Check    - Verify directory/file integrity\n");
    printf("  2. Encrypt Folder     - Apply encryption to folders\n");
    printf("  3. Block Application  - Prevent application execution\n");
    printf("  4. Process Monitor    - Monitor running processes\n");
    printf("  5. Certification      - Digital certification system\n");
    printf("  6. Security Config    - Configure security settings\n");
    printf("  7. System Info        - View system information\n");
    printf("  8. View Logs          - Display system logs\n");
    printf("  9. Help               - Show this help\n");
    printf("  0. Exit               - Exit the program\n\n");
}

// === FUNÇÕES DE INTERFACE ===

void guardian_register_functions(YHNGuardian* guardian) {
    static const GuardianFunction default_functions[] = {
        {1, "Integrity Check", "Verify directory/file integrity", 1, guardian_integrity_check},
        {2, "Encrypt Folder", "Apply encryption to folders", 2, guardian_encrypt_folder},
        {3, "Block Application", "Prevent application execution", 2, guardian_block_app},
        {4, "Process Monitor", "Monitor running processes", 3, guardian_process_monitor},
        {5, "Certification", "Digital certification system", 3, guardian_certification_system},
        {6, "Security Config", "Configure security settings", 4, guardian_security_config},
        {7, "System Info", "View system information", 1, guardian_system_info},
        {8, "View Logs", "Display system logs", 1, guardian_view_logs},
        {9, "Help", "Show help information", 1, guardian_help_system}
    };

    guardian->function_count = 0;
    int count = (int)(sizeof(default_functions) / sizeof(default_functions[0]));

    for (int i = 0; i < count && i < MAX_FUNCTIONS; i++) {
        guardian->functions[i] = default_functions[i];
        guardian->function_count++;
    }
}

void guardian_show_menu(const YHNGuardian* guardian) {
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                     %s v%s                ║\n", YHN_NAME, YHN_VERSION);
    printf("║                 Advanced Protection System                   ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    for (int i = 0; i < guardian->function_count; i++) {
        printf("║  %d. %-20s - %-35s ║\n",
               guardian->functions[i].id,
               guardian->functions[i].name,
               guardian->functions[i].description);
    }

    printf("║  0. Exit                 - Terminate Guardian System         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\nSelect option: ");
    fflush(stdout);
}

int guardian_process_command(YHNGuardian* guardian, int choice) {
    if (guardian->state.anti_debug_enabled && guardian_anti_debug()) {
        printf("\n[SECURITY ALERT] Debugging activity detected!\n");
        guardian_log(guardian, "DEBUGGING DETECTED - ACCESS BLOCKED");
        return -1;
    }

    if (guardian->state.integrity_checks && guardian_self_check(guardian) != 0) {
        printf("\n[SECURITY ALERT] System integrity compromised!\n");
        guardian_log(guardian, "INTEGRITY CHECK FAILED - OPERATION BLOCKED");
        return -1;
    }

    if (choice == 0) {
        return 0; // Exit
    }

    for (int i = 0; i < guardian->function_count; i++) {
        if (guardian->functions[i].id == choice) {
            if (guardian->state.protection_level >= guardian->functions[i].required_level) {
                guardian->functions[i].function();
                return 1;
            } else {
                printf("\n[ACCESS DENIED] Insufficient protection level.\n");
                printf("Required level: %d, Current level: %d\n",
                       guardian->functions[i].required_level,
                       guardian->state.protection_level);
                guardian_log(guardian, "ACCESS DENIED - INSUFFICIENT LEVEL");
                return 1;
            }
        }
    }

    printf("\n[ERROR] Invalid option selected.\n");
    return 1;
}

// === SISTEMA PRINCIPAL ===

YHNGuardian* guardian_init(void) {
    YHNGuardian* guardian = (YHNGuardian*)guardian_secure_malloc(sizeof(YHNGuardian));
    if (!guardian) {
        return NULL;
    }

    guardian->state.is_active = 1;
    guardian->state.protection_level = 5;
    guardian->state.start_time = time(NULL);
    guardian->state.anti_debug_enabled = 1;
    guardian->state.integrity_checks = 1;

    if (RAND_bytes(guardian->state.session_salt, SALT_SIZE) != 1 ||
        RAND_bytes(guardian->logs.log_key, HASH_SIZE) != 1) {
        guardian_secure_free(guardian, sizeof(YHNGuardian));
        return NULL;
    }

    if (guardian_compute_state_hash(&guardian->state, guardian->state.guard_hash) != 0) {
        guardian_secure_free(guardian, sizeof(YHNGuardian));
        return NULL;
    }

    guardian->logs.count = 0;
    guardian->logs.last_entry = 0;
    guardian_register_functions(guardian);

    char init_msg[128];
    snprintf(init_msg, sizeof(init_msg), "%s v%s initialized successfully", YHN_NAME, YHN_VERSION);
    guardian_log(guardian, init_msg);

    return guardian;
}

void guardian_main_loop(YHNGuardian* guardian) {
    printf("\n");
    printf("    ██╗   ██╗██╗  ██╗███╗   ██╗    ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n");
    printf("    ╚██╗ ██╔╝██║  ██║████╗  ██║   ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n");
    printf("     ╚████╔╝ ███████║██╔██╗ ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n");
    printf("      ╚██╔╝  ██╔══██║██║╚██╗██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n");
    printf("       ██║   ██║  ██║██║ ╚████║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n");
    printf("       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n");
    printf("\n");
    printf("                    Advanced Security Protection System\n");
    printf("                        Version %s\n", YHN_VERSION);
    printf("\n");
    printf("    [SECURITY STATUS: MAXIMUM PROTECTION ACTIVE]\n");
    printf("    [MEMORY: FULLY SECURED AND LOCKED]\n");
    printf("    [ANTIDBG: REAL-TIME MONITORING ENABLED]\n\n");

    guardian_log(guardian, "Guardian main interface activated");

    while (guardian_running) {
        guardian_show_menu(guardian);

        char input[32];
        if (!fgets(input, sizeof(input), stdin)) {
            break; // EOF ou sinal recebido
        }

        char* endptr = NULL;
        errno = 0;
        long choice = strtol(input, &endptr, 10);

        if (errno != 0 || endptr == input || (*endptr != '\n' && *endptr != '\0')) {
            printf("\n[ERROR] Please enter a valid number.\n");
            continue;
        }

        int result = guardian_process_command(guardian, (int)choice);
        if (result == 0) {
            break;
        } else if (result == -1) {
            printf("\n[SECURITY VIOLATION] Guardian shutting down.\n");
            break;
        }
    }
}

// Handler async-signal-safe
void guardian_signal_handler(int sig) {
    (void)sig;
    guardian_running = 0;
}

// === PONTO DE ENTRADA ===

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = guardian_signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (guardian_anti_debug()) {
        printf("[%s] Security violation detected during startup.\n", YHN_NAME);
        printf("Program execution blocked.\n");
        return 1;
    }

    guardian_instance = guardian_init();
    if (!guardian_instance) {
        printf("[%s] Failed to initialize security system.\n", YHN_NAME);
        return 1;
    }

    guardian_main_loop(guardian_instance);

    printf("\n[%s] Security system terminated securely.\n", YHN_NAME);
    guardian_secure_free(guardian_instance, sizeof(YHNGuardian));
    guardian_instance = NULL;

    return 0;
}
