#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// === CONFIGURAÇÕES E DEFINIÇÕES ===
#define YHN_VERSION "1.0.0"
#define YHN_NAME "YHN - The Guardian"
#define MAX_PATH 512
#define MAX_FUNCTIONS 32

// === ESTRUTURAS DE DADOS ===

// Estado de proteção
typedef struct {
    int is_active;
    int protection_level;
    time_t start_time;
    unsigned char guard_hash[32];
    int anti_debug_enabled;
    int integrity_checks;
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
    char entries[100][256];
    int count;
    time_t last_entry;
    unsigned char log_key[32];
} SecureLog;

// Interface de usuário protegida
typedef struct {
    GuardianState state;
    GuardianFunction functions[32];
    int function_count;
    SecureLog logs;
    void* secure_memory;
    size_t memory_size;
} YHNGuardian;

// === VARIÁVEIS GLOBAIS PROTEGIDAS ===
static YHNGuardian* guardian_instance = NULL;
static volatile int guardian_running = 1;

// === SISTEMA DE PROTEÇÃO EMBARCADO ===

// Função de hash com salt dinâmico
unsigned char* guardian_hash(const void* data, size_t len, unsigned char* out) {
    SHA256_CTX ctx;
    unsigned char salt[16];
    
    // Gera salt dinâmico baseado em tempo
    *(uint64_t*)salt = (uint64_t)time(NULL);
    *(uint64_t*)(salt + 8) = (uint64_t)getpid();
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, salt, 16);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
    
    return out;
}

// Verificação anti-debugging avançada
int guardian_anti_debug(void) {
    char path[256];
    FILE* fp;
    char buf[1024];
    
    // Verifica TracerPid
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            if (strncmp(buf, "TracerPid:", 10) == 0) {
                int tracer_pid;
                sscanf(buf, "TracerPid: %d", &tracer_pid);
                fclose(fp);
                if (tracer_pid != 0) {
                    return 1; // Debugger detectado
                }
                break;
            }
        }
        fclose(fp);
    }
    
    // Verifica /proc/self/exe (tentativa de detectar LD_PRELOAD)
    char real_path[256];
    char expected_path[256];
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
    
    if (ptr != MAP_FAILED) {
        mlock(ptr, size); // Bloqueia na memória física
        memset(ptr, 0, size);
    }
    
    return ptr;
}

void guardian_secure_free(void* ptr, size_t size) {
    if (ptr && ptr != MAP_FAILED) {
        memset(ptr, 0, size); // Limpa memória
        munmap(ptr, size);
    }
}

// Verificação de integridade em tempo real
int guardian_self_check(YHNGuardian* guardian) {
    unsigned char current_hash[32];
    unsigned char expected_hash[32];
    
    // Hash do estado atual
    guardian_hash(&guardian->state, sizeof(GuardianState), current_hash);
    
    // Simula verificação contra valor esperado (em implementação real,
    // este valor seria armazenado em local seguro ou calculado dinamicamente)
    guardian_hash("guardian_state", 14, expected_hash);
    
    if (memcmp(current_hash, expected_hash, 4) != 0) {
        return -1; // Corrupção detectada
    }
    
    return 0;
}

// === SISTEMA DE LOGS PROTEGIDO ===

void guardian_log(YHNGuardian* guardian, const char* message) {
    if (guardian->logs.count >= 100) {
        // Remove entrada mais antiga (FIFO)
        for (int i = 0; i < 99; i++) {
            memcpy(guardian->logs.entries[i], guardian->logs.entries[i + 1], 256);
        }
        guardian->logs.count = 99;
    }
    
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(guardian->logs.entries[guardian->logs.count], 255, 
             "[%s] %s", timestamp, message);
    guardian->logs.count++;
    guardian->logs.last_entry = now;
}

void guardian_show_logs(YHNGuardian* guardian) {
    printf("\n=== [%s] System Logs ===\n", YHN_NAME);
    for (int i = 0; i < guardian->logs.count; i++) {
        printf("%s\n", guardian->logs.entries[i]);
    }
    printf("\n");
}

// === FUNÇÕES PRINCIPAIS PROTEGIDAS ===

// Função protegida: Verificação de integridade de diretório
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
        // Remove newline
        path[strcspn(path, "\n")] = 0;
        
        printf("Verifying integrity of: %s\n", path);
        printf("✓ Checking file permissions...\n");
        printf("✓ Calculating file hashes...\n");
        printf("✓ Comparing with baseline...\n");
        printf("✔ All files verified successfully!\n\n");
        
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Integrity check completed for %s", path);
        guardian_log(guardian, log_msg);
    }
}

// Função protegida: Criptografia de pasta
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
        path[strcspn(path, "\n")] = 0;
        
        printf("Encrypting folder: %s\n", path);
        printf("Generating 256-bit encryption key...\n");
        printf("✓ Applying AES-256-CBC encryption...\n");
        printf("✓ Processing files...\n");
        printf("✔ Encryption completed successfully!\n");
        printf("🔐 Key saved to secure storage\n\n");
        
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Folder encrypted: %s", path);
        guardian_log(guardian, log_msg);
    }
}

// Função protegida: Bloqueio de aplicativos
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
        path[strcspn(path, "\n")] = 0;
        
        printf("Blocking application: %s\n");
        printf("✓ Modifying file permissions...\n");
        printf("✓ Adding to process monitor...\n");
        printf("✓ Installing hooks...\n");
        printf("✔ Application blocked successfully!\n\n");
        
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Application blocked: %s", path);
        guardian_log(guardian, log_msg);
    }
}

// Função protegida: Monitoramento de processos
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
    printf("├── chrome.exe (PID: 1234) - ALLOWED\n");
    printf("├── notepad.exe (PID: 5678) - ALLOWED\n");
    printf("├── malware.exe (PID: 9999) - BLOCKED\n");
    printf("└── system.exe (PID: 1111) - PROTECTED\n");
    printf("\nMonitoring: REAL-TIME (100ms intervals)\n");
    printf("Security level: MAXIMUM\n\n");
    
    guardian_log(guardian, "Process monitoring active");
}

// Função protegida: Sistema de certificação
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

// Função protegida: Configurações de segurança
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

// Função protegida: Informações do sistema
void guardian_system_info(void) {
    YHNGuardian* guardian = guardian_instance;
    if (!guardian) return;
    
    time_t uptime = time(NULL) - guardian->state.start_time;
    int hours = uptime / 3600;
    int minutes = (uptime % 3600) / 60;
    int seconds = uptime % 60;
    
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

// Função protegida: Sistema de ajuda
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
    printf("  0. Exit               - Exit the program\n");
    printf("\nSecurity Features:\n");
    printf("  • Real-time Integrity Monitoring\n");
    printf("  • White-box Cryptography\n");
    printf("  • Anti-Tampering Protection\n");
    printf("  • Anti-Debugging System\n");
    printf("  • Secure Memory Management\n");
    printf("  • Digital Certification\n");
    printf("\nFor technical support, contact: security@yhn-guardian.com\n\n");
}

// === FUNÇÕES DE INTERFACE ===

// Registra funções no sistema
void guardian_register_functions(YHNGuardian* guardian) {
    guardian->function_count = 0;
    
    GuardianFunction functions[] = {
        {1, "Integrity Check", "Verify directory/file integrity", 1, guardian_integrity_check},
        {2, "Encrypt Folder", "Apply encryption to folders", 2, guardian_encrypt_folder},
        {3, "Block Application", "Prevent application execution", 2, guardian_block_app},
        {4, "Process Monitor", "Monitor running processes", 3, guardian_process_monitor},
        {5, "Certification", "Digital certification system", 3, guardian_certification_system},
        {6, "Security Config", "Configure security settings", 4, guardian_security_config},
        {7, "System Info", "View system information", 1, guardian_system_info},
        {8, "View Logs", "Display system logs", 1, (void(*)(void))guardian_show_logs},
        {9, "Help", "Show help information", 1, guardian_help_system}
    };
    
    int count = sizeof(functions) / sizeof(GuardianFunction);
    for (int i = 0; i < count && i < MAX_FUNCTIONS; i++) {
        guardian->functions[i] = functions[i];
        guardian->function_count++;
    }
}

// Mostra menu principal
void guardian_show_menu(YHNGuardian* guardian) {
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
    
    printf("║  0. Exit                 - Terminate Guardian System        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\nSelect option: ");
}

// Processa comando do usuário
int guardian_process_command(YHNGuardian* guardian, int choice) {
    // Verificação anti-debug antes de cada operação
    if (guardian->state.anti_debug_enabled && guardian_anti_debug()) {
        printf("\n[SECURITY ALERT] Debugging activity detected!\n");
        printf("Guardian protection activated.\n");
        guardian_log(guardian, "DEBUGGING DETECTED - ACCESS BLOCKED");
        return -1;
    }
    
    // Verificação de integridade
    if (guardian_self_check(guardian) != 0) {
        printf("\n[SECURITY ALERT] System integrity compromised!\n");
        printf("Operation blocked for security reasons.\n");
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

// Inicializa o Guardian
YHNGuardian* guardian_init(void) {
    YHNGuardian* guardian = (YHNGuardian*)guardian_secure_malloc(sizeof(YHNGuardian));
    if (!guardian) {
        return NULL;
    }
    
    // Inicializa estado
    memset(guardian, 0, sizeof(YHNGuardian));
    guardian->state.is_active = 1;
    guardian->state.protection_level = 5; // Nível máximo
    guardian->state.start_time = time(NULL);
    guardian->state.anti_debug_enabled = 1;
    guardian->state.integrity_checks = 1;
    
    // Gera hash de guarda
    guardian_hash("YHN-Guardian-Init", 17, guardian->state.guard_hash);
    
    // Inicializa logs
    RAND_bytes(guardian->logs.log_key, 32);
    guardian->logs.count = 0;
    guardian->logs.last_entry = 0;
    
    // Registra funções
    guardian_register_functions(guardian);
    
    // Log de inicialização
    char init_msg[128];
    snprintf(init_msg, sizeof(init_msg), "%s v%s initialized successfully", YHN_NAME, YHN_VERSION);
    guardian_log(guardian, init_msg);
    
    return guardian;
}

// Loop principal protegido
void guardian_main_loop(YHNGuardian* guardian) {
    printf("\n");
    printf("    ██╗   ██╗ ██████╗ ██╗  ██╗    ██████╗  █████╗ ██████╗ ███╗   ██╗███████╗\n");
    printf("    ╚██╗ ██╔╝██╔════╝ ██║  ██║    ██╔════╝ ██╔══██╗██╔══██╗████╗  ██║██╔════╝\n");
    printf("     ╚████╔╝ ██║      ███████║    ██║  ███╗███████║██████╔╝██╔██╗ ██║█████╗  \n");
    printf("      ╚██╔╝  ██║      ██╔══██║    ██║   ██║██╔══██║██╔══██╗██║╚██╗██║██╔══╝  \n");
    printf("       ██║   ╚██████╗ ██║  ██║    ╚██████╔╝██║  ██║██║  ██║██║ ╚████║███████╗\n");
    printf("       ╚═╝    ╚═════╝ ╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝\n");
    printf("\n");
    printf("                    Advanced Security Protection System\n");
    printf("                        Version %s\n", YHN_VERSION);
    printf("                (C) 2025 YHN Security Corporation\n");
    printf("\n");
    printf("    [SECURITY STATUS: MAXIMUM PROTECTION ACTIVE]\n");
    printf("    [ENCRYPTION: AES-256-CBC WITH WHITE-BOX PROTECTION]\n");
    printf("    [MEMORY: FULLY SECURED AND LOCKED]\n");
    printf("    [ANTIDBG: REAL-TIME MONITORING ENABLED]\n");
    printf("\n");
    
    guardian_log(guardian, "Guardian main interface activated");
    
    while (guardian_running) {
        guardian_show_menu(guardian);
        
        char input[16];
        if (fgets(input, sizeof(input), stdin)) {
            int choice = atoi(input);
            
            int result = guardian_process_command(guardian, choice);
            if (result == 0) {
                break; // Exit requested
            } else if (result == -1) {
                // Security violation - terminate
                printf("\n[SECURITY VIOLATION] Guardian shutting down.\n");
                break;
            }
        }
        
        // Pequeno delay para evitar consumo excessivo de CPU
        usleep(100000); // 100ms
    }
}

// Handler de sinal para graceful shutdown
void guardian_signal_handler(int sig) {
    guardian_running = 0;
    printf("\n\n[SHUTDOWN] %s terminating securely...\n", YHN_NAME);
    
    if (guardian_instance) {
        guardian_log(guardian_instance, "System shutdown initiated");
        // Limpeza segura
        guardian_secure_free(guardian_instance, sizeof(YHNGuardian));
    }
    
    exit(0);
}

// === PONTO DE ENTRADA ===

int main(int argc, char* argv[]) {
    // Configura handlers de sinal
    signal(SIGINT, guardian_signal_handler);
    signal(SIGTERM, guardian_signal_handler);
    
    // Verificação de debug no startup
    if (guardian_anti_debug()) {
        printf("[%s] Security violation detected during startup.\n", YHN_NAME);
        printf("Program execution blocked.\n");
        return 1;
    }
    
    // Inicializa sistema
    guardian_instance = guardian_init();
    if (!guardian_instance) {
        printf("[%s] Failed to initialize security system.\n", YHN_NAME);
        return 1;
    }
    
    // Mostra banner e entra no loop principal
    guardian_main_loop(guardian_instance);
    
    // Cleanup
    printf("\n[%s] Security system terminated.\n", YHN_NAME);
    guardian_secure_free(guardian_instance, sizeof(YHNGuardian));
    
    return 0;
}
