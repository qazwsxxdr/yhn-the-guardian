╔═ + YHN - The Guardian v1.0.0 -- Advanced Protection System                        
║  1. Integrity Check - Verify directory/file integrity
║  2. Encrypt Folder - Apply encryption to folders 
║  3. Block Application - Prevent application execution 
║  4. Process Monitor - Monitor running processes 
║  5. Certification - Digital certification system 
║  6. Security Config - Configure security settings 
║  7. System Info - View system information 
║  8. View Logs - Display system logs 
║  9. Help - Show help information 
║  0. Exit - Terminate Guardian System 

FUNCIONALIDADES PRINCIPAIS
1. INTEGRITY CHECK
Verifica a integridade de diretórios e arquivos usando hash SHA-256 com salt dinâmico.

2. ENCRYPT FOLDER
Aplica criptografia AES-256-CBC a pastas inteiras com chaves geradas dinamicamente.

3. BLOCK APPLICATION
Bloqueia a execução de aplicações modificando permissões e instalando hooks de monitoramento.

4. PROCESS MONITOR
Monitora processos em tempo real com detecção de atividades maliciosas.

5. CERTIFICATION
Sistema de certificação digital com verificação de integridade hierárquica.

6. SECURITY CONFIG
Configura níveis de proteção e recursos de segurança.

7. SYSTEM INFO
Informações detalhadas do estado de proteção do sistema.

8. VIEW LOGS
Visualiza logs protegidos de todas as atividades de segurança.

CARACTERÍSTICAS DE PROTEÇÃO
Auto-Proteção em Runtime:
Memória bloqueada com mlock() para evitar swapping
Verificação anti-debugging em tempo real
Hashes de integridade contínua
Criptografia white-box para operações sensíveis
Segurança Monolítica:
Todas as funções em um único binário
Proteção contra dumping de memória
Verificação de integridade hierárquica
Auto-verificação periódica
Níveis de Proteção:
Nível 1: Básico (Integrity Check, System Info, Help)
Nível 2: Intermediário (Encrypt Folder, Block Application)
Nível 3: Avançado (Process Monitor, Certification)
Nível 4: Administrador (Security Config)
Nível 5: Máximo (Todas as funções disponíveis)
RECURSOS DE SEGURANÇA AVANÇADOS
White-box Cryptography: Implementação simplificada de AES com tabelas embaralhadas
Anti-Tampering: Verificação contínua de integridade de memória
Anti-Debugging: Detecção de debuggers e ferramentas de análise
Secure Memory: Alocação de memória protegida com mmap() e mlock()
Digital Certification: Sistema de certificação integrado
Real-time Monitoring: Monitoramento contínuo de ameaças
USO EM AMBIENTES DE PENTEST
Para uso em atividades de pentest autorizadas:

Sempre execute com permissões adequadas
O sistema detectará e bloqueará atividades de reversão não autorizadas
Os logs podem ser usados para auditoria de segurança
A proteção em runtime impede modificações durante testes

build:
gcc -o yhn yhn.c -lssl -lcrypto
./yhn
