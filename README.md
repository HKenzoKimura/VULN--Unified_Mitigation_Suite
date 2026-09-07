# 🛡️ Windows Security Hardening Script — Unified Mitigation Suite

> **Type:** Defensive Security — Windows Registry Hardening
> **Target:** Windows Server / Workstation
> **Execution:** PowerShell (Administrator)
> **Mitigations:** 8 controles de segurança aplicados via registry
>
> Script de hardening que aplica múltiplas mitigações de segurança de forma automatizada — cobrindo vetores de ataque que vão de null sessions e cifragem fraca a exploits de hardware como Spectre/Meltdown. Baseado em recomendações do **CIS Benchmark**, **Microsoft Security Baseline** e **DISA STIG**.


## `Developed by: HKK`

---

## `$ cat ./objective.txt`

Automatizar a aplicação de **8 controles de hardening** no Windows que:

- Fecham vetores de ataque frequentemente explorados em pentests e ataques reais
- Não requerem reinstalação do sistema ou licenças adicionais
- São aplicados via registry — reversíveis e auditáveis
- Cobrem desde ataques de rede (SMB relay, null sessions) até hardware (Spectre/Meltdown)

---

## `$ cat ./mitigations_overview.txt`

```
┌──────────────────────────────────────────────────────────────────────────┐
│              UNIFIED HARDENING SCRIPT — 8 MITIGATIONS                   │
├───┬──────────────────────────────┬──────────┬───────────────────────────┤
│ # │ Mitigação                    │ Risco    │ Referência                │
├───┼──────────────────────────────┼──────────┼───────────────────────────┤
│ 1 │ Null Sessions                │ ALTO     │ CIS Control 4.3           │
│ 2 │ DES/3DES (SWEET32)           │ ALTO     │ CVE-2016-2183             │
│ 3 │ Spectre/Meltdown/SSB         │ CRÍTICO  │ CVE-2017-5753/5754        │
│ 4 │ SMB Signing                  │ CRÍTICO  │ CIS Control 9.1           │
│ 5 │ Cached Logon                 │ ALTO     │ CIS Control 16.11         │
│ 6 │ Guest Account                │ MÉDIO    │ CIS Control 4.7           │
│ 7 │ Authenticode Padding         │ ALTO     │ CVE-2013-3900 (MS13-098)  │
│ 8 │ AutoRun/AutoPlay             │ ALTO     │ CIS Control 8.5           │
└───┴──────────────────────────────┴──────────┴───────────────────────────┘
```

---

## `$ cat ./mitigations_detail.md`

---

### ① Null Sessions — Acesso Anônimo ao SMB

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LSA" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1
```

**O que são Null Sessions?**

Uma Null Session é uma conexão SMB sem credenciais — usuário e senha são strings vazias. Por padrão em configurações legadas, o Windows permite que usuários anônimos consultem informações do sistema via `IPC$` (Inter-Process Communication share).

**O que um atacante pode fazer com Null Sessions:**

```
net use \\target\IPC$ "" /u:""  ← conecta anonimamente

Depois:
  → Enumerar usuários locais (net user, rpcclient -U "" -N)
  → Listar compartilhamentos (net view)
  → Consultar políticas de senha
  → Enumerar grupos e membros do domínio
  → Base para ataques de password spray
```

**O que as chaves fazem:**

| Chave | Valor | Efeito |
|-------|-------|--------|
| `RestrictAnonymous = 1` | LSA | Bloqueia enumeração de SAM e compartilhamentos por usuários anônimos |
| `RestrictNullSessAccess = 1` | LanmanServer | Bloqueia conexões anônimas ao `IPC$` |

**MITRE:** T1135 (Network Share Discovery) · T1087 (Account Discovery)

---

### ② DES/3DES — Cifragem Fraca (SWEET32)

```powershell
New-Item -Path "HKLM:\...\SCHANNEL\Ciphers\Triple DES 168" -Force
Set-ItemProperty -Path "HKLM:\...\Ciphers\Triple DES 168" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKLM:\...\SSL\00010002" -Name "Functions" -Value ""
```

**Por que DES/3DES é inseguro?**

O ataque **SWEET32** (CVE-2016-2183) explora o limite de colisões em cifragens com bloco de 64 bits. O 3DES usa blocos de 64 bits — após ~32GB de tráfego na mesma sessão, colisões de bloco permitem recuperar dados do tráfego cifrado.

```
3DES: bloco de 64 bits → birthday bound ≈ 2^32 blocos ≈ 32GB
AES:  bloco de 128 bits → birthday bound ≈ 2^64 blocos ≈ impraticável
```

**O que as chaves fazem:**

- `Enabled = 0` na chave `Triple DES 168` desabilita o cipher suite no SChannel (TLS/SSL Windows)
- `Functions = ""` no `SSL\00010002` remove todas as cipher suites da lista de preferência da política

**Impacto:** conexões TLS negociarão AES-128/256 em vez de 3DES. Clientes legados que suportam **apenas** 3DES não conseguirão conectar — avaliar impacto antes de aplicar em produção.

**CVE:** CVE-2016-2183 (SWEET32) · CVE-2016-6329

---

### ③ Spectre / Meltdown / Speculative Store Bypass

```powershell
Set-ItemProperty -Path "HKLM:\...\Memory Management" -Name "FeatureSettingsOverride" -Value 72
Set-ItemProperty -Path "HKLM:\...\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3
```

**O que são essas vulnerabilidades de hardware?**

Spectre, Meltdown e SSB (Speculative Store Bypass) são vulnerabilidades em processadores Intel, AMD e ARM que exploram a **execução especulativa** — otimização de CPU que executa instruções antecipadamente para ganhar performance.

| CVE | Nome | Técnica |
|-----|------|---------|
| CVE-2017-5753 | Spectre Variant 1 | Bounds check bypass |
| CVE-2017-5754 | Meltdown | Rogue data cache load |
| CVE-2018-3639 | SSB (Variant 4) | Speculative Store Bypass |

**Anatomia do valor `FeatureSettingsOverride = 72`:**

```
72 decimal = 0x48 = 0100 1000 binário

Bit 3  (valor 8)  → Habilita KVAS (Kernel Virtual Address Shadow / Meltdown)
Bit 6  (valor 64) → Habilita mitigação SSB (Speculative Store Bypass)

Bits não definidos → Spectre Variant 1/2 mitigado pelo microcode/firmware
```

**`FeatureSettingsOverrideMask = 3`** define quais bits do Override são efetivamente aplicados (máscara de 2 bits — habilita override dos bits 0 e 1 que controlam quais mitigações o OS aplica).

**Impacto em performance:** mitigações de hardware têm custo de performance mensurável — 5-30% dependendo do workload. Workloads com muitas syscalls (banco de dados, I/O intensivo) são mais afetados.

**CVE:** CVE-2017-5753 · CVE-2017-5754 · CVE-2018-3639

---

### ④ SMB Signing — Assinatura de Pacotes SMB

```powershell
# Cliente (Workstation)
Set-ItemProperty -Path "HKLM:\...\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\...\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature"  -Value 1

# Servidor (Server)
Set-ItemProperty -Path "HKLM:\...\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\...\LanmanServer\Parameters" -Name "EnableSecuritySignature"  -Value 1
```

**Por que SMB Signing é crítico?**

Sem assinatura SMB, um atacante posicionado no meio do tráfego de rede (MITM) pode realizar **NTLM Relay** — capturar uma autenticação NTLM e retransmiti-la para outro serviço, se autenticando como a vítima sem conhecer a senha.

```
Fluxo de ataque sem SMB Signing:
Vítima ──[NTLM Auth]──► Atacante ──[NTLM Relay]──► Servidor
                              ↑
                    Redireciona resposta
                    de volta à vítima

Ferramentas: Responder + ntlmrelayx (Impacket)
Resultado: Acesso ao servidor como a vítima
```

**O que as chaves fazem:**

| Chave | Efeito |
|-------|--------|
| `EnableSecuritySignature = 1` | Habilita assinatura SMB (negocia se o outro lado suportar) |
| `RequireSecuritySignature = 1` | **Exige** assinatura — rejeita conexões sem ela |

Aplicar em **ambos** (Workstation + Server) garante cobertura bidirecional. Apenas `Enable` sem `Require` não é suficiente — o atacante pode negociar sem assinatura.

**MITRE:** T1557.001 (LLMNR/NBT-NS Poisoning) · T1550.002 (Pass-the-Hash) · T1187 (Forced Authentication)

**Relação com PrintNightmare:** SMB Signing não previne CVE-2021-1675 diretamente, mas bloqueia o vetor de relay que frequentemente precede o ataque.

---

### ⑤ Cached Logon — Credenciais em Cache

```powershell
Set-ItemProperty -Path "HKLM:\...\Winlogon" -Name "cachedlogonscount" -Value 1
```

**O que são cached logon credentials?**

Quando um usuário de domínio faz login em um sistema Windows sem conectividade com o Domain Controller, o Windows usa credenciais armazenadas em cache local — salvas em `HKLM\SECURITY\Cache` como hashes MSCACHE2.

**Por que limitar para `1`?**

Por padrão o Windows armazena as últimas **10 credenciais** em cache. Um atacante com acesso SYSTEM pode extrair esses hashes com ferramentas como Mimikatz:

```powershell
# Mimikatz
lsadump::cache

# Resultado (exemplo):
* Username: usuario.dominio
* MsCacheV2: $DCC2$10240#usuario.dominio#a3f8b2c91d7e...
```

Os hashes MSCACHE2 são offline-crackáveis com hashcat (`-m 2100`). Reduzir para `1` limita a superfície — apenas a última credencial fica exposta.

**Trade-off:** com `cachedlogonscount = 0`, usuários de domínio não conseguem logar sem conectividade com o DC — impacto operacional em notebooks e ambientes remotos.

**MITRE:** T1003.005 (Cached Domain Credentials) · T1558 (Steal or Forge Kerberos Tickets)

---

### ⑥ Guest Account — Conta Padrão Desativada

```powershell
Try {
    Rename-LocalUser -Name "Guest" -NewName "Guest_Disabled"
} Catch {
    Disable-LocalUser -Name "Guest"
}
```

**Por que renomear e não apenas desabilitar?**

A conta **Guest** é conhecida por atacantes — é um alvo de força bruta e tentativas de autenticação anônima. Renomear (`Guest_Disabled`) adiciona uma camada extra de obscuridade: ferramentas de enumeração que procuram especificamente pela conta "Guest" não a encontram pelo nome.

O `Try/Catch` lida com duas situações:
- Sistema com controle de conta funcional → rename
- Sistema onde rename falha (política, idioma diferente) → disable como fallback

**MITRE:** T1078.001 (Valid Accounts: Default Accounts) · T1110 (Brute Force)

---

### ⑦ Authenticode Certificate Padding (MS13-098)

```powershell
# x64
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
  -Name "EnableCertPaddingCheck" -Value 1

# x86 (WOW64)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" `
  -Name "EnableCertPaddingCheck" -Value 1
```

**O que é o CVE-2013-3900?**

A função `WinVerifyTrust()` do Windows valida assinaturas Authenticode de arquivos executáveis. A vulnerabilidade permite que atacantes **adicionem dados arbitrários ao final de um binário assinado** sem invalidar a assinatura — técnica conhecida como **Signature Appending**.

```
Arquivo legítimo assinado:  [PE Header][Code][Digital Signature]
Arquivo malicioso:          [PE Header][Code][Digital Signature][Malicious Payload]
                                                                ↑
                                              WinVerifyTrust retorna VALID
                                              porque a assinatura é verificada
                                              mas o payload extra é ignorado
```

**Por que dois caminhos de registry (x64 e Wow6432Node)?**

Windows 64-bit mantém duas visões do registry:
- `HKLM\SOFTWARE\...` → processos nativos x64
- `HKLM\SOFTWARE\Wow6432Node\...` → processos x86 rodando via WOW64

Sem o `Wow6432Node`, processos 32-bit (como muitos instaladores e browsers legados) continuariam vulneráveis mesmo com a chave x64 aplicada.

**MITRE:** T1553.002 (Subvert Trust Controls: Code Signing) · T1036.001 (Masquerading: Invalid Code Signature)

**CVE:** CVE-2013-3900 (MS13-098)

---

### ⑧ AutoRun / AutoPlay — Execução Automática de Mídia

```powershell
# HKLM (todos os usuários)
Set-ItemProperty -Path "HKLM:\...\Policies\Explorer" -Name "NoAutorun"          -Value 1
Set-ItemProperty -Path "HKLM:\...\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# HKU\.DEFAULT (usuário padrão / novos usuários)
Set-ItemProperty -Path "HKU:\.DEFAULT\...\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
```

**Como AutoRun é explorado?**

AutoRun/AutoPlay executa automaticamente o arquivo `autorun.inf` na raiz de mídias removíveis. Malware de USB usa isso para executar payloads imediatamente ao plugar o dispositivo, sem interação do usuário.

**O valor `NoDriveTypeAutoRun = 255`:**

```
255 = 0xFF = 1111 1111 binário

Cada bit representa um tipo de unidade:
  Bit 0 (1)   → Unknown
  Bit 1 (2)   → Sem raiz (UNC)
  Bit 2 (4)   → Removível (USB, floppy)
  Bit 3 (8)   → Fixo (HD local)
  Bit 4 (16)  → Rede
  Bit 5 (32)  → CD-ROM
  Bit 6 (64)  → RAM disk
  Bit 7 (128) → Reserved

255 → desabilita AutoRun para TODOS os tipos de unidade
```

**Por que aplicar também em `HKU\.DEFAULT`?**

`HKU\.DEFAULT` é o template de perfil para novos usuários. Sem isso, um usuário criado após a aplicação do script não herdaria a mitigação — gap de cobertura.

**MITRE:** T1091 (Replication Through Removable Media) · T1204.002 (User Execution: Malicious File)

---

## `$ cat ./mitre_mapping.yml`

```yaml
mitigations_mitre_coverage:

  null_sessions:
    - T1135   # Network Share Discovery (bloqueia enum via IPC$)
    - T1087   # Account Discovery (bloqueia enum anônima de usuários)
    - T1069   # Permission Groups Discovery

  weak_ciphers:
    - T1557   # Adversary-in-the-Middle (remove viabilidade de downgrade)
    - T1040   # Network Sniffing (tráfego cifrado com 3DES é mais vulnerável)

  spectre_meltdown:
    - T1055   # Process Injection (Spectre pode vazar memória de outros processos)
    - T1003   # OS Credential Dumping (Meltdown pode ler memória do kernel)

  smb_signing:
    - T1557.001  # LLMNR/NBT-NS Poisoning and Relay
    - T1550.002  # Pass-the-Hash
    - T1187      # Forced Authentication (NTLM relay)

  cached_logon:
    - T1003.005  # Cached Domain Credentials (limita hashes extraíveis)

  guest_account:
    - T1078.001  # Default Accounts
    - T1110      # Brute Force

  authenticode:
    - T1553.002  # Code Signing bypass
    - T1036.001  # Invalid Code Signature masquerading

  autorun:
    - T1091      # Replication Through Removable Media
    - T1204.002  # Malicious File Execution via AutoPlay
```

---

## `$ cat ./usage.sh`

```powershell
# Gerar o script PowerShell
python generate_hardening.py

# Executar o script gerado (requer privilégios de Administrador)
# PowerShell como Administrador:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\script_mitigacoes_unificado.ps1

# Verificar aplicação de cada mitigação:

# 1. Null Sessions
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" | Select RestrictAnonymous

# 2. 3DES
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"

# 3. Spectre/Meltdown
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" |
  Select FeatureSettingsOverride, FeatureSettingsOverrideMask

# 4. SMB Signing
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" |
  Select RequireSecuritySignature, EnableSecuritySignature

# 5. Cached Logon
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
  Select cachedlogonscount

# 6. Guest Account
Get-LocalUser | Select Name, Enabled

# 7. Authenticode
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"

# 8. AutoRun
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |
  Select NoAutorun, NoDriveTypeAutoRun
```

---

## `$ cat ./cis_benchmark_mapping.md`

| Mitigação | CIS Control | CIS Benchmark Section | DISA STIG ID |
|-----------|------------|----------------------|-------------|
| Null Sessions | CIS 4.3 | Account Restrictions | V-220906 |
| DES/3DES | CIS 17.1 | System Cryptography | V-220978 |
| Spectre/Meltdown | CIS 18.8 | Vulnerability Mitigation | V-220913 |
| SMB Signing | CIS 9.1 | Network Access | V-220829 |
| Cached Logon | CIS 16.11 | Credential Management | V-220938 |
| Guest Account | CIS 4.7 | Account Management | V-220740 |
| Authenticode | CIS 5.1 | Code Integrity | V-220864 |
| AutoRun | CIS 8.5 | Malware Defense | V-220856 |

---

## `$ cat ./lessons_learned.txt`

```
[+] Registry é o mecanismo mais granular para hardening Windows sem GPO central
[+] Try/Catch no Guest rename lida com ambientes localizados (Guest pode ter outro nome)
[+] Wow6432Node é frequentemente esquecido — deixa processos x86 sem a mitigação
[+] NoDriveTypeAutoRun = 255 cobre todos os tipos de unidade com um único valor
[+] SMB Signing requer Enable + Require em ambos os lados (cliente e servidor)
[-] FeatureSettingsOverride para Spectre/Meltdown tem custo de performance — documentar impacto
[-] cachedlogonscount = 0 quebra login offline — 1 é o mínimo seguro com usabilidade
[-] Script não verifica se as chaves já existem antes de criar (New-Item -Force mitiga isso)
[-] Sem rollback automático — considerar export das chaves antes de aplicar
[-] HKU:.DEFAULT requer que a hive esteja carregada — validar em ambientes com profiles roaming
[→] Melhorias: modo --check para auditar sem aplicar, --rollback para reverter, output em JSON
```

---

<p align="center">
  <i>Windows Hardening · CIS Benchmark aligned · DISA STIG referenced · MITRE ATT&CK mapped · Registry-based · Reversible</i>
</p>
