# Auditoria de segurança de Windows Server e Active Directory

[English](README.md) | **Português (Brasil)** | [Guia rápido de uso](Docs/Guia-Rapido.pt-BR.md)

Conjunto de scripts PowerShell de **somente leitura** para levantar usuários privilegiados no AD, localizar dependências em servidores e identificar configurações de contas que precisam de revisão. Os scripts não removem associações a grupos, não desabilitam usuários, não alteram senhas e não modificam configurações dos servidores.

## O que cada script faz

| Script | Finalidade |
| --- | --- |
| `Scripts/Get-PrivilegedUsers.ps1` | Localiza usuários por associação direta, grupos aninhados e grupo primário; gera o relatório de usuários e um resumo da cobertura dos grupos. |
| `Scripts/Get-PrivilegedAccountDependencies.ps1` | Consulta serviços, tarefas agendadas, pools do IIS, membros diretos de Administradores locais e, opcionalmente, processos em execução nos servidores informados. |
| `Scripts/Get-PrivilegedAccountRisks.ps1` | Consulta novamente os usuários pelo SID e sinaliza contas desabilitadas/inativas, configurações de senha, pré-autenticação Kerberos, delegação, SPNs e histórico de SIDs. |

Grupos padrão: Domain Admins, Group Policy Creator Owners, Builtin Administrators, Account/Server/Print/Backup Operators, DnsAdmins e os grupos Schema/Enterprise Admins do domínio raiz da floresta. Inclua grupos personalizados com `-AdditionalGroup`. Grupos não encontrados aparecem como lacunas de cobertura, inclusive DnsAdmins quando não existe no domínio.

## Requisitos

- Execute no **Windows PowerShell 5.1 de 64 bits**, em Windows Server 2016 ou posterior, ou em uma estação administrativa com RSAT. PowerShell 7 não é o ambiente de execução suportado para a auditoria.
- Os scripts de levantamento e riscos exigem o módulo `ActiveDirectory`, conectividade com DNS/controladores de domínio e permissão de leitura dos objetos consultados. Usam sua identidade atual do Windows.
- A consulta aos servidores exige uma conta autorizada no endpoint de execução remota e nos recursos consultados, geralmente administrador local, além de conectividade WinRM e do endpoint padrão `Microsoft.PowerShell`. O parâmetro `-Credential (Get-Credential)` é opcional e se aplica apenas à consulta de dependências.
- Os servidores precisam dos recursos CIM, ScheduledTasks e Microsoft.PowerShell.LocalAccounts. Servidores IIS também precisam de WebAdministration. Módulos ausentes e acessos negados são registrados como falhas.
- Use um escopo de auditoria aprovado e uma pasta de relatórios com acesso restrito. Os scripts não instalam componentes nem habilitam a execução remota.

## Início rápido

Baixe ou clone o repositório e abra o Windows PowerShell na pasta principal. Substitua os nomes fictícios pelos alvos autorizados:

```powershell
$run = Join-Path $PWD ('Output/' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\Scripts\Get-PrivilegedUsers.ps1 -Server 'dc01.example.test' -OutputFolder $run

# Revise DiscoveryStatus.csv e 02-Privileged-Groups-Summary.csv antes de continuar.
$accounts = Join-Path $run '01-Privileged-Users.csv'
.\Scripts\Get-PrivilegedAccountDependencies.ps1 -PrivilegedCsv $accounts `
    -ComputerName 'app01.example.test','web01.example.test' -OutputFolder $run
.\Scripts\Get-PrivilegedAccountRisks.ps1 -PrivilegedCsv $accounts -OutputFolder $run
```

O [guia rápido](Docs/Guia-Rapido.pt-BR.md) explica a execução passo a passo. Adicione `-ScanProcesses` para consultar os proprietários dos processos naquele momento; essa opção pode aumentar bastante o tempo de coleta. Ajuste os limites de revisão com `-InactiveDays 90` e `-PasswordAgeDays 180`. A idade da senha é um indicador para avaliação interna, não uma exigência universal de troca periódica. Use uma nova pasta por execução: relatórios de mesmo nome são sobrescritos.

## Relatórios e interpretação

Os CSVs usam UTF-8, ponto e vírgula como separador, cabeçalhos estáveis mesmo sem resultados e datas no formato ISO 8601 quando exportadas. Importe com `Import-Csv -Delimiter ';'`. Os nomes de arquivos, parâmetros, colunas e valores continuam em inglês para manter compatibilidade com os scripts.

| Relatório | Conteúdo |
| --- | --- |
| `01-Privileged-Users.csv` | Uma linha por SID de usuário e grupo privilegiado de origem; inclui a identidade com domínio para cruzamento. |
| `02-Privileged-Groups-Summary.csv` | Usuários encontrados, grupos percorridos e cobertura por grupo solicitado. Quando parcial, a contagem representa somente o que foi encontrado. |
| `DiscoveryStatus.csv` | Grupos ausentes, objetos não suportados e falhas na leitura do diretório. |
| `03-Privileged-Service-Dependencies.csv` | Todos os serviços Windows, SID resolvido no alvo, tipo de conta, privilégios, severidade e explicação. |
| `04-Scheduled-Task-Dependencies.csv` | Todas as tarefas, com artefatos interativos de perfil separados das dependências não assistidas. |
| `05-Server-Scan-Status.csv` | Situação de cada coletor em cada servidor: Success, Partial, Failed, Skipped ou NotApplicable. |
| `DependencyInventory.csv` | Todas as identidades configuradas observadas, inclusive contas sem correspondência e grupos para revisão manual. |
| `06-Privileged-Account-Risks.csv` | Uma linha por SID consultado com sucesso, com os indicadores individuais de revisão. |
| `RiskQueryStatus.csv` | Sucesso ou falha de cada consulta de conta solicitada. |
| `Other-Privileged-Dependencies.csv` | Correspondências por SID em IIS, Administradores locais diretos e processos opcionais. |

Veja [Evidências e regras de severidade](Docs/Dependency-Reports.pt-BR.md) para colunas, resolução de identidade, migração dos nomes e revisão. Leia primeiro o relatório 05 e depois o 03. Serviços automáticos em execução com SID privilegiado de domínio ficam Critical; outros serviços privilegiados em execução, High; automáticos privilegiados parados, Review. Tarefas de perfil com logon interativo ficam Informational. `IsPrivileged=False` significa ausência de correspondência no inventário fornecido, não ausência de todos os privilégios.

**Não encontrar dependências não comprova que uma conta está sem uso.** Revise cobertura e inventário antes de qualquer alteração. Um serviço parado ou uma tarefa desabilitada ainda pode depender da identidade configurada. Um indicador de risco não determina que o acesso seja desnecessário; a decisão precisa do responsável pela conta ou aplicação.

## Escopo e limitações

- O levantamento cobre os grupos selecionados, não todos os caminhos possíveis de privilégio. Delegações por ACL no AD, direitos em GPOs, AD CS, relações de confiança, ACLs de recursos e permissões de aplicações exigem avaliação separada. Atributos históricos `adminCount` e exportações de delegações estão fora deste fluxo compacto.
- Execute o levantamento separadamente para cada domínio, em pastas distintas. Os grupos do domínio raiz são incluídos, mas não há auditoria automática de toda a floresta. Principais de segurança externos (foreign security principals) e objetos que não são usuários são registrados para revisão manual.
- Administradores locais e grupos usados como identidade de tarefas são inventariados diretamente; o script de dependências **não expande os membros desses grupos**. Um usuário pode ter acesso local indireto sem aparecer no relatório de correspondências. Controladores de domínio não possuem um grupo Administradores em SAM local; revise o grupo Builtin do domínio.
- A tradução ocorre no alvo e o cruzamento usa apenas SIDs completos. Aliases DNS/NetBIOS e UPNs podem corresponder quando resolvidos pelo Windows. Nomes sem qualificador continuam ambíguos. Identidades não resolvidas preservam erros e geram cobertura Partial; `NotMatched` não significa ausência de privilégio.
- `LastLogonDate` é replicado, aproximado e pode estar defasado. Ausência de logon registrado não comprova ausência de uso. Consulte os DCs relevantes e os registros de segurança/aplicações antes de concluir inatividade.
- Dependências fora dos coletores listados, como scripts, SQL Agent, credenciais de aplicações, clusters, credenciais armazenadas e servidores offline, não estão cobertas. Processos representam apenas o instante da coleta.
- Cobertura indica que a consulta configurada terminou, não que a conta utilizada consegue enxergar todos os recursos protegidos. Valide em laboratório representativo antes do uso em produção.

## Organização do repositório

```text
Scripts/       Scripts de auditoria e funções compartilhadas
Docs/          Fluxo de auditoria, solução de problemas e guia rápido
Examples/      Apenas CSVs fictícios (EXAMPLE / example.test)
Tests/         Testes sem rede e integração contínua no Windows
Output/        Relatórios ignorados pelo Git; somente .gitkeep é versionado
```

Consulte o [fluxo de auditoria](Docs/Audit-Workflow.pt-BR.md) e a [solução de problemas](Docs/Troubleshooting.pt-BR.md). Execute `powershell.exe -NoProfile -File .\Tests\Test-Toolkit.ps1`, `powershell.exe -NoProfile -File .\Tests\Test-Dependencies.ps1` e `powershell.exe -NoProfile -File .\Tests\Test-Workflow.ps1`. Verificam sintaxe, identidades, severidades e coletores/fluxos simulados; não substituem testes reais de AD/WinRM.

## Tratamento dos dados

Não há dados de clientes neste repositório. Os exemplos são inventados e não comprovam uma auditoria real. Os relatórios de execução contêm informações sensíveis sobre identidades e infraestrutura. Guarde-os em local restrito aprovado, aplique a política de retenção e revise os arquivos preparados para commit. O `.gitignore` é uma conveniência, não um controle de acesso ou uma proteção contra vazamento. Ao abrir CSVs em planilhas, importe os valores como texto para evitar a interpretação de fórmulas.

## Referências Microsoft

- [Get-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember)
- [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)
- [Proprietário de processos por Win32_Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process)

## Como contribuir

Mantenha os coletores somente leitura, preserve a identificação de domínio, registre falhas de consulta e acrescente testes de regressão quando alterar comportamentos. Use apenas dados fictícios nos testes. Descreva no pull request o ambiente Windows/AD usado na validação real, sem anexar relatórios de produção.
