# Auditoria de segurança de Windows Server e Active Directory

[English](README.md) | **Português (Brasil)** | [Guia rápido de uso](Docs/Guia-Rapido.pt-BR.md)

Conjunto de scripts PowerShell de **somente leitura** para levantar usuários privilegiados no AD, localizar dependências em servidores e identificar configurações de contas que precisam de revisão. Os scripts não removem associações a grupos, não desabilitam usuários, não alteram senhas e não modificam configurações dos servidores.

## O que cada script faz

| Script | Finalidade |
| --- | --- |
| `Scripts/Get-PrivilegedUsers.ps1` | Localiza usuários por associação direta, grupos aninhados e grupo primário; gera o relatório de usuários e um resumo da cobertura dos grupos. |
| `Scripts/Get-PrivilegedAccountDependencies.ps1` | Consulta serviços, tarefas agendadas, pools do IIS, membros diretos de Administradores locais e, opcionalmente, processos em execução nos servidores descobertos pelo AD ou informados opcionalmente. |
| `Scripts/Get-PrivilegedAccountRisks.ps1` | Consulta novamente os usuários pelo SID e sinaliza contas desabilitadas/inativas, configurações de senha, pré-autenticação Kerberos, delegação, SPNs e histórico de SIDs. |

Grupos padrão: Domain Admins, Group Policy Creator Owners, Builtin Administrators, Account/Server/Print/Backup Operators, DnsAdmins e os grupos Schema/Enterprise Admins do domínio raiz da floresta. Inclua grupos personalizados com `-AdditionalGroup`. Grupos não encontrados aparecem como lacunas de cobertura, inclusive DnsAdmins quando não existe no domínio.

## Requisitos

- Execute no **Windows PowerShell 5.1 de 64 bits**, em Windows Server 2016 ou posterior, ou em uma estação administrativa com RSAT. PowerShell 7 não é o ambiente de execução suportado para a auditoria.
- Os scripts de levantamento e riscos exigem o módulo `ActiveDirectory`, conectividade com DNS/controladores de domínio e permissão de leitura dos objetos consultados. Usam sua identidade atual do Windows.
- A consulta aos servidores exige uma conta autorizada no endpoint de execução remota e nos recursos consultados, geralmente administrador local, além de conectividade WinRM e do endpoint padrão `Microsoft.PowerShell`. O parâmetro `-Credential (Get-Credential)` é opcional e se aplica apenas à consulta de dependências.
- Os servidores precisam dos recursos CIM, ScheduledTasks e Microsoft.PowerShell.LocalAccounts. Servidores IIS também precisam de WebAdministration. Módulos ausentes e acessos negados são registrados como falhas.
- Use um escopo de auditoria aprovado e uma pasta de relatórios com acesso restrito. Os scripts não instalam componentes nem habilitam a execução remota.

## Início rápido

Baixe e extraia o repositório. Em uma máquina integrada ao domínio, abra o **Windows PowerShell 5.1 de 64 bits como administrador**, entre na pasta extraída e execute:

```powershell
.\Start-Audit.ps1
```

**Não é necessário declarar DCs, servidores ou pastas.** O comando detecta o domínio da máquina, consulta os servidores Windows habilitados e os DCs cadastrados no AD e executa as três etapas. Os relatórios ficam em **`C:\scriptsDC`**, criada automaticamente. Resultados anteriores são movidos para `C:\scriptsDC\History\<identificador>`.

Comece pelo [guia rápido](Docs/Guia-Rapido.pt-BR.md). Para incluir processos, execute `.\Start-Audit.ps1 -ScanProcesses`.

A descoberta cobre o domínio atual e usa o AD, sem varredura de IPs. Máquinas fora do domínio ou sem identificação de Windows Server no cadastro podem não aparecer. DCs são enumerados separadamente e incluídos. Nomes DNS ausentes são registrados; servidores inacessíveis geram falhas de coleta.

Os scripts individuais também usam `C:\scriptsDC` por padrão. Dependências e riscos leem o levantamento dessa pasta; execute o levantamento primeiro. Parâmetros manuais continuam disponíveis apenas para uso avançado: `-Server`, `-ComputerName` (dependências), `-OutputFolder` e `-PrivilegedCsv` (dependências/riscos). As etapas individuais sobrescrevem seus relatórios sem arquivá-los.

## Relatórios e interpretação

Os CSVs usam UTF-8, ponto e vírgula como separador, cabeçalhos estáveis mesmo sem resultados e datas no formato ISO 8601 quando exportadas. Importe com `Import-Csv -Delimiter ';'`. Os nomes de arquivos, parâmetros, colunas e valores continuam em inglês para manter compatibilidade com os scripts.

| Relatório | Conteúdo |
| --- | --- |
| `RunStatus.csv` | Situação das três etapas do comando principal; Completed exige revisão dos relatórios detalhados. |
| `ServerDiscovery.csv` | Servidores/DCs descobertos e nomes DNS ausentes. |
| `01-PrivilegedUsers.csv` | Uma linha por SID de usuário e grupo privilegiado de origem; inclui a identidade com domínio para cruzamento. |
| `04-PrivilegedGroupSummary.csv` | Usuários encontrados, grupos percorridos e cobertura por grupo solicitado. Quando parcial, a contagem representa somente o que foi encontrado. |
| `DiscoveryStatus.csv` | Grupos ausentes, objetos não suportados e falhas na leitura do diretório. |
| `05-PrivilegedAccountDependencies.csv` | Correspondências exatas por SID, UPN ou nome qualificado com domínio NetBIOS. |
| `06-ServerScanStatus.csv` | Situação de cada coletor em cada servidor: Success, Partial, Failed, Skipped ou NotApplicable. |
| `DependencyInventory.csv` | Todas as identidades configuradas observadas, inclusive contas sem correspondência e grupos para revisão manual. |
| `07-PrivilegedAccountRisks.csv` | Uma linha por SID consultado com sucesso, com os indicadores individuais de revisão. |
| `RiskQueryStatus.csv` | Sucesso ou falha de cada consulta de conta solicitada. |

**Não encontrar dependências não comprova que uma conta está sem uso.** Revise cobertura e inventário antes de qualquer alteração. Um serviço parado ou uma tarefa desabilitada ainda pode depender da identidade configurada. Um indicador de risco não determina que o acesso seja desnecessário; a decisão precisa do responsável pela conta ou aplicação.

## Escopo e limitações

- O levantamento cobre os grupos selecionados, não todos os caminhos possíveis de privilégio. Delegações por ACL no AD, direitos em GPOs, AD CS, relações de confiança, ACLs de recursos e permissões de aplicações exigem avaliação separada. Atributos históricos `adminCount` e exportações de delegações estão fora deste fluxo compacto.
- Execute o levantamento separadamente para cada domínio, em pastas distintas. Os grupos do domínio raiz são incluídos, mas não há auditoria automática de toda a floresta. Principais de segurança externos (foreign security principals) e objetos que não são usuários são registrados para revisão manual.
- Administradores locais e grupos usados como identidade de tarefas são inventariados diretamente; o script de dependências **não expande os membros desses grupos**. Um usuário pode ter acesso local indireto sem aparecer no relatório de correspondências. Controladores de domínio não possuem um grupo Administradores em SAM local; revise o grupo Builtin do domínio.
- O cruzamento preserva o domínio da identidade. Nomes sem domínio, aliases ausentes do relatório, contas renomeadas e identidades não resolvidas precisam de validação manual. `NotMatched` não significa ausência de privilégio.
- `LastLogonDate` é replicado, aproximado e pode estar defasado. Ausência de logon registrado não comprova ausência de uso. Consulte os DCs relevantes e os registros de segurança/aplicações antes de concluir inatividade.
- Dependências fora dos coletores listados, como scripts, SQL Agent, credenciais de aplicações, clusters, credenciais armazenadas e servidores offline, não estão cobertas. Processos representam apenas o instante da coleta.
- Cobertura indica que a consulta configurada terminou, não que a conta utilizada consegue enxergar todos os recursos protegidos. Valide em laboratório representativo antes do uso em produção.

## Organização do repositório

```text
Scripts/       Scripts de auditoria e funções compartilhadas
Docs/          Fluxo de auditoria, solução de problemas e guia rápido
Examples/      Apenas CSVs fictícios (EXAMPLE / example.test)
Tests/         Testes sem rede e integração contínua no Windows
Output/        Pasta legada opcional; saída padrão em C:\scriptsDC
```

Consulte o [fluxo de auditoria](Docs/Audit-Workflow.pt-BR.md) e a [solução de problemas](Docs/Troubleshooting.pt-BR.md). Execute os testes com `powershell.exe -NoProfile -File .\Tests\Test-Toolkit.ps1` e depois `powershell.exe -NoProfile -File .\Tests\Test-Workflow.ps1`. Eles verificam sintaxe, lógica e fluxos simulados; não substituem testes reais de AD/WinRM.

## Tratamento dos dados

Não há dados de clientes neste repositório. Os exemplos são inventados e não comprovam uma auditoria real. Os relatórios de execução contêm informações sensíveis sobre identidades e infraestrutura. Guarde-os em local restrito aprovado, aplique a política de retenção e revise os arquivos preparados para commit. O `.gitignore` é uma conveniência, não um controle de acesso ou uma proteção contra vazamento. Ao abrir CSVs em planilhas, importe os valores como texto para evitar a interpretação de fórmulas.

## Referências Microsoft

- [Get-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember)
- [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)
- [Proprietário de processos por Win32_Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process)

## Como contribuir

Mantenha os coletores somente leitura, preserve a identificação de domínio, registre falhas de consulta e acrescente testes de regressão quando alterar comportamentos. Use apenas dados fictícios nos testes. Descreva no pull request o ambiente Windows/AD usado na validação real, sem anexar relatórios de produção.
