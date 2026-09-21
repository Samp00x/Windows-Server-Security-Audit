# Como interpretar as dependências

[English](Dependency-Reports.md) | [Guia rápido](Guia-Rapido.pt-BR.md)

Os relatórios numerados agora são sequenciais. Os nomes e esquemas mudaram: atualize importações salvas e use uma pasta nova para não misturar arquivos de versões anteriores.

| Ordem | Arquivo | Conteúdo |
| --- | --- | --- |
| 01 | `01-Privileged-Users.csv` | SIDs de usuários privilegiados e grupos de origem |
| 02 | `02-Privileged-Groups-Summary.csv` | Cobertura do levantamento por grupo |
| 03 | `03-Privileged-Service-Dependencies.csv` | Todos os serviços Windows observados, inclusive identidades sem correspondência ou não resolvidas |
| 04 | `04-Scheduled-Task-Dependencies.csv` | Tarefas agendadas com classificação separada dos artefatos de perfil |
| 05 | `05-Server-Scan-Status.csv` | Cobertura, quantidade de registros e identidades não resolvidas por coletor |
| 06 | `06-Privileged-Account-Risks.csv` | Indicadores de configuração das contas |

Os auxiliares continuam sem numeração: `DiscoveryStatus.csv`, `RiskQueryStatus.csv`, `DependencyInventory.csv` (todos os coletores e erros de resolução) e `Other-Privileged-Dependencies.csv` (correspondências por SID em IIS, Administradores locais diretos e processos opcionais). Esses outros achados não são dependências de serviços Windows.

## Leia a cobertura e depois os serviços

Comece pelo relatório 05. `Success` com `ObservedCount=0` significa consulta concluída sem registros. `Failed` significa consulta incompleta, mesmo que alguns registros tenham chegado. `Partial` inclui lacunas na resolução de identidades; `UnresolvedIdentityCount` conta essas lacunas, não recursos ausentes. `Skipped` e `NotApplicable` ficam explícitos. Uma falha de conexão gera falha para cada coletor sem resposta. Os resultados já coletados são preservados quando outro coletor falha.

O relatório 03 contém `Server`, `ServiceName`, `DisplayName`, `State`, `StartMode`, `StartNameRaw`, `ResolvedAccountType`, `ResolvedDomain`, `ResolvedSamAccountName`, `AccountSID`, `IsPrivileged`, `PrivilegedGroups`, `DependencySeverity`, `WhyItMatters`, `ResolutionStatus` e `ResolutionError`. Inclui todos os serviços para que uma identidade sem correspondência não desapareça. Filtre `IsPrivileged=True` para correspondências confirmadas e revise todos os casos `Review` e não resolvidos.

`State` é o estado observado; `StartMode` é o modo CIM configurado (`Auto`, `Manual`, `Disabled`). O script não deduz criticidade de negócio pelo nome do produto. `Critical` indica exposição de privilégios e dependência de execução, não indisponibilidade comprovada.

| Evidência | Severidade |
| --- | --- |
| Serviço automático em execução com SID privilegiado de domínio | Critical |
| Outro serviço em execução com SID privilegiado | High |
| Serviço automático parado (qualquer identidade), ou outro serviço privilegiado sem execução | Review |
| Identidade de serviço não resolvida ou privilégio desconhecido | Review |
| Outra identidade resolvida sem correspondência nos SIDs fornecidos | Informational |

`IsPrivileged=True` confirma que o SID consta no levantamento fornecido. `False` significa ausência de correspondência **nesse inventário**, não ausência de todos os privilégios. `Unknown` indica resolução incompleta sem correspondência confirmada por SID. Direitos administrativos locais, identidades de sistema, tarefas com grupos, contas gerenciadas ausentes do levantamento de usuários e grupos de domínio fora do escopo precisam de análise separada. O scanner não expande membros de grupos. Um SID órfão é preservado e pode corresponder ao levantamento, mas continua exigindo revisão do escopo não resolvido.

## Resolução de identidade

A tradução ocorre dentro da sessão remota de cada alvo, com cache por identidade naquele servidor. O nome configurado vira SID e depois nome qualificado canônico. O cruzamento de privilégios usa apenas SID: uma correspondência somente por texto nunca confirma dependência. Aliases DNS, UPNs, variações de maiúsculas e contas renomeadas dependem do resolvedor Windows do alvo.

Exemplos fictícios no servidor `APP01`:

| Identidade configurada | Interpretação quando resolvida pelo Windows |
| --- | --- |
| `EXAMPLE\Administrator` ou `example.test\Administrator` | Conta de domínio; mesmo SID se os nomes identificarem a mesma conta |
| `.\Administrator` ou `APP01\Administrator` | Conta local do APP01; SID diferente da conta de domínio |
| `Administrator` | Nome ambíguo sem qualificador; Unresolved, sem adivinhação |
| `LocalSystem`, `NT AUTHORITY\LOCAL SERVICE`, `NT SERVICE\Demo` | Identidade interna/virtual após resolução bem-sucedida |

Os dois administradores podem ter RID final 500; o cruzamento usa o **SID completo**. A identificação local usa o nome real do alvo, não o alias/FQDN usado na conexão. Controladores de domínio não são tratados como possuindo SAM local. Falhas de tradução, contas excluídas, namespaces não suportados ou contexto indisponível preservam o valor original e o erro, com cobertura Partial. Corrija conectividade, confiança ou acesso e execute novamente; o CSV não garante visibilidade de sistemas inacessíveis.

## Tarefas e artefatos de perfil

O relatório 04 preserva todas as tarefas, caminho/nome completo, principal original, tipo de logon, identidade resolvida, privilégios, classificação e explicação. As famílias `OneDrive Startup`, `OneDrive Reporting`, `CreateExplorerShellUnelevatedTask`, `User_Feed_Synchronization` e `GoogleUserPEH` recebem `UserProfileArtifact` / `Informational` **quando o logon é interativo**. Evidenciam contexto de usuário conectado, sem comprovar dependência de serviço Windows não assistido, mesmo se o SID do usuário for privilegiado. Erros de identidade continuam nos relatórios 04 e 05.

Nomes semelhantes com logon Password, S4U, grupo ou desconhecido ficam em `Review`: o nome não comprova legitimidade. Outras tarefas privilegiadas ficam High, ou Review quando desabilitadas. O estado `Ready` não significa execução naquele momento. Confira ações e responsável pela aplicação quando a configuração for inesperada.

Na conclusão da análise, separe serviços privilegiados confirmados, tarefas não assistidas, artefatos de perfil e lacunas de coleta. Valide responsável, permissões mínimas, identidade substituta, reinício e reversão antes das correções. O relatório comprova configuração observada, não validade da senha armazenada nem continuidade após alterar senha ou grupos.

## Validação

Execute os três testes em `Tests/`. Eles exercitam o corpo real do coletor com respostas Windows simuladas, aliases/colisões de SID, identidades internas, falhas de resolução, severidades e tarefas de perfil. Antes de produção, valide em domínio descartável com servidor membro: contas locais/de domínio homônimas, nomes DNS/NetBIOS, serviços automáticos em execução/parados, tarefas interativas/não assistidas, acesso negado e servidor inacessível. Testes sem rede não comprovam validação real de AD/WinRM.

Referências Microsoft: [NTAccount.Translate](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.ntaccount.translate), [Tipos de logon de tarefas](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).
