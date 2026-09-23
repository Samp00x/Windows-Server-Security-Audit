# Guia rápido: execute a auditoria com um comando

[Início em português](../README.pt-BR.md) | [Solução de problemas](Troubleshooting.pt-BR.md)

## Como executar

1. Baixe o repositório pelo botão **Code → Download ZIP** e extraia os arquivos.
2. Em um DC ou computador Windows integrado ao domínio, abra o **Windows PowerShell 5.1 de 64 bits como administrador**, usando uma conta autorizada a consultar o AD e os servidores.
3. Entre na pasta extraída: digite `cd `, arraste a pasta para a janela do PowerShell e pressione Enter.
4. Execute:

```powershell
.\Start-Audit.ps1
```

**Não precisa informar DC, lista de servidores nem pasta de saída.**

O script identifica o domínio da máquina, consulta no AD os computadores habilitados com sistema operacional Windows Server e os controladores de domínio, levanta os usuários privilegiados, procura dependências e verifica riscos. Os DCs também entram na consulta de dependências.

## Onde ficam os resultados?

Sempre em **`C:\scriptsDC`**, por padrão. A pasta é criada automaticamente.

| Abra este arquivo | Para ver |
| --- | --- |
| `01-PrivilegedUsers.csv` | Quem possui privilégios e por quais grupos. |
| `02-PrivilegedUserReview.xlsx` | Uma linha por usuário para preencher decisão e observações. Confira CollectionStatus e a aba Collection. |
| `02-PrivilegedUserReview.csv` | A mesma revisão em CSV. |
| `02-MembershipPaths.csv` | Cada caminho direto/indireto, incluindo rotas alternativas. |
| `DiscoveryRun.csv` | Cobertura global e situação da geração da planilha. |
| `05-PrivilegedAccountDependencies.csv` | Onde essas contas estão configuradas: serviços, tarefas, IIS e Administradores locais diretos. |
| `07-PrivilegedAccountRisks.csv` | Quais configurações das contas precisam de revisão. |
| `RunStatus.csv` | Quais etapas terminaram ou falharam. |
| `06-ServerScanStatus.csv` | Quais consultas funcionaram ou falharam em cada servidor. |
| `ServerDiscovery.csv` | Quais servidores/DCs o AD forneceu e quais não tinham nome DNS. |

Confira também `DiscoveryStatus.csv`, `04-PrivilegedGroupSummary.csv` e `RiskQueryStatus.csv` para identificar lacunas. Discovery fica Partial no RunStatus quando há lacunas de coleta ou exportação. As próximas etapas usam apenas os usuários encontrados.

`AccountStatus` informa se a conta está habilitada; `LoginActivity` informa atividade de login separadamente. `LastLogonDate` é replicado e aproximado. Uma conta desabilitada pode ter logon recente, e data ausente não comprova falta de uso. Ciclos são registrados como CycleDetected e não eliminam rotas alternativas válidas.

Ao executar novamente o comando principal, os relatórios anteriores são movidos para **`C:\scriptsDC\History\<identificador da execução>`**. Os novos ficam diretamente em `C:\scriptsDC`.

No Excel, use **Dados → De Texto/CSV**, UTF-8 e separador ponto e vírgula. Importe os valores como texto.

## O que precisa estar pronto na máquina?

- Windows PowerShell 5.1 de 64 bits e módulo **ActiveDirectory** (ferramentas AD/RSAT).
- Máquina integrada ao domínio e conta com leitura no AD.
- Acesso autorizado aos servidores por WinRM para consultar as dependências.

Se faltar o módulo ou a conexão com o domínio, a execução informa o erro. O script não instala componentes nem altera o firewall ou habilita WinRM automaticamente. Servidores offline ou sem acesso ficam registrados como falha, não como livres de dependências. A descoberta usa o cadastro do **domínio atual no AD**; máquinas fora do domínio ou sem identificação de Windows Server no AD podem não aparecer. Não há varredura de faixas de IP.

## Opcional: incluir processos em execução

```powershell
.\Start-Audit.ps1 -ScanProcesses
```

Essa opção pode demorar mais e mostra apenas os processos existentes no momento.

## Opcional: executar somente uma etapa

Depois do primeiro levantamento, você pode repetir uma etapa sem preencher caminhos:

```powershell
# Levantamento de usuários
.\Scripts\Get-PrivilegedUsers.ps1

# Dependências: lê o levantamento em C:\scriptsDC e descobre os servidores pelo AD
.\Scripts\Get-PrivilegedAccountDependencies.ps1

# Riscos: lê o mesmo levantamento
.\Scripts\Get-PrivilegedAccountRisks.ps1
```

As etapas individuais regeneram seus CSVs; a planilha anterior fica em History/workbook-* para preservar decisões preenchidas. O comando principal arquiva todos os relatórios. Se não houver levantamento válido, dependências/riscos pedem que a entrada seja corrigida; execute primeiro `Start-Audit.ps1` ou `Get-PrivilegedUsers.ps1`.

**Antes de retirar privilégios**, valide com o responsável pela conta/aplicação. Não encontrar correspondências não prova ausência de uso: grupos locais não são expandidos e há tipos de aplicações fora do escopo. Veja o [fluxo completo](Audit-Workflow.pt-BR.md).
