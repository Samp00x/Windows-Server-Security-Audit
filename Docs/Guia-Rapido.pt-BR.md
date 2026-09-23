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
| `05-PrivilegedAccountDependencies.csv` | Onde essas contas estão configuradas: serviços, tarefas, IIS e Administradores locais diretos. |
| `07-PrivilegedAccountRisks.csv` | Quais configurações das contas precisam de revisão. |
| `RunStatus.csv` | Quais etapas terminaram ou falharam. |
| `06-ServerScanStatus.csv` | Quais consultas funcionaram ou falharam em cada servidor. |
| `ServerDiscovery.csv` | Quais servidores/DCs o AD forneceu e quais não tinham nome DNS. |

Confira também `DiscoveryStatus.csv`, `04-PrivilegedGroupSummary.csv` e `RiskQueryStatus.csv` para identificar lacunas. `Completed` em RunStatus significa que a etapa terminou; ainda pode haver falhas individuais nos relatórios detalhados.

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

As etapas individuais sobrescrevem seus próprios relatórios; o histórico automático é feito pelo comando principal. Se não houver levantamento válido, dependências/riscos pedem que a entrada seja corrigida; execute primeiro `Start-Audit.ps1` ou `Get-PrivilegedUsers.ps1`.

**Antes de retirar privilégios**, valide com o responsável pela conta/aplicação. Não encontrar correspondências não prova ausência de uso: grupos locais não são expandidos e há tipos de aplicações fora do escopo. Veja o [fluxo completo](Audit-Workflow.pt-BR.md).
