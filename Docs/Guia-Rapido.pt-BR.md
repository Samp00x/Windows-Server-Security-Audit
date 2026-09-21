# Guia rápido: como usar os scripts

[Início em português](../README.pt-BR.md) | [Solução de problemas](Troubleshooting.pt-BR.md)

**A ordem é: levantar usuários → conferir a coleta → procurar dependências → avaliar riscos.** Os scripts apenas consultam e geram relatórios.

## 1. Prepare a execução

Baixe o repositório, extraia a pasta e abra o **Windows PowerShell 5.1 de 64 bits** nessa pasta. Use uma conta com leitura no AD e acesso administrativo autorizado aos servidores. A máquina de execução precisa do módulo ActiveDirectory/RSAT; os servidores precisam estar acessíveis por WinRM. Consulte os [requisitos completos](../README.pt-BR.md#requisitos).

Defina abaixo seu controlador de domínio e os servidores que serão consultados. Os nomes de exemplo são fictícios e precisam ser substituídos:

```powershell
$dc = 'dc01.example.test'
$servidores = @('app01.example.test', 'web01.example.test')
$pasta = Join-Path $PWD ('Output/' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
```

Execute as próximas etapas **na mesma janela**, pois elas reutilizam essas variáveis. Faça uma execução separada por domínio e comece com poucos servidores.

## 2. Descubra quem possui privilégios

```powershell
.\Scripts\Get-PrivilegedUsers.ps1 -Server $dc -OutputFolder $pasta
```

Abra `01-PrivilegedUsers.csv` para ver os usuários e `04-PrivilegedGroupSummary.csv` para conferir os grupos. Verifique também `DiscoveryStatus.csv`: se houver falhas, corrija ou documente as lacunas antes de continuar. Um arquivo de status somente com cabeçalho indica que não foram registrados problemas nessa coleta.

O mesmo usuário pode aparecer mais de uma vez se pertencer a mais de um grupo privilegiado. Não remova as colunas do CSV: os próximos scripts precisam delas.

## 3. Veja onde essas contas estão configuradas

```powershell
$usuarios = Join-Path $pasta '01-PrivilegedUsers.csv'
.\Scripts\Get-PrivilegedAccountDependencies.ps1 -PrivilegedCsv $usuarios -ComputerName $servidores -OutputFolder $pasta
```

O script verifica serviços, tarefas agendadas, pools IIS e membros diretos de Administradores locais. Leia primeiro `06-ServerScanStatus.csv` e depois `05-PrivilegedAccountDependencies.csv`. Consulte `DependencyInventory.csv` para identidades sem correspondência e grupos que precisam de revisão manual.

Para incluir os processos em execução, acrescente `-ScanProcesses` ao comando. Isso demora mais e mostra apenas aquele momento. Para usar outra credencial nos servidores, acrescente `-Credential (Get-Credential)`; essa opção não altera a identidade usada pelos scripts de AD.

## 4. Gere o relatório de riscos

```powershell
.\Scripts\Get-PrivilegedAccountRisks.ps1 -PrivilegedCsv $usuarios -OutputFolder $pasta
```

Leia `RiskQueryStatus.csv` para confirmar quais contas foram consultadas e `07-PrivilegedAccountRisks.csv` para ver os indicadores. A coluna `Findings` contém os pontos de revisão, por exemplo:

| Indicador | Significado |
| --- | --- |
| DisabledPrivilegedAccount | Conta desabilitada que constava no levantamento de privilegiados. |
| NoReplicatedLogonRecorded | Não há logon replicado registrado; isso não comprova ausência de uso. |
| StaleReplicatedLogon | Logon replicado anterior ao limite informado. |
| PasswordNeverExpires | Senha configurada para nunca expirar. |
| DoesNotRequirePreAuth | Pré-autenticação Kerberos não exigida. |
| ServicePrincipalNamePresent | Conta possui SPN; valide sua finalidade e dependências. |

## 5. Encontre e abra os resultados

```powershell
# Mostra onde os arquivos foram salvos.
$pasta

# Exemplo de leitura do relatório no PowerShell.
Import-Csv (Join-Path $pasta '05-PrivilegedAccountDependencies.csv') -Delimiter ';' | Format-Table Server,UsageType,Resource,SamAccountName -AutoSize
```

No Excel, importe por **Dados → De Texto/CSV**, selecione UTF-8 e ponto e vírgula como separador. Trate as colunas como texto para preservar identidades e evitar interpretação de fórmulas.

| Situação da coleta | Como interpretar |
| --- | --- |
| Success / Complete | Consulta concluída dentro do escopo configurado. |
| Partial | Há resultados, mas também lacunas que exigem revisão. |
| Failed | Não foi possível concluir a consulta. |
| Skipped | Coleta não solicitada, como processos sem `-ScanProcesses`. |
| NotApplicable | Recurso não aplicável àquele alvo, conforme a mensagem. |

## Opções úteis

| Necessidade | Como fazer |
| --- | --- |
| Incluir grupo personalizado | Adicione `-AdditionalGroup 'Grupo-Administrativo-Exemplo'` ao levantamento. |
| Alterar limite de inatividade | Use `-InactiveDays 120` no levantamento e no script de riscos para aplicar o mesmo limite. |
| Alterar idade de senha para revisão | Use `-PasswordAgeDays 180` no script de riscos. Não é uma ordem automática de troca de senha. |
| Ler servidores de arquivo local | Defina `$servidores = Get-Content 'C:\Auditoria\servidores.txt'`, com um nome por linha e sem linhas vazias. Não publique esse arquivo. |
| Consultar ajuda | Execute `Get-Help .\Scripts\Get-PrivilegedUsers.ps1 -Full`. |

**Antes de retirar privilégios ou desabilitar contas**, confirme a necessidade com o responsável e valide as dependências. Grupos locais não são expandidos pelo scanner, logons replicados podem estar defasados e ausência de correspondência não comprova ausência de uso. Veja o [fluxo completo](Audit-Workflow.pt-BR.md) para conduzir a revisão.
