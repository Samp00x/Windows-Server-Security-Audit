# Solução de problemas

[English](Troubleshooting.md) | [Início em português](../README.pt-BR.md) | [Guia rápido](Guia-Rapido.pt-BR.md)

| Sintoma | Verificação e ação |
| --- | --- |
| Domínio não detectado | Execute em máquina integrada ao domínio, com DNS/conectividade AD. O script usa o domínio da máquina, sem exigir o nome do DC. |
| Servidor não descoberto | Revise ServerDiscovery.csv. A descoberta seleciona computadores habilitados com Windows Server no atributo OperatingSystem e enumera DCs separadamente. Máquinas fora do AD não são descobertas. |
| Não consegue criar C:\scriptsDC | Execute com permissão de gravação nessa pasta. A pasta padrão é criada automaticamente. |
| Execução principal falha | Confira RunStatus.csv. Falha no levantamento interrompe as próximas etapas; falha em dependências ainda permite tentar riscos. Relatórios antigos ficam em History. |
| Módulo ActiveDirectory ausente | Use Windows PowerShell 5.1 e instale as ferramentas RSAT AD aprovadas pelo processo normal de administração. |
| Falha ao localizar DC ou consultar AD | Confira `-Server`, DNS, conectividade com AD Web Services, identidade atual e relações de confiança. Examine DiscoveryStatus ou RiskQueryStatus. |
| Falha nos grupos do domínio raiz | Verifique conectividade e leitura no domínio raiz. Execute cada domínio separadamente; uma execução não cobre automaticamente toda a floresta. |
| DnsAdmins ausente | O grupo pode não existir nesse domínio. Documente se é aplicável; o script registra a consulta sem resultado. |
| Membros ausentes ou consulta parcial | Verifique limites do ADWS, permissões entre domínios e principais de segurança externos não suportados. As contagens representam somente os membros encontrados até resolver as lacunas. |
| CSV rejeitado | Use o relatório deste toolkit, separado por ponto e vírgula, com SID, DirectoryServer, DomainNetBIOS, SamAccountName, UserPrincipalName e PrivilegedGroup. Não use uma planilha antiga contendo apenas nomes de usuário. Revise um levantamento vazio antes de continuar. |
| Todos os coletores de servidor falham | Verifique o endpoint WinRM Microsoft.PowerShell, firewall, resolução de nomes e autorização. O script não altera TrustedHosts nem autenticação. |
| Acesso negado em um coletor | Verifique permissões delegadas e a política de elevação remota. Não enfraqueça a política de segurança globalmente; teste com identidade administrativa aprovada. |
| Falha em Administradores locais | Confirme endpoint Windows PowerShell de 64 bits e módulo LocalAccounts. Membros órfãos/não resolvidos podem causar falha no comando; examine o alvo manualmente. |
| Administradores locais: NotApplicable | Esperado em controladores de domínio; audite o grupo Builtin Administrators do domínio. |
| IIS: Failed ou NotApplicable | Configuração IIS ausente produz NotApplicable. Configuração existente com problema de módulo/acesso/consulta produz Failed. IIS instalado com zero pools é uma consulta bem-sucedida sem resultados. |
| Processos: Partial | Alguns processos terminaram ou o acesso ao proprietário foi negado. Há visibilidade incompleta, não comprovação de ausência de dependências. |
| Nenhuma dependência correspondente | Revise a situação dos coletores e DependencyInventory. Verifique acesso por grupos, aliases, identidades sem domínio e tipos de aplicação fora do escopo. |
| Coleta demorada | Use lotes menores e omita processos. O tempo limite de operação remota não é um prazo máximo absoluto para toda a coleta. |
| Usuário ausente do relatório de riscos | Revise RiskQueryStatus; a conta pode ter sido excluída, movida entre domínios ou se tornado inacessível desde o levantamento. |
| Planilha mostra uma única coluna | Importe como UTF-8, com ponto e vírgula como separador e colunas de identidade/data como texto. Evite interpretar conteúdo como fórmula. |
| Script bloqueado pela política de execução | Siga o processo de assinatura/desbloqueio da organização após revisar a origem. Não desabilite a política globalmente. |

## Como relatar um problema

Informe o script, versões de Windows/PowerShell, situação do coletor, comportamento esperado e uma reprodução mínima **fictícia**. Remova domínios, usuários, SIDs, nomes de servidores e caminhos de exceções que identifiquem o ambiente. Nunca anexe CSVs de produção, credenciais ou arquivos de clientes a uma issue pública.
