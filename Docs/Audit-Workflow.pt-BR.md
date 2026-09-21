# Fluxo de auditoria

[English](Audit-Workflow.md) | [Início em português](../README.pt-BR.md) | [Guia rápido](Guia-Rapido.pt-BR.md)

1. **Defina o escopo.** Registre fora do repositório os domínios e servidores autorizados, contatos dos responsáveis, restrições de manutenção e limites de revisão. Separe as pastas por domínio e execução. Primeiro confirme leitura e execução remota em um alvo de laboratório.
2. **Levante os privilégios.** Execute `Get-PrivilegedUsers.ps1`. Inclua grupos administrativos personalizados com `-AdditionalGroup`. Revise todos os grupos com falha/cobertura parcial e os principais de segurança não suportados. Resolva as lacunas ou documente as exclusões antes de usar a lista.
3. **Localize dependências.** Informe o CSV do levantamento e a lista explícita de nomes completos dos servidores (FQDNs) ao `Get-PrivilegedAccountDependencies.ps1`. Comece com poucos servidores. Inclua processos apenas quando necessário. Examine a situação da coleta antes das correspondências e revise manualmente o inventário sem correspondência, grupos administrativos locais e grupos usados por tarefas.
4. **Avalie os riscos.** Execute `Get-PrivilegedAccountRisks.ps1`. Consulte RiskQueryStatus para identificar contas que não puderam ser avaliadas. Os indicadores incluem usuários privilegiados desabilitados, logon replicado antigo/ausente, data de senha antiga/ausente, configurações de senha, pré-autenticação desabilitada, delegação, ausência de AccountNotDelegated, SPNs e histórico de SIDs. Valide cada indicador conforme a finalidade da conta e os controles compensatórios. SPNs e histórico de SIDs podem ser legítimos; o toolkit não calcula explorabilidade nem pontuação automática de risco.
5. **Confirme a necessidade de negócio.** Peça ao responsável pelo serviço/aplicação a validação das dependências e dos privilégios. Verifique tarefas mensais, serviços parados, recuperação de desastres e aplicações externas. A ausência em uma coleta pontual não basta para justificar remoção.
6. **Planeje as correções separadamente.** Registre aprovação, identidade substituta, plano de reversão e validação. Avalie identidades de serviço gerenciadas suportadas, contas administrativas humanas separadas e grupos com menor privilégio. O toolkit não executa correções. Não desabilite uma conta nem altere sua senha somente por um indicador no relatório.
7. **Valide e retenha.** Depois de alterações aprovadas, repita a auditoria em nova pasta e teste as aplicações afetadas. Compare pelo SID do usuário e do grupo de origem, não pelo nome de exibição. Preserve os relatórios de cobertura junto aos resultados e descarte conforme a política de retenção.

## Execução prática

Use `Get-Help .\Scripts\Get-PrivilegedUsers.ps1 -Full` para consultar a ajuda do script. Uma lista local de servidores em arquivo texto pode ser lida com `Get-Content` e passada para `-ComputerName`; não versione essa lista. A autenticação integrada do Windows é o padrão. Credenciais opcionais de acesso aos servidores permanecem em memória e não são exportadas.

O scanner cria uma sessão remota por alvo, processa os servidores sequencialmente e fecha as sessões em `finally`. `-OperationTimeoutSeconds` controla o tempo limite de operação da comunicação remota, não um prazo total garantido para cada coletor. Evite lotes muito grandes.

## Validação antes de produção

- Em um domínio descartável, crie associações diretas, grupos aninhados, um ciclo e uma associação por grupo primário. Verifique uma linha por usuário/grupo privilegiado de origem, a classificação e as contagens.
- Valide consultas ao domínio raiz e a membros de outros domínios; confirme que principais externos não suportados aparecem como lacunas de cobertura.
- Configure em laboratório um serviço, uma tarefa e um pool IIS SpecificUser com uma identidade privilegiada fictícia de teste. Inclua recursos parados/desabilitados. Confirme as correspondências e a ausência de correspondência com um usuário local de mesmo nome.
- Teste um administrador local direto e um grupo AD adicionado a Administradores locais. Confirme que o grupo permanece no inventário para expansão fora do scanner.
- Negue acesso a um coletor, use um servidor inacessível e remova um módulo IIS em um alvo IIS de laboratório. Confirme que falhas são distintas de consultas bem-sucedidas sem resultados e de NotApplicable.
- Teste a negação de acesso ao proprietário de processos e processos encerrados durante a consulta; espere cobertura Partial. Verifique que a coleta de processos não solicitada aparece explicitamente como ignorada.

A suíte de testes sem rede não comprova validação em ambiente real.
