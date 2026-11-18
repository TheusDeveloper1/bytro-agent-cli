<div align="center">

# ▸ Bytro CLI

**Seu projeto. Seu terminal. Uma conversa para começar.**

Agente de programação e chat de IA em Python, com interface Textual.

![Versão](https://img.shields.io/badge/version-1.0.0-A78BFA?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11%2B-7C3AED?style=flat-square)
![Licença](https://img.shields.io/badge/license-GPL--3.0-7C3AED?style=flat-square)
[![GitHub](https://img.shields.io/badge/GitHub-theuzzdeveloper-252336?style=flat-square&logo=github)](https://github.com/theuzzdeveloper)

[Instalação](#instalação) · [Como usar](#como-usar) · [Comandos](#comandos) · [Ferramentas](#ferramentas) · [Atualização](#atualização) · [Estrelas](#histórico-de-estrelas)

</div>

## O que é

O Bytro traz a conversa com uma IA para a pasta do seu projeto. No **Chat**, explica código, responde perguntas e ajuda a planejar. No **Agente**, pode ler arquivos, buscar na web, editar código e executar comandos com sua aprovação.

A interface usa poucos elementos: modelo no topo, conversa no centro e entrada no rodapé. O painel de conversas pode ser ocultado. Em terminais menores, ele se esconde para dar espaço ao texto. Temas claro e escuro usam roxo como destaque.

### O que vem no v2

- Dois modos separados: **Chat** e **Agente**.
- Chat básico com `bytro -c MODELO`, sem painel lateral e sem ferramentas.
- 18 ferramentas para arquivos, Git, sistema, processos e web.
- Aprovação com prévia para edições, exclusões e comandos.
- Botão **■** e **Esc** para cancelar uma solicitação em andamento.
- Conversas locais por pasta, busca por título, renomeação e exportação Markdown.
- API keys cifradas, com cofre nativo ou senha mestra. Também aceita sessão e variáveis de ambiente.
- Versão lida do `pyproject.toml`, SHA256 do aplicativo e atualizações por GitHub Releases.
- Resultados de ferramentas devolvidos ao modelo, bloqueio de chamadas repetidas e tratamento de limite da API.

## Instalação

Requer **Python 3.11 ou mais recente** e um terminal com suporte a Unicode. Para as ferramentas Git, instale também o Git. O aplicativo é Python puro; dependências podem usar wheels próprias para seu sistema.

### Pelo ZIP, com uv

Extraia `bytro-cli-v2.zip`, entre na pasta e execute:

```bash
cd bytro-cli-v2
uv tool install .
uv tool update-shell
```

Reabra o terminal. O comando `bytro` fica disponível no PATH, sem precisar rodar o Python manualmente.

```bash
bytro --version
bytro --setup groq
bytro
```

Se ainda não tiver uv, siga a [instalação oficial](https://docs.astral.sh/uv/getting-started/installation/).

### Com pipx

```bash
cd bytro-cli-v2
pipx install .
pipx ensurepath
```

### Para desenvolver ou rodar da pasta

```bash
python -m venv .venv
```

Ative o ambiente conforme seu shell:

| Shell | Ativação |
| --- | --- |
| Bash / Zsh | `source .venv/bin/activate` |
| Fish | `source .venv/bin/activate.fish` |
| PowerShell | `.venv\Scripts\Activate.ps1` |

Depois:

```bash
python -m pip install .
bytro
```

Com as dependências instaladas, também funciona com `python src/Main.py`.

> Este ZIP é a distribuição desta versão. Os comandos de instalação por PyPI só poderão ser usados depois que o projeto for publicado lá. O repositório precisa receber este código antes de permitir instalação dele diretamente pelo Git.

## Configuração inicial

Na primeira abertura, o Bytro mostra a configuração. Escolha provedor e modelo, cole a chave e escolha como guardá-la. Também dá para abrir esse diálogo diretamente:

```bash
bytro -stp groq
bytro --setup openai
bytro --setup gemini
bytro --setup anthropic
bytro --setup puter
bytro --setup other
```

`antrophic` também é aceito como alias de `anthropic`.

| Provedor | Credencial por ambiente | Integração |
| --- | --- | --- |
| Groq | `GROQ_API_KEY` | Chat Completions + ferramentas |
| OpenAI | `OPENAI_API_KEY` | Chat Completions + ferramentas |
| Gemini | `GEMINI_API_KEY` | Endpoint compatível com OpenAI |
| Anthropic | `ANTHROPIC_API_KEY` | Messages API nativa |
| Puter | `PUTER_AUTH_TOKEN` | Rota nativa `/drivers/call` |
| Other | `BYTRO_API_KEY` | API compatível com Chat Completions |

Os identificadores sugeridos são pontos de partida. A disponibilidade varia conforme a conta e o provedor. Use `bytro --models` ou `/models` para consultar o catálogo; `/model ID` escolhe outro modelo. O catálogo mostra a primeira página retornada pela API, sem garantir listar todos os modelos. O modelo precisa aceitar ferramentas para o modo Agente funcionar.

**Puter:** crie sua conta e um token em [puter.com/dashboard#account](https://puter.com/dashboard#account). Cole o token, não a senha da conta. O Bytro usa a rota nativa, sem depender do endpoint OpenAI compatível que pode exigir assinatura. O uso continua sujeito ao saldo, às regras e aos limites do Puter. Não há promessa de acesso ilimitado.

**Other:** configure a URL base incluindo o prefixo da API, como `http://localhost:11434/v1`. O Bytro permite HTTP apenas em localhost; servidores remotos exigem HTTPS. Servidores locais podem dispensar a API key. Ferramentas dependem do servidor e do modelo escolhidos.

### Como as chaves são guardadas

| Opção | Funcionamento |
| --- | --- |
| Cofre do sistema | Tokens cifrados no arquivo de credenciais; chave mestra no Windows Credential Manager, macOS Keychain, Secret Service ou KWallet. |
| Senha mestra | Tokens cifrados com Fernet; chave derivada da sua senha com Scrypt e salt aleatório. A senha e a chave não são gravadas em disco. |
| Somente sessão | Token fica apenas na memória até fechar o aplicativo. |
| Ambiente | Lê a variável do provedor. Ela tem prioridade sobre a credencial do perfil. |

O Bytro não grava uma chave de descriptografia ao lado do arquivo cifrado. Caso o cofre nativo não esteja disponível, escolha senha mestra ou sessão. A senha mestra deve ter pelo menos 10 caracteres e será pedida nas próximas aberturas. Sem ela, os tokens do arquivo não poderão ser recuperados.

Um arquivo de credenciais usa um único método de armazenamento. Para trocar entre cofre nativo e senha mestra, exporte o que quiser manter e limpe os dados antes de configurar novamente. Perfis diferentes mantêm tokens separados por provedor e URL base.

## Como usar

Abra o Bytro dentro do projeto ou indique a pasta:

```bash
bytro
bytro --workspace ~/Projetos/meu-projeto
bytro --agent
```

O padrão inicial é **Chat**. Clique no botão **Chat/Agente**, pressione **Ctrl+M** ou use `/mode agent` para alternar. O modo escolhido é salvo. Em Chat, nenhuma ferramenta é enviada ao modelo, mesmo que ele tente pedi-las.

Exemplos no modo Agente:

- “Leia o README e explique como rodar este projeto.”
- “Encontre a causa deste erro e proponha uma correção.”
- “Mostre o diff e rode os testes depois da alteração.”
- “Veja o espaço livre do disco e os processos que mais usam memória.”
- “Pesquise a documentação desta biblioteca e confira a página encontrada.”

Edições mostram um diff antes da aprovação. Comandos exibem os argumentos que serão executados. Sem aprovação, a ação retorna como recusada para a IA.

### Chat básico

```bash
bytro -c openai/gpt-oss-120b --provider groq
bytro --chat gpt-4.1-mini --provider openai
bytro -c gemini-2.5-flash --provider gemini --no-history
```

Esse modo mantém só o cabeçalho com versão/modelo, a conversa, o estado da solicitação e a entrada com o botão de envio. Não mostra o painel lateral, a barra de atalhos ou o seletor de modo. As configurações continuam disponíveis com `/setup`.

As respostas aparecem quando a API termina cada etapa. Esta versão não usa streaming de tokens. Enquanto espera, o terminal continua respondendo e a solicitação pode ser cancelada.

### Atalhos

| Atalho | Ação |
| --- | --- |
| Enter | Enviar |
| Esc / botão ■ | Cancelar solicitação; em um diálogo, cancelar ou fechar o diálogo |
| Ctrl+M | Alternar Chat/Agente |
| Ctrl+N | Nova conversa |
| Ctrl+B | Mostrar/ocultar painel |
| Ctrl+F | Buscar conversas por título |
| Ctrl+, | Configurações |
| Ctrl+T | Alternar tema |
| F1 | Ajuda |
| Ctrl+Q | Sair |

Em terminais estreitos, Ctrl+F abre o painel para a busca. Redimensionar o terminal volta a aplicar o layout automático. Conversas são agrupadas pela pasta do projeto. `--no-history` mantém a conversa só na memória, sem ler ou gravar mensagens no banco.

## Comandos

### No terminal

| Comando | Ação |
| --- | --- |
| `bytro` | Interface completa |
| `-v`, `--version` | Versão definida no TOML |
| `-c`, `--chat MODEL` | Chat básico com o modelo escolhido |
| `-stp`, `--setup PROVIDER` | Diálogo de configuração; fecha ao salvar |
| `-cld`, `--clear-data` | Apaga dados do Bytro v2, após confirmação |
| `--clear-data --yes` | Confirma a limpeza sem pergunta interativa |
| `-a`, `--agent` | Inicia em modo Agente |
| `--provider PROVIDER` | Seleciona um perfil de provedor |
| `--model MODEL` | Escolhe o modelo para esta execução |
| `--workspace PATH` | Define a pasta do projeto |
| `--theme dark` / `--theme light` | Define o tema |
| `--no-history` | Conversa temporária |
| `--models` | Consulta modelos |
| `--doctor` | Diagnóstico sem mostrar tokens |
| `--sha256` | Digest do código, TCSS e TOML |
| `--sha256 FILE` | SHA256 dos bytes de um arquivo |
| `--check-update` | Consulta a release mais recente |
| `--update` | Verifica e instala atualização após confirmação |
| `--list-chats` | Lista IDs e títulos de conversas da pasta |
| `--export CHAT_ID` | Exporta conversa salva para a saída do terminal |
| `-h`, `--help` | Ajuda |

Exportação por linha de comando:

```bash
bytro --list-chats
bytro --export ID_DA_CONVERSA > conversa.md
```

`--yes` se aplica apenas à limpeza. Atualizações e ações do Agente continuam pedindo confirmação.

### Dentro da conversa

| Comando | Ação |
| --- | --- |
| `/mode chat`, `/mode agent` | Trocar modo |
| `/model ID`, `/models` | Escolher ou listar modelos |
| `/new`, `/setup`, `/theme` | Nova conversa, configuração e tema |
| `/tools` | Listar ferramentas |
| `/about`, `/hash` | Sobre, GitHub, versão e SHA256 |
| `/update` | Consultar e instalar atualização |
| `/export` | Exportar conversa em Markdown para a pasta do projeto |
| `/help`, `/quit` | Ajuda e saída |

## Ferramentas

| Grupo | Ferramentas |
| --- | --- |
| Leitura | `list_files`, `read_file`, `search_text` |
| Alterações com aprovação | `write_file`, `replace_text`, `make_directory`, `move_file`, `delete_file` |
| Git | `git_status`, `git_diff`, `git_log` |
| Terminal com aprovação | `run_command` |
| Sistema | `system_info`, `disk_usage`, `process_list` |
| Integridade | `sha256` |
| Web | `web_search`, `fetch_url` |

As ferramentas de arquivo ficam dentro da pasta do projeto. Dados do Bytro, `.env*`, `.git`, pastas de credenciais e alguns arquivos de chave conhecidos são bloqueados. A busca ignora dependências e diretórios comuns de cache. Isso não identifica todo arquivo que possa conter informação privada: revise a pasta que está oferecendo ao Agente.

`run_command` usa uma lista de argumentos, sem shell implícito, e exige aprovação em toda chamada. **É execução com os privilégios do seu usuário, sem sandbox.** Um comando aprovado pode alcançar outras pastas, a rede ou iniciar outros programas. O ambiente do processo omite variáveis com nomes que contenham `KEY`, `TOKEN`, `SECRET` ou `PASSWORD`; isso não impede acesso a credenciais por outros meios.

Limites por solicitação: até 6 rodadas de ferramentas, até 18 chamadas e uma etapa final sem ferramentas. Chamadas idênticas são bloqueadas na mesma solicitação. Comandos têm limite de 60 segundos e saída de 64 KB. Cancelar encerra a requisição e o processo direto em execução; no Linux/macOS também encerra seu grupo de processos. No Windows, processos filhos independentes podem continuar. Ações já concluídas não são desfeitas.

A pesquisa web consulta DuckDuckGo e pode encontrar bloqueios ou não retornar resultados. `fetch_url` aceita texto de páginas públicas e rejeita endereços que resolvam para redes privadas. Essas páginas podem conter instruções maliciosas; confira ações propostas pela IA. O Bytro não é um navegador, nem garante acesso a sites com login ou conteúdo renderizado em JavaScript.

## SHA256

```bash
bytro --sha256
bytro --sha256 bytro-cli-v2.zip
```

O primeiro comando calcula um digest estável de `src/Main.py`, `src/ui/app.tcss` e `pyproject.toml`, incluindo seus nomes normalizados e bytes. Ele é igual no código extraído e na wheel correspondente. É exibido também em `/hash` e `/about`.

O ZIP tem **outro digest**, calculado sobre seus próprios bytes. Ele não pode conter dentro dele o hash final de si mesmo. O arquivo `SHA256SUMS` incluído verifica os arquivos extraídos:

```bash
sha256sum -c SHA256SUMS
```

No PowerShell, use `Get-FileHash .\bytro-cli-v2.zip -Algorithm SHA256` para conferir o ZIP.

## Atualização

```bash
bytro --check-update
bytro --update
```

Ou `/update` na conversa. O atualizador consulta a última release estável de [theuzzdeveloper/bytro-agent-cli](https://github.com/theuzzdeveloper/bytro-agent-cli/releases), baixa a wheel e confere o SHA256 publicado antes de pedir confirmação para instalar. Não instala ZIP como programa e não executa scripts baixados diretamente.

Sem release mais recente, informa que não encontrou atualização. Sem wheel e manifesto compatíveis, recusa a instalação. O hash detecta divergência do download em relação à release; não é uma assinatura independente do autor.

### Como publicar uma versão para o atualizador

1. Altere `version` em `pyproject.toml` e atualize o histórico de mudanças.
2. Gere a wheel e o pacote de fontes:

```bash
python -m pip install build
python -m build
```

3. Na pasta `dist`, gere o manifesto dos artefatos:

```bash
cd dist
sha256sum *.whl *.tar.gz > SHA256SUMS
```

4. Crie uma GitHub Release estável com a tag `vX.Y.Z`. Anexe `bytro_cli-X.Y.Z-py3-none-any.whl`, o pacote de fontes e `SHA256SUMS`.

O nome do arquivo no manifesto deve ser só o nome, sem prefixo `dist/`. Esse manifesto de release é diferente do manifesto dos arquivos de código incluído neste ZIP. Na instalação por uv, o atualizador reinstala a ferramenta com a wheel validada; nas demais instalações, usa o pip do interpretador atual. Instalações gerenciadas por pipx podem exigir atualização manual com `pipx install --force <wheel>` se o pip do ambiente não estiver disponível. Depois de atualizar, reabra a CLI.

## Dados e privacidade

Configuração, tokens cifrados e banco de conversas ficam no diretório de dados do usuário definido por `platformdirs`. `bytro --doctor` mostra o caminho. `BYTRO_DATA_DIR` pode apontar para um diretório próprio.

**O histórico de mensagens não é criptografado.** Use `--no-history` para conversas que não devem ser salvas. Arquivos lidos pelo Agente são enviados ao provedor como contexto, dentro dos limites da solicitação. As chamadas usam a conta e a cobrança do provedor escolhido. O código mascara as credenciais carregadas nas saídas das ferramentas e mensagens que salva; isso não substitui revisar o conteúdo antes de compartilhar.

`--clear-data` remove somente arquivos conhecidos do Bytro v2 e sua chave mestra no cofre nativo, quando usada. Não mexe em projetos, exportações, variáveis de ambiente, backups ou dados de versões anteriores. Não há migração automática do MVP para esta versão. Para limpar, feche outras instâncias do Bytro antes de executar o comando.

## Estrutura

```text
bytro-cli-v2/
├── src/
│   ├── Main.py
│   └── ui/
│       └── app.tcss
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
└── SHA256SUMS
```

`Main.py` separa configuração, cofre, histórico, provedores, ferramentas, loop do agente, atualização e interface em classes. O TCSS cuida da aparência. A wheel empacota esse mesmo código em `bytro_cli`, sem alterar a estrutura de desenvolvimento.

## Validação e limites

O código foi verificado com testes automatizados de ferramentas, protocolo dos seis provedores com respostas simuladas, criptografia, histórico, tratamento de 429 e interface Textual em diferentes tamanhos. A instalação e os comandos da wheel também foram verificados. Não foram feitas chamadas pagas a modelos reais, nem instalações de releases futuras. Os cofres nativos e todos os sistemas operacionais não foram validados em máquinas reais nesta entrega.

Não existe garantia de que todo modelo de um provedor aceite ferramentas ou os mesmos parâmetros. Se a API recusar a solicitação, confira modelo, endpoint, permissões e saldo. Use `--doctor` para conferir sua configuração sem mostrar o token.

## Licença

Distribuído sob **GNU GPL v3.0**, conforme [LICENSE](LICENSE). Modificações e redistribuições devem seguir seus termos. Os provedores de IA e suas marcas têm termos próprios.

Criado por [Matheus Nascimento · theuzzdeveloper](https://github.com/theuzzdeveloper).

## Histórico de estrelas

[![Histórico de estrelas](https://api.star-history.com/svg?repos=theuzzdeveloper/bytro-agent-cli&type=Date)](https://www.star-history.com/#theuzzdeveloper/bytro-agent-cli&Date)

O gráfico é carregado pelo serviço Star History e depende dos dados públicos do repositório. Pode demorar para aparecer em projetos novos. Nenhuma contagem de estrelas foi inventada ou embutida no código.
