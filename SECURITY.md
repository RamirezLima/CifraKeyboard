# Cifra Keyboard: design de segurança

Teclado Android, baseado no Simple Keyboard, que cifra mensagens **dentro do teclado** antes de
qualquer app recebê-las. O app de mensagens ou de e-mail só vê texto cifrado, então a
segurança não depende da criptografia de ponta a ponta (ou da falta dela) desse app.

## Premissas

- **Sem rede.** O APK não declara `INTERNET` (o manifesto remove a permissão mesmo que uma
  biblioteca a peça). A única permissão é `VIBRATE`.
- **Sem capturas.** A janela do teclado, as configurações, a tela de identidade e todos os
  diálogos usam `FLAG_SECURE`: não aparecem em screenshots, gravações, espelhamento, na prévia de
  recentes nem para o assistente. Diálogos são janelas próprias e não herdam a flag da tela, então
  cada um a recebe explicitamente.
- **Sem rastros em logs.** O app não registra texto digitado, posições de cursor nem tamanhos de
  texto, e o build de release remove todos os logs informativos (`Log.v/d/i`). Num teste completo
  (cifrar, inserir, copiar, decifrar), o texto não apareceu no logcat, no `dumpsys` nem nos
  relatórios de erro do sistema.
- **Sem backup.** `allowBackup="false"` e regras de extração excluindo tudo.
- **O app só recebe texto cifrado,** e só depois de o usuário ver o resultado e tocar em
  "Inserir no app". Mensagens decifradas aparecem apenas na janela do teclado.

## Identidades (BIP39)

1. O usuário digita 12 a 24 palavras da lista BIP39 oficial em inglês ou gera novas com
   `SecureRandom`. As listas em outros idiomas não são aceitas: a própria comunidade
   desaconselha o uso delas, e quase nenhuma outra ferramenta as suporta, o que tornaria o
   backup frágil. Ao gerar, precisa redigitar duas palavras sorteadas para provar que anotou.
2. `seed = PBKDF2-HMAC-SHA512(NFKD(palavras), "mnemonic" + NFKD(passphrase), 2048)` (BIP39 padrão,
   validado com os vetores oficiais da Trezor).
3. `ikm = HMAC-SHA512("cifra/identity/v1", seed)` separa o domínio de outros usos da mesma seed.
4. `(sk, pk) = DeriveKeyPair(ikm)` do HPKE (RFC 9180) para X25519.

Cada passphrase gera uma identidade sem relação com as outras. Isso permite manter identidades
separadas a partir das mesmas palavras.

**As palavras e a passphrase nunca são gravadas.** Elas são o backup: com elas a identidade é
recriada em qualquer aparelho.

## Chaveiro (Android Keystore)

- Uma chave AES-256-GCM no Android Keystore, não exportável e em StrongBox quando o aparelho
  tem, cifra cada chave secreta X25519. O AAD é a chave pública da identidade.
- Uma segunda chave do Keystore cifra o arquivo do cofre (`files/cifra_vault.bin`), com nomes,
  chaves públicas e as chaves secretas já cifradas.
- As duas chaves exigem o aparelho desbloqueado (`setUnlockedDeviceRequired`, Android 9+).
- A chave secreta só é decifrada durante uma operação de cifrar ou decifrar e é zerada logo
  depois.
- "Apagar todas as chaves" remove o arquivo e as chaves do Keystore. Sem elas, uma cópia do
  arquivo não serve para nada.

O Android Keystore não consegue fazer X25519 com chaves importadas em todas as versões
suportadas (minSdk 24). Por isso ele sela as chaves em vez de executar o ECDH.

## Chaves públicas

- Formato: Bech32 (BIP173) com prefixo `cifra`, por exemplo `cifra1qv…` (64 caracteres). O
  checksum detecta erros de digitação e o alfabeto evita caracteres ambíguos.
- Impressão digital: `SHA-256("cifra/fingerprint/v1" || pk)`, mostrada como 6 grupos de 5
  dígitos (cerca de 99 bits), no estilo dos números de segurança do Signal. Ela é igual em
  qualquer idioma e serve para conferir a chave por ligação ou pessoalmente.
- Contatos começam como "não verificado". O usuário marca como verificado depois de comparar a
  impressão digital.

## Formato da mensagem (v1)

```
HPKE modo Auth, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305
info = "cifra/msg/v1"
aad  = cabeçalho

wire      = "CF" 0x01 || enc (32 bytes) || ciphertext
plaintext = tamanho (uint32 BE) || texto UTF-8 || zeros até múltiplo de 256 bytes
```

Em texto, a mensagem vai em Base64 entre `-----BEGIN CIFRA MESSAGE-----` e
`-----END CIFRA MESSAGE-----`. O leitor ignora quebras de linha, espaços e marcas de citação
(`>`) que apps de chat e e-mail costumam inserir.

- **Autenticação do remetente sem assinatura:** o modo Auth do HPKE prova ao destinatário que a
  mensagem veio de quem tem a chave secreta do contato. Como não há assinatura, o destinatário
  não consegue provar isso a terceiros, o que preserva a negação plausível.
- **Sem identificadores de chave:** o texto cifrado não diz quem enviou nem para quem. O
  destinatário testa os contatos conhecidos (e as próprias identidades, para notas para si).
  Consequência: para ler uma mensagem, o remetente precisa estar nos contatos.
- **Padding** em blocos de 256 bytes esconde o tamanho exato do texto.

## Fluxo no teclado

1. **Cadeado (canto esquerdo da barra):** escolhe o contato. A partir daí, todas as teclas vão
   para um rascunho dentro do teclado. O campo de texto do app não recebe nada, nem texto em
   composição.
2. **Cifrar:** gera a mensagem, mostra o texto cifrado e só insere no app após "Inserir no app".
   O modo seguro continua ativo para a próxima mensagem. Para sair, toque de novo no cadeado.
3. **Ler (aparece quando há mensagem cifrada na área de transferência):** pergunta qual chave
   privada usar (se houver mais de uma) e mostra o texto decifrado só no teclado, sem opção de
   copiar. "Responder" abre o modo seguro já com o remetente como destinatário.
4. Ao esconder o teclado, a mensagem decifrada é apagada da tela na hora. Um rascunho é
   descartado após 5 minutos com o teclado escondido.
5. Serviços de acessibilidade são um canal comum de spyware. Por padrão, rascunho, texto
   decifrado e nomes de contatos no teclado ficam ocultos de **todos** os serviços de
   acessibilidade, inclusive o TalkBack: o texto é retirado das informações entregues a eles e
   os eventos de mudança de texto são descartados. Marcar as views como "não importantes" ou
   "sensíveis" não bastaria, porque alguns serviços ainda conseguem lê-las.
   A opção "Permitir leitor de tela no modo seguro" libera o acesso. No Android 14+ as views
   continuam marcadas como `accessibilityDataSensitive`, e só ferramentas de acessibilidade
   reconhecidas pelo sistema as leem; antes do Android 14, qualquer serviço instalado lê.

## Limites conhecidos

- **Aparelho comprometido:** root, malware com privilégios ou um teclado de terceiros usado
  para digitar as palavras anulam estas proteções. Digite as palavras com o próprio Cifra.
- **Sem sigilo futuro (forward secrecy):** quem obtiver a chave secreta de uma identidade (ou as
  palavras e a passphrase) lê todas as mensagens antigas enviadas a ela. O modo Auth do HPKE
  também não resiste a KCI: quem tiver a sua chave secreta pode forjar mensagens "de" qualquer
  contato para você.
- **Memória:** strings Java são imutáveis. O texto digitado e decifrado é zerado onde o código
  controla (rascunho, buffers de bytes), mas cópias temporárias podem ficar na memória até o
  coletor de lixo agir.
- **Metadados:** o app de mensagens continua sabendo quem fala com quem e quando, só não sabe o
  conteúdo.
- **Sem bloqueio de tela:** sem PIN ou senha no aparelho, quem estiver com ele desbloqueado usa
  as chaves. As configurações mostram um aviso nesse caso.
- **Leitor de tela:** com a opção padrão, o modo seguro não funciona com TalkBack. Ligando a
  opção num Android anterior ao 14, qualquer serviço de acessibilidade lê o modo seguro.
- **Metadados do sistema:** o Android registra quando o teclado abre e fecha, em qual app, e cada
  vez que o Cifra lê a área de transferência (data e hora, sem conteúdo). O app não controla isso.
- **Build de debug:** é depurável. Por USB, alguém pode rodar código como o app e pedir ao Keystore
  que abra o cofre. Para uso real, só o build de release.

## Testes

`./gradlew :app:testDebugUnitTest` cobre os vetores BIP39 da Trezor, os vetores Bech32 do
BIP173, cifrar e decifrar, remetente ou destinatário errado, adulteração, padding, armadura
mutilada por apps de chat, chaves públicas de ordem baixa e o formato da impressão digital.
