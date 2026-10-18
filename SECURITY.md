# Cifra Keyboard: design de segurança

Teclado Android, baseado no Simple Keyboard, que cifra mensagens **dentro do teclado** antes de
qualquer app recebê-las. O app de mensagens ou de e-mail só vê texto cifrado, então a
segurança não depende da criptografia de ponta a ponta (ou da falta dela) desse app.

## Premissas

- **Sem rede.** O APK não declara `INTERNET` (o manifesto remove a permissão mesmo que uma
  biblioteca a peça). As permissões são `VIBRATE`, `USE_BIOMETRIC` (digital ou rosto como
  alternativa ao bloqueio de tela para abrir o cofre) e `CAMERA`, pedida só na primeira leitura
  de um QR code (veja "Celular frio").
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

- `cifra_secrets_v2`: chave AES-256-GCM no Android Keystore, não exportável e em StrongBox
  quando o aparelho tem, que lacra cada chave secreta X25519 (AAD: a chave pública da
  identidade). **Só funciona por 15 segundos depois de uma autenticação** com o bloqueio de
  tela ou uma biometria forte (classe 3). Chaves lacradas pela versão anterior (`v1`, sem essa
  exigência) migram na primeira abertura do cofre.
- `cifra_vault_v1`: lacra o arquivo do cofre (`files/cifra_vault.bin`), com nomes, chaves
  públicas, chaves secretas já lacradas e o estado das conversas da catraca.
- As duas exigem o aparelho desbloqueado (`setUnlockedDeviceRequired`, Android 9+).
- "Apagar todas as chaves" remove o arquivo e as chaves do Keystore. Sem elas, uma cópia do
  arquivo não serve para nada.

O app só usa o cofre com bloqueio de tela configurado: sem PIN, padrão ou senha, o Android não
cria chaves que dependem de autenticação.

## Autenticação a cada abertura

- Tocar no cadeado, em "Ler", abrir "Chaves e contatos" ou criar uma identidade pede o bloqueio
  de tela ou a biometria forte. Como um teclado nunca está em primeiro plano, o pedido é feito
  por uma tela transparente do próprio Cifra (`AuthActivity`).
- O que decide é o Keystore, não a tela: sem autenticação recente, ele se recusa a abrir as
  chaves secretas.
- As chaves secretas ficam na memória só durante a sessão, que termina ao sair do modo seguro,
  ao fechar a leitura, depois de 5 minutos com o teclado escondido ou quando a tela apaga.

## Proteção das chaves no aparelho

Na primeira abertura e a cada atualização do Android, o app testa o chip de segurança com chaves
descartáveis: cria ou importa uma chave, pede a troca de chaves ao Keystore e confere o resultado
contra o mesmo cálculo em software. O resultado aparece em "Chaves e contatos". Quando o chip não
suporta um tipo de chave, o Android cai para software sem avisar; o teste confere onde cada chave
realmente ficou.

## Chaves públicas

- Formato: Bech32 (BIP173) com prefixo `cifra`, por exemplo `cifra1qv…` (64 caracteres). O
  checksum detecta erros de digitação e o alfabeto evita caracteres ambíguos.
- Impressão digital: `SHA-256("cifra/fingerprint/v1" || pk)`, mostrada como 6 grupos de 5
  dígitos (cerca de 99 bits), no estilo dos números de segurança do Signal. Ela é igual em
  qualquer idioma e serve para conferir a chave por ligação ou pessoalmente.
- Contatos começam como "não verificado". O usuário marca como verificado depois de comparar a
  impressão digital.

## Formato clássico (v1)

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
- **Sem sigilo futuro:** todas as mensagens enviadas a uma identidade dependem da mesma chave
  fixa. O usuário escolhe esse modo conscientemente; o padrão é a catraca.

## Formato da catraca (v2)

Double Ratchet com cabeçalho cifrado, seguindo a especificação do Signal, adaptado a um app sem
servidor:

- **Início da conversa:** `DH(identidade de quem inicia, identidade do contato)` gera a chave raiz
  e as chaves de cabeçalho da primeira corrente (HKDF-SHA256, `info` com as duas chaves públicas
  na ordem iniciador e respondente). A chave fixa do contato faz o papel da primeira chave de
  catraca dele, no lugar da chave temporária que um servidor forneceria.
- **A cada resposta,** quem responde sorteia um par X25519 novo; a chave raiz é misturada com a
  troca entre as chaves temporárias, e a chave temporária anterior é apagada.
- **Cada mensagem** usa uma chave tirada de uma corrente HMAC-SHA256 que só anda para a frente;
  a chave usada é apagada.
- **Cabeçalho cifrado:** chave temporária pública, contador e tamanho da corrente anterior vão
  cifrados (ChaCha20-Poly1305 com nonce aleatório). A mensagem não carrega identificador; o
  destinatário testa as chaves de cabeçalho das conversas abertas.

```
wire = "CF" 0x02 || nonce (12) || cabeçalho cifrado (40 + 16) || corpo cifrado
corpo: ChaCha20-Poly1305, chave e nonce = HKDF(chave da mensagem), AAD = prefixo || cabeçalho
```

Propriedades e limites:

- **Sigilo futuro e recuperação:** depois da primeira resposta, nenhuma mensagem depende só das
  chaves fixas. Quem roubar as palavras ou copiar o estado do aparelho não abre mensagens já
  lidas, e perde o acesso na próxima troca de catraca.
- **Primeira corrente:** até o contato responder, as mensagens dependem das chaves fixas; quem
  obtiver as palavras de quem **recebe** consegue abri-las.
- **Ordem e perdas:** até 50 mensagens puladas por corrente; as chaves delas ficam guardadas por
  7 dias.
- **Releitura:** por padrão, a chave é queimada na leitura. Em "Chaves e contatos" dá para manter
  por 1, 12 ou 24 horas.
- **Aparelho novo:** o estado da catraca não volta com as palavras. A primeira mensagem do
  aparelho novo começa uma conversa nova, e o outro lado é avisado.
- **Estado salvo antes de enviar:** o estado avança e é gravado antes de o texto cifrado sair,
  para nunca reutilizar uma chave de mensagem.

## Fluxo no teclado

1. **Cadeado (canto esquerdo da barra):** escolhe o contato e, numa conversa nova, o modo
   (catraca ou clássico, com o risco explicado). A partir daí, todas as teclas vão para um
   rascunho dentro do teclado. O campo de texto do app não recebe nada, nem texto em composição.
2. **Cifrar:** gera a mensagem, mostra o texto cifrado e só insere no app após "Inserir no app".
   O modo seguro continua ativo para a próxima mensagem. Para sair, toque de novo no cadeado.
3. **Ler (aparece quando há mensagem cifrada na área de transferência):** no formato clássico,
   pergunta qual chave privada usar (se houver mais de uma); na catraca, a conversa já sabe.
   Mostra o texto decifrado só no teclado, sem opção de copiar, junto com o modo e os avisos
   (primeira mensagem, releitura, conversa reiniciada). "Responder" abre o modo seguro já com o
   remetente como destinatário.
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

## Celular frio (QR codes)

Opcional, desligado por padrão ("Botão de QR code no teclado"). As identidades ficam num celular
que nunca fica online; o celular com internet não guarda chaves e só transporta texto cifrado. Na
"Área de escrita" do celular frio as opções de QR aparecem mesmo com o botão desligado, e na
prévia "Mostrar QR code" substitui "Inserir no app". Ali o limite de tamanho é conferido antes de
cifrar, para uma mensagem que não cabe num QR code não gastar uma chave da catraca.

- **O texto aberto nunca passa pelo celular com internet.** A mensagem é escrita e cifrada no
  celular frio, e lida e decifrada nele também. Diferente do PSBT do Bitcoin, onde o celular
  online monta uma transação que é pública de qualquer jeito, aqui o conteúdo é o próprio
  segredo: digitá-lo no celular online o exporia a quem controlar esse aparelho, e um QR code com
  texto aberto pode ser lido por qualquer câmera por perto. Por isso só passam por QR o texto
  cifrado e as chaves públicas.
- **Enviar:** no celular frio, a "Área de escrita" é só um campo de texto para abrir o teclado.
  No modo seguro, depois de cifrar, "Mostrar QR code" mostra a mensagem no próprio teclado, que
  cresce para o código caber, com brilho máximo enquanto ele aparece. O rascunho é apagado como em
  "Inserir no app". No celular com internet, o botão de QR do teclado lê o código e insere a
  mensagem na conversa.
- **Sem janelas separadas:** os códigos aparecem no teclado, não numa tela própria. A câmera é
  uma tela, porque o Android não deixa um teclado usá-la sozinho: na área de escrita ela abre
  dentro do app; dentro de outro app (o de conversa, no celular com internet) ela precisa de uma
  tarefa separada, como a tela de autenticação.
- **Ler:** o celular com internet mostra como QR code a mensagem cifrada copiada; o celular frio
  lê e decifra com o fluxo normal, que pede a autenticação do cofre.
- **Formato:** a mensagem vai em binário (o mesmo conteúdo da armadura, sem Base64), num único QR
  code de até versão 20 (97 × 97 módulos), com correção de erro L. Cabem 858 bytes: mensagens de
  até 764 bytes de texto, nos dois formatos. Chaves públicas vão como texto `cifra1...`.
- **Câmera:** usa a API nativa (Camera2) e a ZXing (Java puro), sem bibliotecas de câmera nem
  serviços do Google. Só o quadrado central de cada quadro é analisado, na memória, e nada é
  gravado. A tela da câmera usa `FLAG_SECURE`, como a janela do teclado.
- **Modo avião:** se um celular com identidades mostrar ou ler um QR code fora do modo avião, o
  teclado ou a câmera avisa. O app não vê Wi-Fi nem Bluetooth: isso exigiria a permissão de estado da rede, que o
  Cifra remove de propósito.
- **Contatos por QR:** a tela da identidade mostra a chave pública como QR code, e "Adicionar
  contato" pode ler o código do outro celular. Ler pessoalmente o código da outra pessoa
  equivale a conferir a impressão digital.

## Limites conhecidos

- **Aparelho comprometido:** root, malware com privilégios ou um teclado de terceiros usado
  para digitar as palavras anulam estas proteções. Digite as palavras com o próprio Cifra.
- **Modo clássico e primeira corrente da catraca:** quem obtiver a chave secreta de uma identidade
  (ou as palavras e a passphrase) lê as mensagens que dependem só das chaves fixas. Nesses casos,
  quem tiver a sua chave secreta também pode forjar mensagens "de" qualquer contato para você
  (KCI).
- **Estado da catraca:** fica no cofre, lacrado por `cifra_vault_v1`, que não exige autenticação
  recente; quem rodar código como o app num aparelho desbloqueado lê as mensagens seguintes até a
  próxima troca de catraca.
- **Apagar do armazenamento flash** não é garantido: versões antigas do arquivo do cofre podem
  sobrar em blocos não sobrescritos, lacradas pelo Keystore.
- **Memória:** strings Java são imutáveis. O texto digitado e decifrado é zerado onde o código
  controla (rascunho, buffers de bytes), mas cópias temporárias podem ficar na memória até o
  coletor de lixo agir.
- **Metadados:** o app de mensagens continua sabendo quem fala com quem e quando, só não sabe o
  conteúdo.
- **Leitor de tela:** com a opção padrão, o modo seguro não funciona com TalkBack. Ligando a
  opção num Android anterior ao 14, qualquer serviço de acessibilidade lê o modo seguro.
- **Metadados do sistema:** o Android registra quando o teclado abre e fecha, em qual app, e cada
  vez que o Cifra lê a área de transferência (data e hora, sem conteúdo). O app não controla isso.
- **Celular frio:** só protege enquanto ficar realmente offline, e sem outros apps que possam
  ler a tela ou o teclado. Ler um QR code é ler dados de fora: a ZXing decodifica imagens da
  câmera, e o Cifra só aceita o resultado se for uma mensagem ou chave válida. Mensagens maiores
  que um QR code (764 bytes) ainda não têm uma sequência de códigos.
- **Build de debug:** é depurável. Por USB, alguém pode rodar código como o app e pedir ao Keystore
  que abra o cofre. Para uso real, só o build de release.

## Testes

`./gradlew :app:testDebugUnitTest` cobre os vetores BIP39 da Trezor, os vetores Bech32 do
BIP173, cifrar e decifrar, remetente ou destinatário errado, adulteração, padding, armadura
mutilada por apps de chat, chaves públicas de ordem baixa, o formato da impressão digital e, na
catraca: conversa nos dois sentidos, mensagens fora de ordem e perdidas, limite de perdas,
releitura com e sem prazo, primeira mensagem repetida, sigilo futuro com estado roubado,
aparelho novo, início simultâneo dos dois lados e o estado salvo e restaurado no cofre. Nos QR
codes: ida e volta do maior conteúdo na versão 20, o limite de tamanho, a mensagem mais longa nos
dois formatos, armadura em texto, chave pública e códigos que não são do Cifra.
