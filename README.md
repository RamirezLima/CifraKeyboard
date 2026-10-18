# Cifra Keyboard

Teclado Android que cifra suas mensagens antes de qualquer app recebê-las, para que a privacidade
das suas conversas não dependa da criptografia de ponta a ponta (ou da falta dela) do app de
mensagens ou de e-mail.

> **O Cifra Keyboard é um fork do [Simple Keyboard](https://github.com/rkkr/simple-keyboard)**, de
> Raimondas Rimkus e colaboradores, que por sua vez é baseado no teclado
> [LatinIME do Android Open Source Project](https://android.googlesource.com/platform/packages/inputmethods/LatinIME/).
> O teclado em si (layouts, idiomas, temas, gestos) vem do Simple Keyboard; o Cifra acrescenta a
> camada de criptografia. Este projeto não é afiliado nem endossado pelos autores do Simple
> Keyboard.

**Atenção:** o Cifra está em desenvolvimento e ainda não passou por auditoria de segurança
independente. Não confie nele para proteger informações das quais dependa a segurança de alguém.

## O que o Cifra faz

- **Modo seguro.** Toque no cadeado, escolha o contato e escreva. O texto fica num rascunho dentro
  do teclado; o app só recebe o texto cifrado, e só depois que você aprova.
- **Leitura.** Copie a mensagem cifrada recebida. O teclado mostra o botão Ler e exibe o texto
  decifrado apenas na própria janela, sem opção de copiar.
- **Identidades a partir de palavras BIP39.** 12 ou 24 palavras da lista oficial em inglês e uma
  passphrase opcional. As palavras nunca são gravadas: elas são o seu backup.
- **Chaves protegidas pelo Android Keystore**, em StrongBox quando o aparelho tem.
- **Sem internet, sem backup e sem capturas de tela** da janela do teclado.

O design, o formato das mensagens e os limites conhecidos estão em [SECURITY.md](SECURITY.md). O
que o app guarda e o que não guarda está em [PRIVACY.md](PRIVACY.md).

## Herdado do Simple Keyboard

- Altura do teclado ajustável
- Linha de números
- Deslizar no espaço para mover o cursor e na tecla apagar para apagar
- Cores de tema personalizadas
- Dezenas de idiomas e layouts

## O que muda em relação ao Simple Keyboard

| | Simple Keyboard | Cifra Keyboard |
|---|---|---|
| ID do app | `rkr.simplekeyboard.inputmethod` | `org.cifra.keyboard` (os dois podem ser instalados juntos) |
| Criptografia | não tem | modo seguro, identidades BIP39, HPKE |
| Teclado na tela com teclado físico conectado | desligado por padrão | ligado por padrão |
| Backup do Android | ligado | desligado |
| Política de privacidade e licença | abrem páginas no GitHub | exibidas no próprio app |
| Tamanho do APK | menos de 1 MB | cerca de 2 MB (inclui o Bouncy Castle) |

O código Java mantém o pacote original `rkr.simplekeyboard.inputmethod`, para facilitar acompanhar
as atualizações do Simple Keyboard. O que é do Cifra fica em
[`crypto/`](app/src/main/java/rkr/simplekeyboard/inputmethod/crypto/).

## Compilar e testar

Abra o projeto no Android Studio e use **Run**, ou, com o Gradle 9.6 instalado:

```bash
gradle :app:assembleDebug
gradle :app:testDebugUnitTest
```

## Licença e créditos

Licenciado sob a [Licença Apache 2.0](LICENSE), a mesma do projeto original. Os avisos de
atribuição e as licenças de terceiros estão em [NOTICE](NOTICE).

- [Simple Keyboard](https://github.com/rkkr/simple-keyboard): Raimondas Rimkus e colaboradores,
  Apache 2.0
- [LatinIME](https://android.googlesource.com/platform/packages/inputmethods/LatinIME/): The Android
  Open Source Project, Apache 2.0
- [Bouncy Castle](https://www.bouncycastle.org): MIT
- [Lista de palavras BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): MIT
- Ícones Material: Apache 2.0

Os arquivos do Simple Keyboard alterados neste fork mantêm os avisos de copyright originais e
trazem também a linha `Copyright (C) 2026 Ramirez Lima`.
