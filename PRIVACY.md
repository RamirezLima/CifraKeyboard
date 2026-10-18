# Privacidade do Cifra Keyboard

O Cifra Keyboard não tem permissão de internet e não envia nada a lugar nenhum: sem estatísticas,
sem relatórios de erro, sem anúncios.

Somente neste aparelho, ele guarda:

- **suas identidades:** nome, chave pública e a chave privada lacrada pelo Android Keystore;
- **seus contatos:** nome e chave pública;
- **as conversas no modo catraca:** as chaves em uso, as chaves de mensagens que ainda não
  chegaram (por até 7 dias) e, se "Reler mensagens" estiver ligado, as chaves das mensagens já
  lidas até o prazo acabar. Tudo isso fica lacrado pelo Android Keystore. Enquanto a chave de uma
  mensagem existir, essa mensagem cifrada pode ser aberta de novo neste aparelho;
- **as configurações do teclado** e o resultado do diagnóstico em "Proteção das chaves neste
  aparelho".

Ele nunca guarda suas palavras BIP39, sua passphrase nem o texto das mensagens que você escreve ou
decifra. Ele lê a área de transferência só no aparelho, para encontrar mensagens cifradas.

Se você ligar o botão de QR code (para usar um celular frio), a câmera é usada só enquanto um
código é lido: as imagens são analisadas na memória, uma por vez, e nunca gravadas.

O backup do Android está desligado. "Apagar todas as chaves" remove identidades, contatos e
conversas; desinstalar o app remove tudo.

---

# Cifra Keyboard privacy

Cifra Keyboard has no internet permission and sends nothing anywhere: no analytics, no crash
reports, no ads.

Only on this device, it keeps:

- **your identities:** name, public key and the private key sealed by the Android Keystore;
- **your contacts:** name and public key;
- **your ratchet conversations:** the keys in use, the keys of messages that have not arrived yet
  (for up to 7 days) and, if "Read messages again" is on, the keys of messages already read until
  that time runs out. All of it is sealed by the Android Keystore. While the key of a message
  exists, that encrypted message can be opened again on this device;
- **the keyboard settings** and the result of the check in "Key protection on this device".

It never stores your BIP39 words, your passphrase, or the text of the messages you write or
decrypt. It reads the clipboard only on this device, to find encrypted messages.

If you turn on the QR code button (to use a cold phone), the camera is only used while a code is
being read: frames are looked at in memory, one at a time, and never stored.

Android backup is disabled. "Erase all keys" deletes identities, contacts and conversations;
uninstalling the app deletes everything.
