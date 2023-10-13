const forge = require('node-forge');

class Server{
    constructor() {
        this.rsaKeyPair = forge.pki.rsa.generateKeyPair(1024);
        this.sessionKey = null;
    }

    getPublicKey() {
        return this.rsaKeyPair.publicKey;
    }

    receiveEncryptedSessionKey(encryptedSessionKey) {
        this.sessionKey = this.rsaKeyPair.privateKey.decrypt(encryptedSessionKey, 'RSA-OAEP');
    }

    receiveEncryptedData(encryptedData, iv) {
        const decipher = forge.cipher.createDecipher('AES-CTR', this.sessionKey);
        decipher.start({iv: iv});
        decipher.update(encryptedData);
        decipher.finish();
        return decipher.output.toString();
    }
}

class Client {
    constructor(serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    generateAndSendSessionKey() {
        const sessionKey = forge.random.getBytesSync(16); // 128 bits
        const encryptedSessionKey = this.serverPublicKey.encrypt(sessionKey, 'RSA-OAEP');
        this.sessionKey = sessionKey;
        return encryptedSessionKey;
    }

    sendEncryptedData(plainText) {
        const iv = forge.random.getBytesSync(16);
        const cipher = forge.cipher.createCipher('AES-CTR', this.sessionKey);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(plainText));
        cipher.finish();
        return { encryptedData: cipher.output, iv: iv };
    }
}

// เฟส 1: Handshake Phase
const server = new Server();
const client = new Client(server.getPublicKey());

const encryptedSessionKey = client.generateAndSendSessionKey();
server.receiveEncryptedSessionKey(encryptedSessionKey);

console.log('Session key: ', forge.util.bytesToHex(server.sessionKey));

// เฟส 2: Data Transfer Phase

const plainText = "Hello, Secure World!";

const { encryptedData, iv } = client.sendEncryptedData(plainText);

console.log('Encrypted data: ', forge.util.bytesToHex(encryptedData));
console.log('IV: ', forge.util.bytesToHex(iv));

const receivedText  = server.receiveEncryptedData(encryptedData, iv);

console.log("Original Message:", plainText);
console.log("Received Message:", receivedText);