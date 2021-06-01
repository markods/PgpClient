/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.iu170057d_sm170081d.encryption;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author User
 */
public class Encryption {
    
    public static enum SymmetricEncryptionAlgorithm {
        ELGAMAL_IDEA,
        ELGAMAL_3DES,
        NONE
    }
    
    public static enum AsymmetricEncryptionAlgorithm {
        ELGAMAL,
        DSA
    }
    
    public static class DecryptedMessage {
        public final byte[] decryptedMessage;
        public final boolean messageIntegrity;
        public final boolean messageSigned;
        public final String messageAuthor;
        
        public DecryptedMessage(
                byte[] decryptedMessage,
                boolean messageIntegrity,
                boolean messageSigned,
                String messageAuthor) {
            this.decryptedMessage = decryptedMessage;
            this.messageIntegrity = messageIntegrity;
            this.messageSigned = messageSigned;
            this.messageAuthor = messageAuthor;
        }
    }
    
    public static class PublicPrivateKeyPair {
        public final byte[] privateKey;
        public final byte[] publicKey;
        
        public PublicPrivateKeyPair(byte[] privateKey, byte[] publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }
    
    // TODO(Marko): Implement the actual encryption function instead of this
    // stub version
    public static byte[] encrypt(
            byte[] message,
            PGPSecretKey senderSecretKey,
            PGPPublicKey receiverPublicKey,
            SymmetricEncryptionAlgorithm encryptionAlgorithm,
            char[] senderPassphrase,
            boolean addSignature,
            boolean addCompression,
            boolean addConversionToRadix64) {
        return message.clone();
    }

    // TODO(Marko): Implement the actual decryption function instead of this
    // stub version
    public static DecryptedMessage decrypt(
            byte[] message,
            char[] receiverPassphrase) {
        String stubMessageAuthor = "stub-author";
        DecryptedMessage dm = new DecryptedMessage(message, false, false, stubMessageAuthor);
        return dm;
    }
    
    public static PublicPrivateKeyPair generateKeyPair(
            AsymmetricEncryptionAlgorithm encryptionAlgorithm,
            byte[] passphrase) {
        PublicPrivateKeyPair kp = new PublicPrivateKeyPair(
                Hex.decode("e04fd020ea3a6910a2d808002b30309d"),
                Hex.decode("e04fd020ea3a6910a2d808002b30309d"));
        return kp;
    }   
}
