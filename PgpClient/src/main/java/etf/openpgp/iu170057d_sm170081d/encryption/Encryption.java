/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.iu170057d_sm170081d.encryption;

/**
 *
 * @author User
 */
public class Encryption {
    
    public static enum EncrptionAlgorithm {
        ELGAMAL_IDEA,
        ELGAMAL_3DES,
        NONE
    }
    
    // TODO(Marko): Implement the actual encryption function instead of this
    // stub version
    public static byte[] encrypt(
            byte[] message,
            byte[] senderSignaturePrivateKey,
            byte[] senderConfidentialityPublicKey,
            EncrptionAlgorithm encryptionAlgorithm,
            byte[] senderPassphrase,
            boolean confidentiality,
            boolean signature,
            boolean compression,
            boolean conversionToRadix64) {
        return message.clone();
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
    
    // TODO(Marko): Implement the actual decryption function instead of this
    // stub version
    public static DecryptedMessage decrypt(byte[] message, byte[] senderPublicKey, byte[] receiverPrivateKey) {
        String stubMessageAuthor = "stub-author";
        DecryptedMessage dm = new DecryptedMessage(message, false, false, stubMessageAuthor);
        return dm;
    }
    
}
