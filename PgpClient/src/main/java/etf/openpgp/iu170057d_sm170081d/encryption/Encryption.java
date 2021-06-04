package etf.openpgp.iu170057d_sm170081d.encryption;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

public class Encryption
{

    public static enum EncryptionAlgorithm
    {
        ELGAMAL_3DES(PGPEncryptedData.TRIPLE_DES),
        ELGAMAL_IDEA(PGPEncryptedData.IDEA),
        NONE(PGPEncryptedData.NULL);

        public final int id;
        
        private EncryptionAlgorithm(int id)
        {
            this.id = id;
        }
    }

    public static class DecryptedMessage
    {
        public final byte[] decryptedMessage;
        public final boolean messageIntegrity;
        public final boolean messageSigned;
        public final String messageAuthor;

        public DecryptedMessage(
                byte[] decryptedMessage,
                boolean messageIntegrity,
                boolean messageSigned,
                String messageAuthor )
        {
            this.decryptedMessage = decryptedMessage;
            this.messageIntegrity = messageIntegrity;
            this.messageSigned = messageSigned;
            this.messageAuthor = messageAuthor;
        }
    }

    public static byte[] encrypt(
            byte[] plaintext,
            PGPSecretKey senderSecretKey,
            PGPPublicKey receiverPublicKey,
            EncryptionAlgorithm encryptionAlgorithm,
            char[] senderPassphrase,
            boolean addSignature,
            boolean addCompression,
            boolean addConversionToRadix64 )
    {
        JcePGPDataEncryptorBuilder ciphertextBuilder = new JcePGPDataEncryptorBuilder( encryptionAlgorithm.id );
        ciphertextBuilder.setSecureRandom( new SecureRandom() );
        ciphertextBuilder.setWithIntegrityPacket( true );
        ciphertextBuilder.setProvider( "BC" );
        
        PGPEncryptedDataGenerator ciphertextGenerator = new PGPEncryptedDataGenerator( ciphertextBuilder );
        
        // TODO(Marko): Implement

        PGPLiteralDataGenerator g;
        PGPCompressedDataGenerator g1;
        
        
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream( plaintext.length*4/3 );

        return ciphertext.toByteArray();
    }

    public static DecryptedMessage decrypt(
            byte[] message,
            char[] receiverPassphrase )
    {
        // TODO(Marko): Implement -- only encrypted files need to be decrypted here

        String stubMessageAuthor = "stub-author";
        DecryptedMessage dm = new DecryptedMessage( message, false, false, stubMessageAuthor );
        return dm;
    }
}
