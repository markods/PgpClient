package etf.openpgp.iu170057d_sm170081d.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class Encryption
{
    static
    {
        if( Security.getProvider( "BC" ) == null )
        {
            Security.addProvider( new BouncyCastleProvider() );
        }
    }

    public static enum EncryptionAlgorithm
    {
        ELGAMAL_3DES( PGPEncryptedData.TRIPLE_DES ),
        ELGAMAL_IDEA( PGPEncryptedData.IDEA ),
        NONE( PGPEncryptedData.NULL );

        public final int id;

        private EncryptionAlgorithm( int id )
        {
            this.id = id;
        }
    }

    public static class PgpMessage
    {
        public final byte[] message;
        public final int senderSecretKeyId;
        public final int receiverPublicKeyId;
        public final EncryptionAlgorithm encryptionAlgorithm;
        public final boolean signed;
        public final boolean compressed;
        public final boolean radix64Encoded;
        public final boolean valid;

        public PgpMessage(
                byte[] message,
                int senderSecretKeyId,
                int receiverPublicKeyId,
                EncryptionAlgorithm encryptionAlgorithm,
                boolean signed,
                boolean compressed,
                boolean radix64Encoded,
                boolean valid )
        {
            this.message = message;
            this.senderSecretKeyId = senderSecretKeyId;
            this.receiverPublicKeyId = receiverPublicKeyId;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.signed = signed;
            this.compressed = compressed;
            this.radix64Encoded = radix64Encoded;
            this.valid = valid;
        }
    }

    // create a literal data packet from the given message
    private static byte[] createLiteralPacket(
            byte[] message ) throws IOException
    {
        if( message == null )
            return null;

        ByteArrayOutputStream messageStream = null;
        OutputStream literalDataStream = null;

        try
        {
            // create a message stream for the resulting packet
            messageStream = new ByteArrayOutputStream();

            // create a literal data packet generator and stream with the above message stream
            PGPLiteralDataGenerator literalDataGen = new PGPLiteralDataGenerator();
            literalDataStream = literalDataGen.open(
                    messageStream,
                    PGPLiteralData.BINARY,
                    "filename", // FIXME: this should be specified in the function parameters
                    new Date(),
                    new byte[50000]
            );

            // write the data packet to the message body and close the literal packet stream
            literalDataStream.write( message );
            literalDataStream.close();

            // overwrite the message buffer and close the message stream
            message = messageStream.toByteArray();
            messageStream.close();

            // return the message
            return message;
        }
        catch( IOException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not create a literal data packet.", ex );
        }
        finally
        {
            try
            {
                // close all open resources
                if( messageStream != null )
                    messageStream.close();
                if( literalDataStream != null )
                    literalDataStream.close();
            }
            catch( IOException ex )
            {
                Logger.getLogger( Encryption.class.getName() ).log( Level.SEVERE, "Could not close file after IOException occured during write.", ex );
            }
        }

        throw new IOException( "Could not create a literal data packet." );
    }

    // append a signature packet to the message
    private static byte[] appendSignaturePacket(
            byte[] message,
            PGPSecretKey senderSecretKey,
            char[] senderPassphrase ) throws IOException
    {
        if( message == null || senderSecretKey == null || senderPassphrase == null )
            return null;

        ByteArrayOutputStream messageStream = null;

        try
        {
            // get the sender's private key using the given passphrase
            PGPPrivateKey senderPrivateKey = senderSecretKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider( "BC" )
                            .build( senderPassphrase )
            );
            // get the sender's public key
            PGPPublicKey senderPublicKey = senderSecretKey.getPublicKey();
            // get the sender's public key id
            String senderPublicKeyId = ( String )senderPublicKey.getUserIDs().next();

            // make a signature generator
            PGPSignatureGenerator signatureGen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(
                            senderSecretKey.getPublicKey().getAlgorithm(),
                            HashAlgorithmTags.SHA1
                    ).setProvider( "BC" )
            );
            signatureGen.init( PGPSignature.BINARY_DOCUMENT, senderPrivateKey );

            // make a generator for the signature's header subpackets
            PGPSignatureSubpacketGenerator signatureSubpacketGen = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGen.setSignerUserID( /*isCritical=*/ false, senderPublicKeyId );
            signatureSubpacketGen.setSignatureCreationTime( /*isCritical=*/ false, new Date() );
            signatureSubpacketGen.setPreferredHashAlgorithms( /*isCritical=*/ false, new int[]
                    {
                        HashAlgorithmTags.SHA1
                    } );
            signatureSubpacketGen.setPreferredSymmetricAlgorithms( /*isCritical=*/ false, new int[]
                    {
                        PGPEncryptedData.IDEA, PGPEncryptedData.TRIPLE_DES
                    } );
            signatureSubpacketGen.setPreferredCompressionAlgorithms( /*isCritical=*/ false, new int[]
                    {
                        PGPCompressedData.ZIP
                    } );

            // set the hashed subpackets in the signature
            signatureGen.setHashedSubpackets( signatureSubpacketGen.generate() );
            // create the message digest by hashing the message body
            signatureGen.update( message );
            // create a one pass signature by signing the message digest with the sender's private key
            PGPOnePassSignature signature = signatureGen.generateOnePassVersion( /*isNested=*/ false );

            // append the signature packet to the message data packet
            messageStream = new ByteArrayOutputStream();
            signature.encode( messageStream );
            messageStream.write( message );

            // overwrite the message buffer and close the message stream
            message = messageStream.toByteArray();
            messageStream.close();

            return message;
        }
        catch( IOException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not append a signature packet to the message.", ex );
        }
        catch( PGPException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not create message signature.", ex );
        }
        finally
        {
            try
            {
                // close all open resources
                if( messageStream != null )
                    messageStream.close();
            }
            catch( IOException ex )
            {
                Logger.getLogger( Encryption.class.getName() ).log( Level.SEVERE, "Could not close file after IOException occured during write.", ex );
            }
        }

        throw new IOException( "Could not append a signature packet to the message." );
    }

    // create a compressed packet from the given message
    private static byte[] createCompressedPacket(
            byte[] message ) throws IOException
    {
        if( message == null )
            return null;

        ByteArrayOutputStream messageStream = null;
        OutputStream compressedDataStream = null;

        try
        {
            // create a compressed data packet stream
            messageStream = new ByteArrayOutputStream();
            PGPCompressedDataGenerator compressedDataGen = new PGPCompressedDataGenerator( PGPCompressedData.ZIP );
            compressedDataStream = compressedDataGen.open( messageStream );

            // write the compressed data packet to the message stream and close the compressed data stream
            compressedDataStream.write( message );
            compressedDataStream.close();

            // overwrite the message buffer and close the message stream
            message = messageStream.toByteArray();
            messageStream.close();

            return message;
        }
        catch( IOException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not create a compressed data packet.", ex );
        }
        finally
        {
            try
            {
                // close all open resources
                if( messageStream != null )
                    messageStream.close();
                if( compressedDataStream != null )
                    compressedDataStream.close();
            }
            catch( IOException ex )
            {
                Logger.getLogger( Encryption.class.getName() ).log( Level.SEVERE, "Could not close file after IOException occured during write.", ex );
            }
        }

        throw new IOException( "Could not create a compressed data packet." );
    }

    // turn the message into an encrypted packet
    private static byte[] createEncryptedPacket(
            byte[] message,
            PGPPublicKey receiverPublicKey,
            EncryptionAlgorithm encryptionAlgorithm,
            char[] senderPassphrase ) throws IOException
    {
        if( message == null || receiverPublicKey == null || senderPassphrase == null )
            return null;

        ByteArrayOutputStream messageStream = null;
        OutputStream encryptedDataStream = null;

        try
        {
            // create an encryption generator
            PGPEncryptedDataGenerator encryptedDataGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder( encryptionAlgorithm.id )
                            .setProvider( "BC" )
                            .setSecureRandom( new SecureRandom() )
                            .setWithIntegrityPacket( true )
            );
            encryptedDataGen.addMethod(
                    new JcePublicKeyKeyEncryptionMethodGenerator( receiverPublicKey )
                            .setProvider( "BC" )
            );

            // make an encrypted output stream using the encryption generator
            messageStream = new ByteArrayOutputStream();
            encryptedDataStream = encryptedDataGen.open( messageStream, new byte[50000] );

            // write the encrypted data packet to the message stream and close the encrypted data stream
            encryptedDataStream.write( message );
            encryptedDataStream.close();

            // overwrite the message buffer and close the message stream
            message = messageStream.toByteArray();
            messageStream.close();

            return message;
        }
        catch( IOException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not create an encrypted data packet.", ex );
        }
        catch( PGPException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not encrypt message.", ex );
        }
        finally
        {
            try
            {
                // close all open resources
                if( messageStream != null )
                    messageStream.close();
                if( encryptedDataStream != null )
                    encryptedDataStream.close();
            }
            catch( IOException ex )
            {
                Logger.getLogger( Encryption.class.getName() ).log( Level.SEVERE, "Could not close file after IOException occured during write.", ex );
            }
        }

        throw new IOException( "Could not create an encrypted data packet." );
    }

    // encode the message into radix64 format
    private static byte[] encodeAsRadix64(
            byte[] message ) throws IOException
    {
        if( message == null )
            return null;

        ByteArrayOutputStream messageStream = null;
        ArmoredOutputStream armoredStream = null;

        try
        {
            // make an armored output stream using the message stream
            messageStream = new ByteArrayOutputStream();
            armoredStream = new ArmoredOutputStream( messageStream );

            // write the radix64 data packet to the message stream and close the armored data stream
            armoredStream.write( message );
            armoredStream.close();

            // overwrite the message buffer and close the message stream
            message = messageStream.toByteArray();
            messageStream.close();

            return message;
        }
        catch( IOException ex )
        {
            Logger.getLogger( Encryption.class.getName() ).log( Level.INFO, "Could not create an radix64 encoded data packet.", ex );
        }
        finally
        {
            try
            {
                // close all open resources
                if( messageStream != null )
                    messageStream.close();
                if( armoredStream != null )
                    armoredStream.close();
            }
            catch( IOException ex )
            {
                Logger.getLogger( Encryption.class.getName() ).log( Level.SEVERE, "Could not close file after IOException occured during write.", ex );
            }
        }

        throw new IOException( "Could not encode message in radix64 format." );
    }

    public static byte[] createPgpMessage(
            byte[] message,
            PGPSecretKey senderSecretKey,
            PGPPublicKey receiverPublicKey,
            EncryptionAlgorithm encryptionAlgorithm,
            char[] senderPassphrase,
            boolean addSignature,
            boolean addCompression,
            boolean addConversionToRadix64 ) throws IOException
    {
        // create a literal data packet from the message body
        message = createLiteralPacket( message );

        // if the message should be signed, append a signature packet
        if( addSignature )
            message = appendSignaturePacket( message, senderSecretKey, senderPassphrase );

        // if the message should be compressed, turn it into a compressed packet
        if( addCompression )
            message = createCompressedPacket( message );

        // if the message should be encrypted, turn it into an encrypted packet
        if( encryptionAlgorithm != EncryptionAlgorithm.NONE )
            message = createEncryptedPacket( message, receiverPublicKey, encryptionAlgorithm, senderPassphrase );

        // if the message should be converted into radix64 format, encode it into that format
        if( addConversionToRadix64 )
            message = encodeAsRadix64( message );

        return message;
    }

    public static PgpMessage readPgpMessage(
            byte[] message,
            char[] receiverPassphrase )
    {
        PgpMessage dm = null; //new PgpMessage( message, false, false, "stub-author" );
        return dm;
    }
}
