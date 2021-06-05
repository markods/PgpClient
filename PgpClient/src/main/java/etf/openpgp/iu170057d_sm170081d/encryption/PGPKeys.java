package etf.openpgp.iu170057d_sm170081d.encryption;

import etf.openpgp.iu170057d_sm170081d.utils.FileUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class PGPKeys
{

    private static final File publicKeyFile = new File( "./settings/public.asc" );
    private static final File privateKeyFile = new File( "./settings/secret.asc" );

    private static PGPPublicKeyRingCollection publicKeyRingCollection;
    private static PGPSecretKeyRingCollection secretKeyRingCollection;

    static
    {
        if( Security.getProvider( "BC" ) == null )
        {
            Security.addProvider( new BouncyCastleProvider() );
        }

        try
        {
            FileUtils.ensureFileExists( publicKeyFile );
            publicKeyRingCollection = new PGPPublicKeyRingCollection(
                    new ArmoredInputStream(
                            new FileInputStream( publicKeyFile ) ),
                    new BcKeyFingerprintCalculator() );
        }
        catch( IOException | PGPException ex )
        {
            java.util.logging.Logger.getLogger( PGPKeys.class.getName() ).log( Level.INFO, "Public keyring file missing from settings and could not be recreated; exiting.", ex );
            System.exit( 1 );
        }

        try
        {
            FileUtils.ensureFileExists( privateKeyFile );
            secretKeyRingCollection = new PGPSecretKeyRingCollection(
                    new ArmoredInputStream(
                            new FileInputStream( privateKeyFile ) ),
                    new BcKeyFingerprintCalculator() );
        }
        catch( IOException | PGPException ex )
        {
            java.util.logging.Logger.getLogger( PGPKeys.class.getName() ).log( Level.INFO, "Secret keyring file missing from settings and could not be recreated; exiting.", ex );
            System.exit( 1 );
        }
    }

    private PGPKeys()
    {
    }

    public static PGPSecretKeyRingCollection getSecretKeysCollection()
            throws IOException, PGPException
    {
        return secretKeyRingCollection;
    }

    public static PGPPublicKeyRingCollection getPublicKeysCollection()
            throws IOException, PGPException
    {
        return publicKeyRingCollection;
    }

    public static final void addSecretKey( PGPKeyRingGenerator pgpKeyRingGen ) throws IOException
    {
        PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();
        secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing( secretKeyRingCollection, pgpSecKeyRing );
    }

    public static final void addPublicKey( PGPKeyRingGenerator pgpKeyRingGen ) throws IOException
    {
        PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing( publicKeyRingCollection, pgpPubKeyRing );
    }

    public static final void removePublicKey( PGPPublicKeyRing publicKeyRing ) throws IOException
    {
        publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing( publicKeyRingCollection, publicKeyRing );
    }

    public static final void removeSecretKey( PGPSecretKeyRing secretKeyRing ) throws IOException
    {
        secretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing( secretKeyRingCollection, secretKeyRing );
    }

    public static void saveSecretKeysToFile() throws IOException
    {
        try( ArmoredOutputStream aos = new ArmoredOutputStream( new FileOutputStream( privateKeyFile ) ) )
        {
            secretKeyRingCollection.encode( aos );
        }
    }

    public static void savePublicKeysToFile() throws IOException
    {
        try( ArmoredOutputStream aos = new ArmoredOutputStream( new FileOutputStream( publicKeyFile ) ) )
        {
            publicKeyRingCollection.encode( aos );
        }
    }

    public static void exportPublicKey( PGPPublicKeyRing publicKeyRing, File file ) throws IOException
    {
        try( ArmoredOutputStream aos = new ArmoredOutputStream( new FileOutputStream( file ) ) )
        {
            publicKeyRing.encode( aos );
        }
    }

    public static void exportSecretKey( PGPSecretKeyRing publicKeyRing, File file ) throws IOException
    {
        try( ArmoredOutputStream aos = new ArmoredOutputStream( new FileOutputStream( file ) ) )
        {
            publicKeyRing.encode( aos );
        }
    }

    public static void importPublicKey( File file ) throws IOException, PGPException
    {
        ArmoredInputStream ais = new ArmoredInputStream( new FileInputStream( file ) );
        PGPPublicKeyRingCollection pgpPubKeyCol = new PGPPublicKeyRingCollection( ais, new BcKeyFingerprintCalculator() );

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPubKeyCol.getKeyRings();
        while( keyRingIter.hasNext() )
        {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing( publicKeyRingCollection, keyRing );
        }
    }

    public static void importSecretKey( File file ) throws IOException, PGPException
    {
        ArmoredInputStream ais = new ArmoredInputStream( new FileInputStream( file ) );
        PGPSecretKeyRingCollection pgpSecKeyCol = new PGPSecretKeyRingCollection( ais, new BcKeyFingerprintCalculator() );

        Iterator<PGPSecretKeyRing> keyRingIter = pgpSecKeyCol.getKeyRings();
        while( keyRingIter.hasNext() )
        {
            PGPSecretKeyRing keyRing = keyRingIter.next();
            secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing( secretKeyRingCollection, keyRing );
        }
    }

    public static final PGPKeyRingGenerator createPGPKeyRingGenerator(
            KeyPair dsaKeyPair,
            KeyPair elGamalKeyPair,
            String identity,
            char[] passphrase ) throws Exception
    {
        PGPKeyPair dsaPgpKeyPair = new JcaPGPKeyPair( PGPPublicKey.DSA, dsaKeyPair, new Date() );
        PGPKeyPair elGamalPgpKeyPair = new JcaPGPKeyPair( PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPair, new Date() );
        PGPDigestCalculator shaCalc = new JcaPGPDigestCalculatorProviderBuilder().build().get( HashAlgorithmTags.SHA1 );

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                dsaPgpKeyPair,
                identity,
                shaCalc,
                null,
                null,
                new JcaPGPContentSignerBuilder( dsaPgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1 ),
                new JcePBESecretKeyEncryptorBuilder( PGPEncryptedData.AES_256, shaCalc ).setProvider( "BC" ).build( passphrase ) );

        keyRingGen.addSubKey( elGamalPgpKeyPair );

        return keyRingGen;
    }

    public static final KeyPair generateDsaKeyPair( int keySize )
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "DSA", "BC" );
        keyPairGenerator.initialize( keySize );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static final KeyPair generateElGamalKeyPair( int keySize ) throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "ELGAMAL", "BC" );
        keyPairGenerator.initialize( keySize );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static final KeyPair generateElGamalKeyPair( ElGamalParameterSpec paramSpecs ) throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "ELGAMAL", "BC" );
        keyPairGenerator.initialize( paramSpecs );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static final PGPPublicKeyRing findPublicKeyRing( long id ) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = PGPKeys.getPublicKeysCollection();
        PGPPublicKey pubKey = null;

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        PGPPublicKeyRing keyRing = null;
        while( keyRingIter.hasNext() && pubKey == null )
        {
            keyRing = keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while( keyIter.hasNext() )
            {
                PGPPublicKey key = keyIter.next();
                if( (key.getKeyID() == id) )
                {
                    pubKey = key;
                    break;
                }
            }
        }

        if( pubKey != null )
        {
            return keyRing;
        }
        else
        {
            throw new IllegalArgumentException( "Invalid key index" );
        }
    }

    public static PGPSecretKeyRing findSecretKeyRing( long id ) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = PGPKeys.getSecretKeysCollection();
        PGPSecretKey secKey = null;

        Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
        PGPSecretKeyRing keyRing = null;
        while( iter.hasNext() && secKey == null )
        {
            keyRing = iter.next();

            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while( keyIter.hasNext() )
            {
                PGPSecretKey key = keyIter.next();
//                System.out.println("key.getKeyID(): " + key.getKeyID());
                if( (key.getKeyID() == id) )
                {
                    secKey = key;
                    break;
                }
            }
        }

        if( secKey != null )
        {
            return keyRing;
        }
        else
        {
            throw new IllegalArgumentException( "Can't find signing key in key ring." );
        }
    }

    public static String keyIdToHexString( long keyId )
    {
        String hexString = Long.toHexString( keyId );
        String userFriendlyHexString = hexString.replaceAll( "....(?!$)", "$0 " );
        return userFriendlyHexString;
    }

    public static long hexStringToKeyId( String userFriendlyHexString )
    {
        String hexString = userFriendlyHexString.replaceAll( "\\s", "" );
        try
        {
            String mostSignificantBits = hexString.substring( 0, 8 );
            String leastSignificantBits = hexString.substring( 8, 16 );
            long keyId = (Long.parseLong( mostSignificantBits, 16 ) << 32) | Long.parseLong( leastSignificantBits, 16 );
            return keyId;
        }
        catch( NumberFormatException ex )
        {
            Logger.getLogger( PGPKeys.class.getName() ).log( Level.INFO, "Invalid hex string given for keyId.", ex );
            return 0;
        }
    }

    public static boolean isValidPassphrase( PGPSecretKeyRing secretKeyring, int index, char[] passphrase )
    {
        if( secretKeyring == null || passphrase == null )
            return false;
        
        try
        {
            Iterator secretKeyIter = secretKeyring.getSecretKeys();
            PGPSecretKey secretKey = null;
            for( int i = 0; i <= index && secretKeyIter.hasNext(); i++ )
                secretKey = ( PGPSecretKey )secretKeyIter.next();
            
            if( secretKey == null )
            {
                Logger.getLogger( PGPKeys.class.getName() ).log( Level.FINE, "Secret key at given index missing - it could not be checked against passphrase." );
                return false;
            }
                        
            secretKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider( "BC" )
                            .build( passphrase )
            );
            
            Logger.getLogger( PGPKeys.class.getName() ).log( Level.FINE, "Valid passphrase used to decode secret key." );
            return true;
        }
        catch( PGPException ex )
        {
            Logger.getLogger( PGPKeys.class.getName() ).log( Level.FINE, "Invalid passphrase used to decode secret key.", ex );
            return false;
        }
    }
}
