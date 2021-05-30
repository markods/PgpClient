/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.iu170057d_sm170081d.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

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
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 *
 * @author User
 */
public class PGPKeys {

    private static final File publicKeyFile = new File("C:\\Users\\User\\src\\PgpClient\\PgpClient\\target\\public.asc");
    private static final File privateKeyFile = new File("C:\\Users\\User\\src\\PgpClient\\PgpClient\\target\\private.asc");
        
    private static PGPPublicKeyRingCollection publicKeyRingCollection;
    private static PGPSecretKeyRingCollection secretKeyRingCollection; 

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        try {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(new ArmoredInputStream(new FileInputStream(publicKeyFile)), new BcKeyFingerprintCalculator());
            secretKeyRingCollection = new PGPSecretKeyRingCollection(new ArmoredInputStream(new FileInputStream(privateKeyFile)), new BcKeyFingerprintCalculator());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    private PGPKeys() {}
    
    public static PGPSecretKeyRingCollection getSecretKeysCollection() throws IOException, PGPException{
        return secretKeyRingCollection;
    }
       
    public static PGPPublicKeyRingCollection getPublicKeysCollection() throws IOException, PGPException{
        return publicKeyRingCollection;
    }
   
    public static final void addSecretKey(PGPKeyRingGenerator pgpKeyRingGen) throws IOException {
        PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();
        secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection, pgpSecKeyRing);
    }
		
    public static final void addPublicKey(PGPKeyRingGenerator pgpKeyRingGen) throws IOException {
        PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing(); 
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, pgpPubKeyRing);
    }

    public static final void removePublicKey(PGPPublicKeyRing publicKeyRing) throws IOException {
        publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, publicKeyRing);
    }
        
    public static final void removeSecretKey(PGPSecretKeyRing secretKeyRing) throws IOException {
        secretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyRingCollection, secretKeyRing);
    }
        
    public static void saveSecretKeysToFile() throws IOException {
        ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(privateKeyFile));
        secretKeyRingCollection.encode(aos);
        aos.close();
    }
        
    public static void savePublicKeysToFile() throws IOException {
        ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(publicKeyFile));
        publicKeyRingCollection.encode(aos);
        aos.close();
    }
        
    public static void exportPublicKey(PGPPublicKeyRing publicKeyRing, File file) throws IOException {
        ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(file));
        publicKeyRing.encode(aos);
        aos.close();
    }
        
    public static void exportSecretKey(PGPSecretKeyRing publicKeyRing, File file) throws IOException {
        ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(file));
        publicKeyRing.encode(aos);
        aos.close();
    }
        
    public static void importPublicKey(File file) throws IOException, PGPException {
        ArmoredInputStream ais = new ArmoredInputStream(new FileInputStream(file));
        PGPPublicKeyRingCollection pgpPubKeyCol = new PGPPublicKeyRingCollection(ais, new BcKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPubKeyCol.getKeyRings();
         while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, keyRing);
         }
    }
        
    public static void importSecretKey(File file) throws IOException, PGPException {
        ArmoredInputStream ais = new ArmoredInputStream(new FileInputStream(file));
        PGPSecretKeyRingCollection pgpPubKeyCol = new PGPSecretKeyRingCollection(ais, new BcKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> keyRingIter = pgpPubKeyCol.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();
            secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection, keyRing);
        }
    }
        /**
         * 
         * @param dsaKeyPair - the generated DSA key pair
         * @param elGamalKeyPair - the generated El Gamal key pair
         * @param identity - the given identity of the key pair ring
         * @param passphrase - the secret pass phrase to protect the key pair
         * @return a PGP Key Ring Generate with the El Gamal key pair added as sub key
         * @throws Exception
         */
    public static final PGPKeyRingGenerator createPGPKeyRingGenerator(
            KeyPair dsaKeyPair,
            KeyPair elGamalKeyPair,
            String identity, 
           char[] passphrase) throws Exception {
        PGPKeyPair dsaPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
        PGPKeyPair elGamalPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPair, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                dsaPgpKeyPair,
                identity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(dsaPgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passphrase));

        keyRingGen.addSubKey(elGamalPgpKeyPair);

        return keyRingGen;
    }

    /**
     * 
     * @param keySize 512 - 1024 (multiple of 64)
     * @return the DSA generated key pair
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     */
    public static final KeyPair generateDsaKeyPair(int keySize) 
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * 
     * @param keySize - 1024, 2048, 4096
     * @return the El Gamal generated key pair
     * @throws Exception 
     */
    public static final KeyPair generateElGamalKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * 
     * @param paramSpecs - the pre-defined parameter specs
     * @return the El Gamal generated key pair
     * @throws Exception
     */
    public static final KeyPair generateElGamalKeyPair(ElGamalParameterSpec paramSpecs) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keyPairGenerator.initialize(paramSpecs);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
}

