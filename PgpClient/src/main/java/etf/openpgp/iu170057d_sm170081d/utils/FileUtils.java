package etf.openpgp.iu170057d_sm170081d.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.filechooser.FileNameExtensionFilter;

public class FileUtils
{

    private FileUtils()
    {
    }

    public static void writeToFile( String filePath, byte[] content )
    {
        try( FileOutputStream fos = new FileOutputStream( filePath ) )
        {
            fos.write( content );
        }
        catch( FileNotFoundException ex )
        {
            Logger.getLogger( FileUtils.class.getName() ).log( Level.SEVERE, null, ex );
        }
        catch( IOException ex )
        {
            Logger.getLogger( FileUtils.class.getName() ).log( Level.SEVERE, null, ex );
        }
    }

    public static byte[] readFromFile( String filePath )
    {
        File file = new File( filePath );
        try( FileInputStream fin = new FileInputStream( file ) )
        {
            byte fileContent[] = new byte[( int )file.length()];
            fin.read( fileContent );
            return fileContent;
        }
        catch( FileNotFoundException ex )
        {
            Logger.getLogger( FileUtils.class.getName() ).log( Level.INFO, "File not found.", ex );
        }
        catch( IOException ex )
        {
            Logger.getLogger( FileUtils.class.getName() ).log( Level.INFO, "Could not read file contents fully.", ex );
        }

        return null;
    }

    public static void ensureFileExists( File file ) throws FileNotFoundException
    {
        file.getParentFile().mkdirs();

        try
        {
            file.createNewFile();
        }
        catch( IOException ex )
        {
            if( Files.notExists( Paths.get( file.getAbsolutePath() ) ) )
            {
                throw new FileNotFoundException( "Could not ensure the file exists" );
            }
        }
    }

    // file chooser dialog type
    public static final int OPEN_DIALOG = JFileChooser.OPEN_DIALOG;
    public static final int SAVE_DIALOG = JFileChooser.SAVE_DIALOG;
    // file chooser file types
    public static final int ANY_FILE = 0;
    public static final int PGP_MESSAGE_FILE = 1;
    public static final int PGP_KEY_FILE = 2;

    public static String getUserSelectedFilePath( int dialogType, int allowedFileType )
    {
        JFileChooser jFileChooser = new javax.swing.JFileChooser();
        jFileChooser.setFileSelectionMode( JFileChooser.FILES_ONLY );
        jFileChooser.setMultiSelectionEnabled( false );
        // jFileChooser.setCurrentDirectory(new File("."));

        switch( allowedFileType )
        {
            case ANY_FILE:
            {
                break;
            }
            case PGP_MESSAGE_FILE:
            {
                jFileChooser.setFileFilter( new FileNameExtensionFilter( "PGP message (*.gpg)", "gpg" ) );
                break;
            }
            case PGP_KEY_FILE:
            {
                jFileChooser.setFileFilter( new FileNameExtensionFilter( "PGP key file (*.asc)", "asc" ) );
                break;
            }
            default:
            {
                throw new IllegalArgumentException( "Invalid <allowed file type> provided" );
            }
        }

        JFrame jFrame = new JFrame();
        jFrame.setDefaultCloseOperation( javax.swing.WindowConstants.DISPOSE_ON_CLOSE );
        // these two lines dont't work since we don't have internal access to the showOpenDialog and showSaveDialog methods
        // jFrame.setTitle("Choose file");
        // jFrame.getContentPane().setSize(new Dimension(640, 480));

        int dialogStatus = -1;
        switch( dialogType )
        {
            case OPEN_DIALOG:
            {
                dialogStatus = jFileChooser.showOpenDialog( jFrame );
                break;
            }
            case SAVE_DIALOG:
            {
                dialogStatus = jFileChooser.showSaveDialog( jFrame );
                break;
            }
            default:
            {
                throw new IllegalArgumentException( "Invalid dialog type provided" );
            }
        }

        if( dialogStatus != JFileChooser.APPROVE_OPTION )
            return null;


        String filePath = jFileChooser.getSelectedFile().getAbsolutePath();
        switch( allowedFileType )
        {
            case PGP_MESSAGE_FILE:
            {
                if( !filePath.endsWith( ".gpg" ) )
                    filePath += ".gpg";
                break;
            }
            case PGP_KEY_FILE:
            {
                if( !filePath.endsWith( ".asc" ) )
                    filePath += ".asc";
                break;
            }
        }
        
        return filePath;
    }
}
