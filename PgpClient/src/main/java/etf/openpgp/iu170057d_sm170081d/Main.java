package etf.openpgp.iu170057d_sm170081d;

public class Main
{

    /* Set the Nimbus look and feel (preferably)
     * If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
     * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
     */
    public static void SetLookAndFeel( String lookAndFeelName )
    {
        if( lookAndFeelName == null )
            return;

        try
        {
            for( javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels() )
            {
                if( lookAndFeelName.equals( info.getName() ) )
                {
                    javax.swing.UIManager.setLookAndFeel( info.getClassName() );
                    break;
                }
            }
        }
        catch( ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex )
        {
            java.util.logging.Logger.getLogger( App.class.getName() ).log( java.util.logging.Level.SEVERE, null, ex );
        }
    }

    public static void main( String[] args )
    {
        SetLookAndFeel( "Nimbus" );
        App app = new App();

        java.awt.EventQueue.invokeLater( () ->
        {
            app.setVisible( true );
        } );
    }

}
