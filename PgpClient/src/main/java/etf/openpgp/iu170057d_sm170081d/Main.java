package etf.openpgp.iu170057d_sm170081d;

import etf.openpgp.iu170057d_sm170081d.App;

public class Main {
    
    public static void main(String[] args) {
        
        App app = new App();
        
        app.populatePublicKeyRingTable();
        app.populatePrivateKeyRingTable();
        // TODO(Uros): Call these event whenever send or receive pages are opened
        app.populateSendMessageFromComboBox();
        app.populateSendMessageToComboBox();
        
        java.awt.EventQueue.invokeLater(() -> {
            app.setVisible(true);
        });
    }
    
}
