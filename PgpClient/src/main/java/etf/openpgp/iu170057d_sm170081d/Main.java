/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.iu170057d_sm170081d;

import etf.openpgp.iu170057d_sm170081d.App;

/**
 *
 * @author User
 */
public class Main {
    
    public static void main(String[] args) {
        
        App app = new App();
        
        app.populatePublicKeyRingTable();
        app.populatePrivateKeyRingTable();
        app.populateSendMessageFromComboBox();
        app.populateSendMessageToComboBox();
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                app.setVisible(true);
            }
        });
    }
    
}
