/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.iu170057d_sm170081d.utils;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author User
 */
public class Utils {
    
    public static void writeToFile(String filePath, byte[] content)
    {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static byte[] readFromFile(String filePath)
    {
        return null;
    }
}
