package lv.lumii.smartcard;

import javax.smartcardio.*;
import java.util.Arrays;

public class JavaCardCommunication {
  private static CardChannel channel;
  private static Card card=null;

  public JavaCardCommunication() {
    this("*"); // the "*" string means "any reader"
  }

  public JavaCardCommunication(String readerName) {
    try {
      if (readerName.equals("*")) {
        readerName = "";
        // We will search for readerName as a substring of reader description string.
        // The readerName=="" will select the first available card reader.
      }
      TerminalFactory factory = TerminalFactory.getDefault();
      CardTerminals terminals = factory.terminals();
      java.util.List<CardTerminal> list = terminals.list();
      CardTerminal terminal = null;
      for (CardTerminal term : list) {
        if (term.toString().toLowerCase().contains(readerName.toLowerCase()))
        terminal = term;
      }
      if (terminal == null) {
        throw new CardException("No card reader found");
      }
      card = terminal.connect("*");
      channel = card.getBasicChannel();
    }
    catch (CardException e) {
      System.out.println("Error while initializing the card reader: " + e.getMessage());
    }
  }

  public static boolean isConnected() {
    return card!=null;
  }

  public static boolean selectApplet(byte[] aID) {
    try {
      CommandAPDU selectAppletCommand = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aID);
      ResponseAPDU response = channel.transmit(selectAppletCommand);
      if (response.getSW() != 0x9000) throw new CardException("Applet not found");
      return true;
    }
    catch (CardException e) {
      System.out.println("Connection error: " + e.getMessage());
      return false;
    }
  }

  public static void disconnect() {
    try {
      card.disconnect(false);
      card=null;
    }
    catch (CardException e) {
      e.printStackTrace();
    }
  }

  public static byte[] getPublicKey() {
    byte[] responseData= new byte[] {};
    try {
      CommandAPDU command = new CommandAPDU(0x80, 0x23, 0x03, 0x00);
      ResponseAPDU response = channel.transmit(command);
      responseData = response.getData();
    }
    catch (CardException e) {
      e.printStackTrace();
    }
    return responseData;
  }

  public static byte[] appendByteArray(byte[] array1, byte[] array2) {
      int length1 = array1.length;
      int length2 = array2.length;
      array1 = Arrays.copyOf(array1, length1 + length2);
      System.arraycopy(array2, 0, array1, length1, length2);
      return array1;
  }

  public static byte[] getCertificate() {
    byte[] responseData= new byte[] {};
    byte[] res=new byte[]{};
    try {
      byte part=0x00;
      while (true) {
        CommandAPDU command = new CommandAPDU(0x80, 0x33, 0x01, part, 0x00);
        ResponseAPDU response = channel.transmit(command);
        responseData = response.getData();
        if (responseData.length==0) break;
        res=appendByteArray(res, responseData);
        part++;
      }
      //CommandAPDU command = new CommandAPDU(0x80, 0x23, 0x01, 0x00);
      //ResponseAPDU response = channel.transmit(command);
      //responseData = response.getData();
    }
    catch (CardException e) {
      e.printStackTrace();
    }
    return res;
  }

  public static byte[] sign(byte[] msgBytes) {
    byte[] responseData=new byte[] {};
    try {
      //byte[] msgBytes = msg.getBytes();
      CommandAPDU command = new CommandAPDU(0x80, 0x26, 0x00, 0x00, msgBytes);
      int count=2;
      ResponseAPDU response = channel.transmit(command);
      do {
        if (response.getData().length>2) break;
        response = channel.transmit(command);
        count--;
      } while (count>0);
      responseData = response.getData();
    }
    catch (CardException e) {
      e.printStackTrace();
    }
    return responseData;
  }

  public static boolean verify(byte[] msgBytes,byte[] signedMsg) {
    byte[] responseData= new byte[] {0};
    try {
      CommandAPDU command = new CommandAPDU(0x80, 0x28, 0x00, 0x00, signedMsg);
      ResponseAPDU response = channel.transmit(command);
      //byte[] msgBytes = msg.getBytes();
      command = new CommandAPDU(0x80, 0x27, 0x00, 0x00, msgBytes);
      response = channel.transmit(command);
      responseData = response.getData();
    }
    catch (CardException e) {
      e.printStackTrace();
    }
    return responseData[0]==1;
  }
}
