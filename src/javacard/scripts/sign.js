s="Hello, World!";
print("Attempting to sign the message: "+s);
resp=card.sendApdu(0x80,0x26,0x00,0x00,new ByteString(s,ASCII));
print("Signature: "+resp);
print(resp);
