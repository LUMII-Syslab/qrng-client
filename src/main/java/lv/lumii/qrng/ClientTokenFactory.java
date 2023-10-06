package lv.lumii.qrng;

import lv.lumii.qrng.clienttoken.Token;

public interface ClientTokenFactory {
    Token clientToken(String location);
}
