package lv.lumii.qrng.token;

public interface SignFunction {
    byte[] sign(byte[] message);
}
