package lv.lumii.qrng.clienttoken;

public interface SignFunction {
    byte[] sign(byte[] message);
}
