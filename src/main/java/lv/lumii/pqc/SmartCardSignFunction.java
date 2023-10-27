package lv.lumii.pqc;

public interface SmartCardSignFunction {
    byte[] sign(byte[] message) throws Exception;
}
