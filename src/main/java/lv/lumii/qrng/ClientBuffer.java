package lv.lumii.qrng;

import org.bouncycastle.util.Arrays;
import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;
import org.slf4j.Logger;

import java.nio.ByteBuffer;

public class ClientBuffer {

    public static Logger logger = QrngClient.logger; // one common logger

    private Unchecked<byte[]> buffer; // circular

    private static int MAX_EMPTY_TRIALS = 10;

    // state:
    private int capacity;
    private int first;
    private int length;

    public ClientBuffer(int capacity) {
        this.buffer = new Unchecked<>(new Sticky<>(()->createBuffer(capacity)));
        this.capacity = capacity;
        this.first = 0;
        this.length = 0;
    }

    private byte[] createBuffer(int size) {
        byte[] buffer = new byte[size];
        for(int i=0; i<size; i++)
            buffer[i] = 0;
        return buffer;
    }

    public synchronized void replenishWith(byte[] data) {

        logger.info("Replenishing the buffer with "+data.length+" bytes...");

        // do not replenish more than remaining unused capacity:
        int unused = this.unusedCapacity();
        if (data.length > unused) {
            data = Arrays.copyOf(data, unused);
        }

        // replenishing...
        int remainingDataLength = data.length;

        int i = 0; // data index
        int j = nextIndex(); // this.buffer index

        while (remainingDataLength>0) {
            this.buffer.value()[j] = data[i];
            i++;
            j = (j+1) % this.capacity;

            remainingDataLength--;
            this.length++;
        }

        logger.info("Buffer fill: "+length+" of " +capacity +" ("+(length*100.0/capacity)+"%)");
    }

    public byte[] consume(int requiredLength) throws InterruptedException { // blocking (but thread-safe)...

        int remainingLength = requiredLength;
        int emptyTrials = 0;
        ByteBuffer consumed = ByteBuffer.allocate(remainingLength);

        while (remainingLength > 0) {
            synchronized (this) {
                if (this.length==0)
                    emptyTrials++;
                else
                    emptyTrials=0;

                // fill what we can (while nobody interferes with us):
                while (this.length>0 && remainingLength>0) {
                    consumed.put(this.buffer.value()[this.first]);
                    this.first++;
                    this.length--;
                    remainingLength--;
                }
            }
            if (emptyTrials>=MAX_EMPTY_TRIALS)
                throw new InterruptedException("The client buffer has not been replenished for too long");
            if (remainingLength > 0) {
                // After filling what we could, there are still some more bytes required.
                // Waiting 1 seconds to wait for the buffer to be replenished...
                Thread.sleep(1000);
            }
        }

        logger.info("Consumed "+requiredLength+" random bytes from the buffer.");

        consumed.rewind();
        return consumed.array();
    }

    public synchronized int capacity() {
        return capacity;
    }

    public synchronized int usedCapacity() {
        return length;
    }

    public synchronized int unusedCapacity() {
        return capacity - length;
    }

    private int nextIndex() {
        return (first + length) % capacity;
    }



}
