package org.bouncycastle.tls.injection;

import org.bouncycastle.tls.injection.kems.InjectedKEMs;

public class InjectableAlgorithms {
    InjectableAlgorithms withKEM(int kemCodePoint,
                                 String standardName, InjectedKEMs.KemFactory kemFactory) {
        return this;
    }

    InjectableAlgorithms withDefaultKEMs(boolean before) {
        return this;
    }
    InjectableAlgorithms withoutDefaultKEMs() {
        return this;
    }
}
