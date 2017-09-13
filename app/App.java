
import data.StandardId;
import data.Trade;

import java.util.ArrayList;
import java.util.List;

class App {
    static {
        System.loadLibrary("app_jni");
    }

    /*
        Note: You cannot trust this!
    */
    private static native boolean sgx_available();

    private static native void encryptTrades(List<Trade> trades);

    public static void main(String[] args) {
        System.out.println("Hello World! SGX:"+sgx_available());

        List<Trade> trades = new ArrayList<Trade>();

        Trade t1 = new Trade();
        t1.party = new StandardId("a","a");
        t1.counter_party = new StandardId("a","b");
        t1.value = 1234567890L;
        trades.add(t1);

        encryptTrades(trades);

    }
}