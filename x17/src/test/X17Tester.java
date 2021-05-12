import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import hash.X17MessageDigest;

import static utils.HelperFunctions.*;

public class X17Tester {

  private static final X17MessageDigest x17;

  static {
    x17 = new X17MessageDigest();
  }

  @Test
  public void X17TesterMain() {
    testX17(
        x17.HashX17(
            Hex.decode(
                "041800009a04d9dd22efb4c0e322d12260ac1a6168f0d9d6752c4ae7b0337baaa1b1fb512ffcb93e17d818095cd4194a1eb5272b5df34897456a2284ee4fd62aabda4538412a375e9501011b14ebd1a7")),
        Hex.decode("0000000000001626efc6afc18acee83b71fb78b7823d5235279a3138e79b272e"));

    testX17(
        x17.HashX17(
            Hex.decode(
                "04180000e6db0c480eb762feec8f650ce44cfaebe4e6e2f4cecd403f386917df0d3f20871f27d82a01fa39b0f3e7ed2c08d2849a8ef70b04ba707124888bb7d12561a9108dff665d8fa80b1b01a9bc92")),
        Hex.decode("00000000000550a9ba39bf31637c29d318283d1b2e292f0db81d3ac166788a0e"));

    testX17(
        x17.HashX17(strToBytesArrayUTF8("The quick brown fox jumps over the lazy dog")),
        Hex.decode("958399aafef85344daba789bd611b1bd143de215b358cfec64cadb5ba9727d1f"));

    reportSuccess("X17");
  }
}
