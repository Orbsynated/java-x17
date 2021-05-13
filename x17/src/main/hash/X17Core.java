package hash;

import crypto.*;

import static org.spongycastle.util.Arrays.reverse;

abstract class X17Core extends DigestEngine {

  private static final Digest blake512_context;
  private static final Digest bmw512_context;
  private static final Digest groestl512_context;
  private static final Digest skein512_context;
  private static final Digest jh512_context;
  private static final Digest keccak512_context;
  private static final Digest luffa512_context;
  private static final Digest cubehash512_conetxt;
  private static final Digest shavite512_context;
  private static final Digest simd512_context;
  private static final Digest echo512_context;
  private static final Digest hamsi512_context;
  private static final Digest fugue512_context;
  private static final Digest shabal512_context;
  private static final Digest whirlpool_context;
  private static final Digest sha512_context;
  private static final Digest haval256_5_context;

  static {
    blake512_context = new BLAKE512();
    bmw512_context = new BMW512();
    groestl512_context = new Groestl512();
    skein512_context = new Skein512();
    jh512_context = new JH512();
    keccak512_context = new Keccak512();
    luffa512_context = new Luffa512();
    cubehash512_conetxt = new CubeHash512();
    shavite512_context = new SHAvite512();
    simd512_context = new SIMD512();
    echo512_context = new ECHO512();
    hamsi512_context = new Hamsi512();
    fugue512_context = new Fugue512();
    shabal512_context = new Shabal512();
    whirlpool_context = new Whirlpool();
    sha512_context = new SHA512();
    haval256_5_context = new HAVAL256_5();
  }

  private byte[] A;

  X17Core() {}

  private void doReset() {
    A = new byte[getDigestLength()];
  }

  @Override
  protected void processBlock(byte[] data) {
    blake512_context.update(data, 0, data.length);
    A = blake512_context.digest();

    bmw512_context.update(A, 0, 64);
    A = bmw512_context.digest();

    groestl512_context.update(A, 0, 64);
    A = groestl512_context.digest();

    skein512_context.update(A, 0, 64);
    A = skein512_context.digest();

    jh512_context.update(A, 0, 64);
    A = jh512_context.digest();

    keccak512_context.update(A, 0, 64);
    A = keccak512_context.digest();

    luffa512_context.update(A, 0, 64);
    A = luffa512_context.digest();

    cubehash512_conetxt.update(A, 0, 64);
    A = cubehash512_conetxt.digest();

    shavite512_context.update(A, 0, 64);
    A = shavite512_context.digest();

    simd512_context.update(A, 0, 64);
    A = simd512_context.digest();

    echo512_context.update(A, 0, 64);
    A = echo512_context.digest();

    hamsi512_context.update(A, 0, 64);
    A = hamsi512_context.digest();

    fugue512_context.update(A, 0, 64);
    A = fugue512_context.digest();

    shabal512_context.update(A, 0, 64);
    A = shabal512_context.digest();

    whirlpool_context.update(A, 0, 64);
    A = whirlpool_context.digest();

    sha512_context.update(A, 0, 64);
    A = sha512_context.digest();

    haval256_5_context.update(A, 0, 64);
    A = haval256_5_context.digest();

    A = reverse(A);
  }

  @Override
  protected void doPadding(byte[] out, int off) {
    int ptr = flush();
    byte[] buf = getBlockBuffer();
    if ((ptr + 1) != buf.length) {
      for (int i = ptr + 1; i < (buf.length - 1); i++) buf[i] = 0;
    }
    processBlock(buf);
    int dlen = getDigestLength();
    System.arraycopy(A, 0, out, off, dlen);
  }

  /** @see Digest */
  public int getBlockLength()
  {
    return 64;
  }

  @Override
  protected void engineReset() {
    doReset();
  }

  @Override
  protected void doInit() {

    doReset();
  }

  /** @see DigestEngine */
  protected Digest copyState(X17Core dst) {
    System.arraycopy(A, 0, dst.A, 0, 64);
    return super.copyState(dst);
  }
}
