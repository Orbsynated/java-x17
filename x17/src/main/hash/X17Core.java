package hash;

import crypto.*;

import static org.spongycastle.util.Arrays.reverse;

public abstract class X17Core extends DigestEngine {
  private final Digest bmw512_context;
  private final Digest groestl512_context;
  private final Digest skein512_context;
  private final Digest jh512_context;
  private final Digest keccak512_context;
  private final Digest luffa512_context;
  private final Digest cubehash512_conetxt;
  private final Digest shavite512_context;
  private final Digest simd512_context;
  private final Digest echo512_context;
  private final Digest hamsi512_context;
  private final Digest fugue512_context;
  private final Digest shabal512_context;
  private final Digest whirlpool_context;
  private final Digest sha512_context;
  private final Digest haval256_5_context;
  private Digest blake512_context;
  private byte[] tmpOutput;

  public X17Core() {
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

  private void doReset() {
    tmpOutput = new byte[getDigestLength()];
  }

  @Override
  protected void processBlock(byte[] data) {
    blake512_context.update(data, 0, data.length);
  }

  @Override
  public void update(byte[] input, int offset, int len) {
    byte[] inputBuf = new byte[len];
    System.arraycopy(input, offset, inputBuf, 0, len);
    blake512_context.update(inputBuf);
  }

  @Override
  public void update(byte input) {
    blake512_context.update(input);
  }

  @Override
  public void update(byte[] input) {
    blake512_context.update(input);
  }

  @Override
  protected void doPadding(byte[] out, int off) {

    tmpOutput = blake512_context.digest();

    bmw512_context.update(tmpOutput, 0, 64);
    tmpOutput = bmw512_context.digest();

    groestl512_context.update(tmpOutput, 0, 64);
    tmpOutput = groestl512_context.digest();

    skein512_context.update(tmpOutput, 0, 64);
    tmpOutput = skein512_context.digest();

    jh512_context.update(tmpOutput, 0, 64);
    tmpOutput = jh512_context.digest();

    keccak512_context.update(tmpOutput, 0, 64);
    tmpOutput = keccak512_context.digest();

    luffa512_context.update(tmpOutput, 0, 64);
    tmpOutput = luffa512_context.digest();

    cubehash512_conetxt.update(tmpOutput, 0, 64);
    tmpOutput = cubehash512_conetxt.digest();

    shavite512_context.update(tmpOutput, 0, 64);
    tmpOutput = shavite512_context.digest();

    simd512_context.update(tmpOutput, 0, 64);
    tmpOutput = simd512_context.digest();

    echo512_context.update(tmpOutput, 0, 64);
    tmpOutput = echo512_context.digest();

    hamsi512_context.update(tmpOutput, 0, 64);
    tmpOutput = hamsi512_context.digest();

    fugue512_context.update(tmpOutput, 0, 64);
    tmpOutput = fugue512_context.digest();

    shabal512_context.update(tmpOutput, 0, 64);
    tmpOutput = shabal512_context.digest();

    whirlpool_context.update(tmpOutput, 0, 64);
    tmpOutput = whirlpool_context.digest();

    sha512_context.update(tmpOutput, 0, 64);
    tmpOutput = sha512_context.digest();

    haval256_5_context.update(tmpOutput, 0, 64);
    tmpOutput = haval256_5_context.digest();

    // Result is reversed per testing
    tmpOutput = reverse(tmpOutput);

    System.arraycopy(tmpOutput, 0, out, off, getDigestLength());
  }

  /** @see Digest */
  public int getBlockLength() {
    // Block length doesn't matter because we relay on the other algorithms block length via the
    // 'update' function
    // Value set to 128 to be the same as most algorithms and to not break digest engine
    return 128;
  }

  @Override
  protected void engineReset() {
    doReset();
  }

  @Override
  protected void doInit() {
    doReset();
  }

  public String toString() {
    return "X17";
  }

  /** @see DigestEngine */
  protected Digest copyState(X17Core dst) {
    System.arraycopy(tmpOutput, 0, dst.tmpOutput, 0, 32);
    dst.tmpOutput = tmpOutput;
    dst.blake512_context = blake512_context.copy();
    return dst;
  }
}
