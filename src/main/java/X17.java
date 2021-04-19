import crypto.*;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;
import utils.Sha512Hash;

import java.nio.charset.StandardCharsets;

import static utils.ByteArrayUtils.*;

public class X17 {
    private final Digest blake512_context;
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
    public X17(){
        blake512_context = new BLAKE512();
        bmw512_context = new BMW512();
        groestl512_context = new Groestl512();
        skein512_context = new Skein512();
        jh512_context = new JH512();
        keccak512_context  = new Keccak512();
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
    public byte[] HashX17(byte[] input){
        blake512_context.update(input, 0, input.length);
        input = blake512_context.digest();
        bmw512_context.update(input, 0, 64);
        input = bmw512_context.digest();
        groestl512_context.update(input, 0, 64);
        input = groestl512_context.digest();
        skein512_context.update(input, 0, 64);
        input = skein512_context.digest();
        jh512_context.update(input, 0, 64);
        input = jh512_context.digest();

        keccak512_context.update(input, 0, 64);
        input = keccak512_context.digest();

        luffa512_context.update(input, 0, 64);
        input = luffa512_context.digest();

        cubehash512_conetxt.update(input, 0, 64);
        input = cubehash512_conetxt.digest();

        shavite512_context.update(input, 0, 64);
        input = shavite512_context.digest();

        simd512_context.update(input, 0, 64);
        input = simd512_context.digest();

        echo512_context.update(input, 0, 64);
        input = echo512_context.digest();

        hamsi512_context.update(input, 0, 64);
        input = hamsi512_context.digest();

        fugue512_context.update(input, 0, 64);
        input = fugue512_context.digest();

        shabal512_context.update(input, 0, 64);
        input = shabal512_context.digest();

        whirlpool_context.update(input, 0, 64);
        input = whirlpool_context.digest();

        sha512_context.update(input, 0, 64);
        input = sha512_context.digest();

        haval256_5_context.update(input, 0, 64);
        input = haval256_5_context.digest();

        input = Arrays.reverse(input);

        return trim256(input);
    }

  public static void main(String[] args) {

  }

}
