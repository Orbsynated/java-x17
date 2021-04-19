import crypto.*;

public class X17 {
    BLAKE512 blake512_context;
    BMW512 bmw512_context;
    Groestl512 groestl512_context;
    Skein512 skein512_context;
    JH512 jh512_context;
    Keccak512 keccak512_context;
    Luffa512 luffa512_context;
    CubeHash512 cubehash512_conetxt;
    SHAvite512 shavite512_context;
    SIMD512 simd512_context;
    ECHO512 echo512_context;
    Hamsi512 hamsi512_context;
    Fugue512 fugue512_context;
    Shabal512 shabal512_context;
    Whirlpool whirlpool_context;
    SHA512 sha512_context;
    HAVAL256_5 haval256_5_context;
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
    public void HashX17(byte[] input){
        byte[][] hashs = new byte[16][64];

        blake512_context.digest(input, 0, 80);



    }
}
