import java.io.File;

public class SM2ForBlockChain {
    public native String stringMethod(String text);
    public native String GenPrivateKey();
    public native String GetPublicKeyByPriv(String privKeyHex);
    //public native String GetPublicKeyByPriv_bin(byte[] privKeyBytes);
    public native String Sign(String privKeyHex, byte[] src, int srcLen);
    public native boolean Verify(String pubKeyHex, String signatureHex, byte[] src, int srcLen);
    public native String SM2Error();

	static {
	    try{
            if (System.getProperty("os.name").contains("Windows")){
                System.load("D:\\mine\\src\\github.com\\GmSSL\\blockchain\\libs\\libcrypto-1_1-x64.dll");
            }
            System.loadLibrary("sm2jni");   
        }catch (Exception ignored){
        }
	}

    // set .dll/.so load path before init class
    public static void LoadLibrary(String dllDir){
	    String dllFilePath;
	    if (System.getProperty("os.name").contains("Windows")){
            dllFilePath = new File(dllDir, "libcrypto-1_1-x64.dll").getAbsolutePath();
        }else {
            //linux(xxx.a)
            dllFilePath = new File(dllDir, "libcrypto-1_1-x64.so").getAbsolutePath();
        }
        System.load(dllFilePath);
        System.loadLibrary("sm2jni");
    }

    public static void main(String[] args){

        SM2ForBlockChain sm2 = new SM2ForBlockChain();

        String text = sm2.stringMethod("Java");
        System.out.println("stringMethod: " + text);

        byte[] src = "testdata".getBytes();
        // create key
        String priv = sm2.GenPrivateKey();
        String pub = sm2.GetPublicKeyByPriv(priv);
        System.out.printf("GenPrivateKey: %s\nPublicKey:%s\n", priv, pub);

        // sign&verify
        String signature = sm2.Sign(priv, src, src.length);
        boolean isValid = sm2.Verify(pub, signature, src, src.length);
        if (!isValid){
            throw new RuntimeException("Verify failed");
        }
        System.out.println("Verify success");
    }
}