import java.io.*;

/**
 * @author pollux
 * @version 1.0.0
 * @date 2020/2/18 10:01 上午
 */
public class ModifyLibc {
    private static byte[] shellcode = new byte[]{
            (byte) 0xFF, 0x40, 0x2D, (byte) 0xE9,       //push {r0, r1, r2, r3, r4, r5, r6, r7, lr}
            0x18, 0x00, (byte) 0x9F, (byte) 0xE5,       //LDR R0,[PC,#24]	R0 = 0xC
            0x00, 0x10, (byte) 0xA0, (byte) 0xE3,       //MOV R1,#0
            0x00, 0x00, (byte) 0x8F, (byte) 0xE0,       //ADD R0,PC,R0
            0x01, (byte) 0xF7, (byte) 0xFF, (byte) 0xEB,//BL (dlopenAddr - PC)>>2 = (dlopenAddr - (asmAddr+0x18))>>2 dlopen("",0)
            (byte) 0xFF, 0x40, (byte) 0xBD, (byte) 0xE8,//LDMFD	SP!,{R0-R1,LR}
            0x08, 0x00, (byte) 0x9F, (byte) 0xE5,       //LDR R0,[PC,#8]
            0x00, 0x00, (byte) 0x8F, (byte) 0xE0,       //ADD R0,PC,R0
            0x10, (byte) 0xFF, 0x2F, (byte) 0xE1,       //BX R0
            (byte) 0x9C, 0x68, 0x03, 0x00,              //(soNameOff - injectOff - 5*4)
            0x09, (byte) 0xBF, 0x01, 0x00,              //(oldInitAddr - injectOff - 9*4)
            0x00, 0x00, 0x00, 0x00};                    //0x0

    private static int dlopenOff = 0xF3D0;
    private static int initarrayOff = 0x683C0 - 0x1000;
    private static int injectOff = 0x61DF0;
    private static int soNameOff = injectOff+0x50;  //0x69150


    public static void main(String[] args) {
        int oldInitAddr;//.init_array中的第一个函数指针

        try{
            File libc = new File("./libc.so");
            byte[] libcData = readByteFromFile(libc);
            byte[] soNameB = "libhook.so".getBytes();

            //------取原.init_array中的第一个函数指针内容
            byte[] initAddrB = new byte[4];
            System.arraycopy(libcData,initarrayOff,initAddrB,0,4);
            for(int i =0;i<2;i++){
                byte[] tmp = new byte[1];
                tmp[0] = initAddrB[i];
                initAddrB[i] = initAddrB[3-i];
                initAddrB[3-i] = tmp[0];
            }
            ByteArrayInputStream baisInitAddr = new ByteArrayInputStream(initAddrB);
            DataInputStream disInitAddr = new DataInputStream(baisInitAddr);
            oldInitAddr = disInitAddr.readInt();    //0x00011E65

            byte[] injectOffB = int2ByteLittleEndian(injectOff);
            System.arraycopy(injectOffB,0,libcData,initarrayOff,4);

            //------填充shellcode
            byte[] initarrayjumpOffB = int2ByteLittleEndian(oldInitAddr-injectOff-0x24);//shellcode中跳转原到init_array函数指针的偏移
            System.arraycopy(initarrayjumpOffB,0,shellcode,0x28,initarrayjumpOffB.length);

            byte[] soNameJumpOffB = int2ByteLittleEndian(soNameOff - injectOff - 0x14);//shellcode中so名的偏移
            System.arraycopy(soNameJumpOffB,0,shellcode,0x24,4);

            byte[] dlopenJumpOffB = int2ByteLittleEndian((dlopenOff - injectOff-0x18)>>2);
            System.arraycopy(dlopenJumpOffB,0,shellcode,0x10,3);
            //------填充shellcode完毕

            System.arraycopy(shellcode,0,libcData,injectOff,shellcode.length);
            System.arraycopy(soNameB,0,libcData,soNameOff,soNameB.length);//在libc中写入待加载的so名称

            File newLibcFile = new File("new_libc.so");
            if(!newLibcFile.exists()){
                newLibcFile.createNewFile();
            }
            FileOutputStream fileOutputStream = new FileOutputStream(newLibcFile);
            fileOutputStream.write(libcData);

            System.out.println("end end");
        }catch (IOException e){
            e.printStackTrace();
        }





    }


    private static byte[] readByteFromFile(File file) throws IOException {
        byte[] buf = new byte[104];
        int nums = 0;
        FileInputStream fileInputStream = new FileInputStream(file);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while (true) {
            nums = fileInputStream.read(buf);
            if (nums != -1) {
                byteArrayOutputStream.write(buf, 0, nums);
            } else {
                return byteArrayOutputStream.toByteArray();
            }
        }
    }

    private static byte[] int2Byte(int n) {
        byte[] buf = new byte[4];
        for (int i = 3; i >= 0; i--) {
            buf[i] = (byte) (n % 256);//256 = 0x100h
            n >>= 8;
        }
        return buf;
    }

    private static byte[] int2ByteLittleEndian(int n) {
        byte[] buf = new byte[4];
        for (int i = 0; i <4; i++) {
            buf[i] = (byte) (n % 256);//256 = 0x100h
            n >>= 8;
        }
        return buf;
    }

}
