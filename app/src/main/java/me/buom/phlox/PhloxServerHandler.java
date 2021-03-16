package me.buom.phlox;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.IO;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.spec.KeySpec;
import java.util.Base64;

import static javax.servlet.http.HttpServletResponse.SC_METHOD_NOT_ALLOWED;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static me.buom.phlox.PhloxServer.SECRET;
import static me.buom.phlox.PhloxServer.SALT;

public class PhloxServerHandler extends AbstractHandler {

    static final String ALGO_NAME = "AES/GCM/NoPadding";
    private final SecretKeySpec secret;
    private final byte[] iv;

    private final Charset charset = Charset.defaultCharset();
    private final Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getDecoder();

    private final BCrypt.Hasher bcrypt;
    private final byte[] salt;

    public PhloxServerHandler() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        KeySpec key = new PBEKeySpec(SECRET.toCharArray(), SALT.getBytes(charset), 65556, 256);
        secret = new SecretKeySpec(factory.generateSecret(key).getEncoded(), "AES");

        key = new PBEKeySpec(SECRET.toCharArray(), SALT.getBytes(charset), 41556, 16);
        iv = factory.generateSecret(key).getEncoded();

        key = new PBEKeySpec(SECRET.toCharArray(), SALT.getBytes(charset), 31556, 128);
        salt = factory.generateSecret(key).getEncoded();

        bcrypt = BCrypt.with(LongPasswordStrategies.hashSha512(BCrypt.Version.VERSION_2A));
    }

    @Override
    public void handle(String target,
                       Request baseRequest,
                       HttpServletRequest request,
                       HttpServletResponse response)
            throws IOException
    {
        if ("POST".equals(request.getMethod())) {
            if ("/encrypt".equals(target)) {
                byte[] src = IO.readBytes(request.getInputStream());
                response.setCharacterEncoding(charset.name());
                response.getWriter().print(encrypt(src));
            } else if ("/decrypt".equals(target)) {
                byte[] src = IO.readBytes(request.getInputStream());
                response.setCharacterEncoding(charset.name());
                response.getWriter().print(decrypt(src));
            } else if ("/hash".equals(target)) {
                byte[] src = IO.readBytes(request.getInputStream());
                response.setCharacterEncoding(charset.name());
                response.getWriter().print(hash(src));
            } else {
                response.setStatus(SC_NOT_FOUND);
            }
        } else {
            response.setStatus(SC_METHOD_NOT_ALLOWED);
        }
        baseRequest.setHandled(true);
    }


    private String encrypt(final byte[] src) {
        try {
            Cipher cipher = Cipher.getInstance(ALGO_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(128, iv));

            return encoder.encodeToString(cipher.doFinal(src));
        } catch (Exception x) {
            x.printStackTrace();
        }

        return null;
    }

    private String decrypt(final byte[] src) {
        try {
            Cipher cipher = Cipher.getInstance(ALGO_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(128, iv));
            byte[] original = cipher.doFinal(decoder.decode(src));

            return new String(original);
        } catch (Exception x) {
            x.printStackTrace();
        }

        return null;
    }

    private String hash(final byte[] src) {
        try {
            return new String(bcrypt.hash(6, salt, src), charset);
        } catch (Exception x) {
            x.printStackTrace();
        }

        return null;
    }
}
