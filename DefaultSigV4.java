import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class DefaultSig4 {

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
  
    private Map<String, String> credentials;

    public DefaultSig4(Map<String, String> credentials) {
        this.credentials = credentials;
    }

    public String sigUrl(String method, String scheme, String serviceName, String hostname, String path, String payload,
                         Map<String, List<String>> queryParams, String region) throws Exception {
      
        // you may change it, depends on your timezone
        String now = getTimeStamp(OffsetDateTime.now().minusHours(3));
        String today = getDate(OffsetDateTime.now());

        String algorithm = "AWS4-HMAC-SHA256";
        String signedHeaders = "host";

        String canonicalHeaders = "host:" + hostname.toLowerCase() + "\n";
        String credentialScope = today + "/" + region + "/" + serviceName + "/" + "aws4_request";

        final Map<String, List<String>> params = new HashMap<>();
        params.put("X-Amz-Algorithm", Arrays.asList(algorithm));
        params.put("X-Amz-Credential", Arrays.asList(URLEncoder.encode(credentials.get("accessKeyId") + "/" + credentialScope)));
        params.put("X-Amz-Date", Arrays.asList(now));
        params.put("X-Amz-Expires", Arrays.asList("500"));
        params.put("X-Amz-SignedHeaders", Arrays.asList("host"));


        queryParams.forEach((key, values) -> {
            String encodedKey = URLEncoder.encode(key);

            values.forEach(value -> {
                if (!params.containsKey(value)) {
                    params.put(encodedKey, new ArrayList(Arrays.asList()));
                }
                params.get(encodedKey).add(URLEncoder.encode(value));
            });
        });

        final StringBuilder canonicalQuerystring = new StringBuilder("");
        Map<String, List<String>> sortedParams = new TreeMap<>(params);

        sortedParams.forEach((key, values) -> {
            values.forEach(value -> {
                if (canonicalQuerystring.length() > 0) {
                    canonicalQuerystring.append("&");
                }
                canonicalQuerystring.append(key + "=" + value);
            });
        });

        String canonicalRequest = method + '\n' + path + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + generateHex(payload);
        String hashedCanonicalRequest = generateHex(canonicalRequest);
        String stringToSign = "AWS4-HMAC-SHA256\n" + now + '\n' + today + '/' + region + '/' + serviceName + "/aws4_request\n" + hashedCanonicalRequest;

        String signingKey = getSignatureKey(
                credentials.get("secretAccessKey"),
                today,
                region,
                serviceName
        ).toString();

        String signature = calculateSignature(stringToSign, credentials.get("secretAccessKey"), today, region, serviceName);

        String finalParams = canonicalQuerystring + "&X-Amz-Signature=" + signature;

        return scheme + "://" + hostname + path + "?" + finalParams;

    }

    /**
     * Gets the date string in yyyyMMdd format, which is required to build the
     * credential scope string
     *
     * @return the formatted date string
     */
    private String getDate(OffsetDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        String formatDateTime = dateTime.format(formatter);
        return formatDateTime;
    }
    /**
     * Gets the timestamp in YYYYMMDD'T'HHMMSS'Z' format, which is the required
     * format for AWS4 signing request headers and credential string
     *
     * @param dateTime
     *            an OffsetDateTime object representing the UTC time of current
     *            signing request
     * @return the formatted timestamp string
     *
     * @see <a href=
     *      "https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html">
     *      Examples of the Complete Version 4 Signing Process (Python)</a>
     */
    private String getTimeStamp(OffsetDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
        String formatDateTime = dateTime.format(formatter);
        return formatDateTime;
    }

    /**
     * Generate Hex code of String.
     *
     * @param data
     * @return
     */
    private String generateHex(String data) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data.getBytes("UTF-8"));
            byte[] digest = messageDigest.digest();
            return String.format("%064x", new java.math.BigInteger(1, digest));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generate AWS signature key.
     *
     * @param key
     * @param date
     * @param regionName
     * @param serviceName
     * @return
     * @throws Exception
     * @reference
     * http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-java
     */
    private byte[] getSignatureKey(String key, String date, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(kSecret, date);
        byte[] kRegion = HmacSHA256(kDate, regionName);
        byte[] kService = HmacSHA256(kRegion, serviceName);
        byte[] kSigning = HmacSHA256(kService, "aws4_request");

        return kSigning;
    }

    /**
     * Apply HmacSHA256 on data using given key.
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     * @reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-java
     */
    private byte[] HmacSHA256(byte[] key, String data) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    private String calculateSignature(String stringToSign, String secretAccessKey, String currentDate, String regionName, String serviceName) {
        try {
          
            byte[] signatureKey = getSignatureKey(secretAccessKey, currentDate, regionName, serviceName);
     
            byte[] signature = HmacSHA256(signatureKey, stringToSign);
            
            String strHexSignature = bytesToHex(signature);
          
            return strHexSignature;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Convert byte array to Hex
     *
     * @param bytes
     * @return
     */
    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }
}

