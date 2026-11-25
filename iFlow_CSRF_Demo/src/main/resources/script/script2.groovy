import com.sap.gateway.ip.core.customdev.util.Message
def Message processData(Message message) {
    def token = message.getHeader("x-csrf-token", String.class)
    if (!token) {
        token = message.getHeader("X-CSRF-Token", String.class)
    }
    def cookieHeader = ""
    def headers = message.getHeaders()
    headers.each { k, v ->
        if (k.toString().equalsIgnoreCase("Set-Cookie")) {
            if (v instanceof List) {
                v.each { c -> cookieHeader += c.toString() + "; " }
            } else {
                cookieHeader += v.toString() + "; "
            }
        }
    }
    if (!token) {
        throw new RuntimeException("No CSRF token found in response headers")
    }
    def expiry = new Date().getTime() + (50 * 60 * 1000)
    // Force real String - avoid GString persistence issue
    def json = ("{\"token\":\"" + token + "\",\"cookie\":\"" + cookieHeader.trim() + "\",\"expiry\":" + expiry + "}").toString()
    message.setBody(json)
    message.setHeader("Content-Type", "application/json")
    
    message.setHeader("X-CSRF-Token", token)
    message.setHeader("Cookie", cookieHeader)
    return message
}