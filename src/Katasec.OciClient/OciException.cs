namespace Katasec.OciClient;

public class OciException(string message, Exception? inner = null)
    : Exception(message, inner);

public class OciAuthException(string message) : OciException(message);
