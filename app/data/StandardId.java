package data;

public class StandardId {
    public StandardId(){}
    public StandardId(String scheme, String value)
    {
        this.scheme = scheme;
        this.value = value;
    }

    public String scheme;
    public String value;
}