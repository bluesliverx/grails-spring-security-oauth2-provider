package test.oauth2

class RefreshToken {

    byte[] authentication
    String value

    static constraints = {
        value nullable: false, blank: false, unique: true
        authentication nullable: false, minSize: 1, maxSize: 1024 * 4
    }

    static mapping = {
        version false
    }
}
