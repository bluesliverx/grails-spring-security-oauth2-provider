package test.oauth2

import grails.test.mixin.TestFor
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(UserApproval)
class UserApprovalSpec extends Specification {

    @Unroll
    void "property [#key] with value [#value] is valid [#valid]"() {
        when:
        def approval = new UserApproval((key): value)

        then:
        approval.validate([key]) == valid

        where:
        key             |   value       |   valid
        'username'      |   null        |   false
        'username'      |   ''          |   false
        'username'      |   'user'      |   true

        'clientId'      |   null        |   false
        'clientId'      |   ''          |   false
        'clientId'      |   'client'    |   true

        'scope'         |   null        |   false
        'scope'         |   ''          |   false
        'scope'         |   'read'      |   true

        'expiration'    |   null        |   false
        'expiration'    |   new Date()  |   true

        'lastModified'  |   null        |   false
        'lastModified'  |   new Date()  |   true
    }
}
