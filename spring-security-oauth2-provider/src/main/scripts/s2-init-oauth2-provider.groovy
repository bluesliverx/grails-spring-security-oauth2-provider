import grails.codegen.model.Model
import groovy.transform.Field

@Field String usageMessage = """
Usage: grails s2-init-oauth2-provider <package> <client> <authorization-code> <access-token> <refresh-token>

Creates OAuth2 client, authorization code, access token and refresh token domain classes in specified package

Example: grails s2-init-oauth2-provider com.yourapp Client AuthorizationCode AccessToken RefreshToken
"""

@Field Map templateAttributes
@Field boolean uiOnly

description 'Creates artifacts for the Spring Security OAuth2 Provider plugin', {

    usage usageMessage

    argument name: 'Domain class package',          description: 'The package to use for the domain classes',   required: false
    argument name: 'Client class name',             description: 'The name of the Client class',                required: false
    argument name: 'AuthorizationCode class name',  description: 'The name of the AuthorizationCode class',     required: false
    argument name: 'AccessToken class name',        description: 'The name of the AccessToken class',           required: false
    argument name: 'RefreshToken class name',       description: 'The name of the RefreshToken class',          required: false

    flag name: 'uiOnly', description: 'If specified, no domain classes are created but the plugin settings are initialized'
}

Model clientModel
Model authorizationCodeModel
Model accessTokenModel
Model refreshTokenModel

uiOnly = flag('uiOnly')
if (uiOnly) {
    addStatus '\nConfiguring Spring Security OAuth2 Provider; not generating domain classes'
}
else {
    if (args.size() != 5) {
        error 'Usage:' + usageMessage
        return false
    }

    String packageName = args[0]

    clientModel = model(packageName + '.' + args[1])
    authorizationCodeModel = model(packageName + '.' + args[2])
    accessTokenModel = model(packageName + '.' + args[3])
    refreshTokenModel = model(packageName + '.' + args[4])

    addStatus "Creating Client class '${clientModel.simpleName}', " +
              "AuthorizationCode class '${authorizationCodeModel.simpleName}', " +
              "AccessToken class '${accessTokenModel.simpleName}', " +
              "RefreshToken class '${refreshTokenModel.simpleName}' " +
              "in package '${packageName}'"

    templateAttributes = [
            packageName: packageName,
            OAuth2ClientClassName: clientModel.simpleName,
            OAuth2AuthorizationCodeClassName: authorizationCodeModel.simpleName,
            OAuth2AccessTokenClassName: accessTokenModel.simpleName,
            OAuth2RefreshTokenClassName: refreshTokenModel.simpleName,
    ]

    createDomains clientModel, authorizationCodeModel, accessTokenModel, refreshTokenModel
}

updateConfig clientModel?.simpleName, authorizationCodeModel?.simpleName, accessTokenModel?.simpleName, refreshTokenModel?.simpleName, clientModel?.packageName

if (uiOnly) {
    addStatus '''
************************************************************
* Your grails-app/conf/application.groovy has been updated *
* with security settings; please verify that the           *
* values are correct.                                      *
************************************************************
'''
}
else {
    addStatus '''
************************************************************
* Created OAuth2-related domain classes. Your              *
* grails-app/conf/application.groovy has been updated with *
* the class names of the configured domain classes;        *
* please verify that the values are correct.               *
************************************************************
'''
}

addStatus '''
************************************************************
* Don't forget to update your security rules for the token *
* and authorization endpoints!                             *
************************************************************
'''

private void createDomains(Model clientModel, Model authorizationCodeModel, Model accessTokenModel, Model refreshTokenModel) {

    generateFile 'OAuth2Client', clientModel.packagePath, clientModel.simpleName
    generateFile 'OAuth2AuthorizationCode', authorizationCodeModel.packagePath, authorizationCodeModel.simpleName

    generateFile 'OAuth2AccessToken', accessTokenModel.packagePath, accessTokenModel.simpleName
    generateFile 'OAuth2RefreshToken', refreshTokenModel.packagePath, refreshTokenModel.simpleName
}

private void updateConfig(String clientClassName, String authorizationCodeClassName,
                          String accessTokenClassName, String refreshTokenClassName, String packageName) {

    file('grails-app/conf/application.groovy').withWriterAppend { BufferedWriter writer ->
        writer.newLine()
        writer.newLine()
        writer.writeLine '// Added by the Spring Security OAuth2 Provider plugin:'
        writer.writeLine "grails.plugin.springsecurity.oauthProvider.clientLookup.className = '${packageName}.$clientClassName'"
        writer.writeLine "grails.plugin.springsecurity.oauthProvider.authorizationCodeLookup.className = '${packageName}.$authorizationCodeClassName'"
        writer.writeLine "grails.plugin.springsecurity.oauthProvider.accessTokenLookup.className = '${packageName}.$accessTokenClassName'"
        writer.writeLine "grails.plugin.springsecurity.oauthProvider.refreshTokenLookup.className = '${packageName}.$refreshTokenClassName'"
        writer.newLine()
    }
}

private void generateFile(String templateName, String packagePath, String className) {
    render template(templateName + '.groovy.template'),
            file("grails-app/domain/$packagePath/${className}.groovy"),
            templateAttributes, false
}
