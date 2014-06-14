includeTargets << grailsScript('_GrailsBootstrap')
includeTargets << new File(springSecurityCorePluginDir, 'scripts/_S2Common.groovy')

USAGE = """
Usage: grails s2-init-oauth2-provider <package> <client> <authorization-code> <access-token> <refresh-token>

Creates OAuth2 client, authorization code, access token and refresh token domain classes in specified package

Example: grails s2-init-oauth2-provider com.yourapp Client AuthorizationCode AccessToken RefreshToken
"""

CONFIG_NOT_FOUND = """
Could not find Config.groovy
You must configure the domain classes in Config.groovy before the plugin will work properly
"""

SUCCESS = """
*******************************************************
* Created OAuth2-related domain classes. Your         *
* grails-app/conf/Config.groovy has been updated with *
* the class names of the configured domain classes;   *
* please verify that the values are correct.          *
*                                                     *
* Don't forget to update your security rules for the  *
* token and authorization endpoints!                  *
*******************************************************
"""

templateDir = "$springSecurityOauth2ProviderPluginDir/src/templates"

packageName = ''
clientClassName = ''
authorizationCodeClassName = ''
accessTokenClassName = ''
refreshTokenClassName = ''

target(s2InitOauth2Provider: "Creates artifacts for the Spring Security OAuth2 Provider plugin") {
    depends(checkVersion, configureProxy, packageApp, classpath, parseArguments)

    configure()
    createDomains()
    updateConfig()

    printMessage(SUCCESS)
}

private void configure() {
    (packageName, clientClassName, authorizationCodeClassName, accessTokenClassName, refreshTokenClassName) = parseArgs()

    templateAttributes = [
            packageName: packageName,
            OAuth2ClientClassName: clientClassName,
            OAuth2AuthorizationCodeClassName: authorizationCodeClassName,
            OAuth2AccessTokenClassName: accessTokenClassName,
            OAuth2RefreshTokenClassName: refreshTokenClassName
    ]
}

private parseArgs() {
    def args = argsMap.params

    if(args.size() != 5) {
        errorMessage USAGE
        System.exit(1)
    }

    printMessage "Creating Client class ${args[1]}, AuthorizationCode class ${args[2]}, AccessToken class ${args[3]}, RefreshToken class ${args[4]} in package ${args[0]}"
    return args
}

private void createDomains() {
    def dir = packageToDir(packageName)
    generateFile "$templateDir/OAuth2Client.groovy.template", "$appDir/domain/${dir}${clientClassName}.groovy"
    generateFile "$templateDir/OAuth2AuthorizationCode.groovy.template", "$appDir/domain/${dir}${authorizationCodeClassName}.groovy"
    generateFile "$templateDir/OAuth2AccessToken.groovy.template", "$appDir/domain/${dir}${accessTokenClassName}.groovy"
    generateFile "$templateDir/OAuth2RefreshToken.groovy.template", "$appDir/domain/${dir}${refreshTokenClassName}.groovy"

}

private void updateConfig() {
    def configFile = new File(appDir, 'conf/Config.groovy')
    if(!configFile.exists()) {
        errorMessage CONFIG_NOT_FOUND
        return
    }

    configFile.withWriterAppend { BufferedWriter writer ->
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

setDefaultTarget(s2InitOauth2Provider)
