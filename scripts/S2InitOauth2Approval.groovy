includeTargets << grailsScript('_GrailsBootstrap')
includeTargets << new File(springSecurityCorePluginDir, 'scripts/_S2Common.groovy')

USAGE = """
Usage: grails s2-init-oauth2-approval <package> <approval>

Creates OAuth2 approval domain class in specified package

Example: grails s2-init-oauth2-approval com.yourapp Approval
"""

CONFIG_NOT_FOUND = """
Could not find Config.groovy
You must configure the domain class in Config.groovy before the approval store will work properly
"""

SUCCESS = """
*******************************************************
* Created OAuth2 approval domain class. Your          *
* grails-app/conf/Config.groovy has been updated with *
* the class name of the configured domain class;      *
* please verify that the value is correct.            *
*                                                     *
* Don't forget to update your Config.groovy to select *
* the user approval method you want to use!           *
*******************************************************
"""

templateDir = "$springSecurityOauth2ProviderPluginDir/src/templates"

packageName = ''
approvalClassName = ''

target(s2InitOauth2Approval: "Creates artifacts to support approval store for the Spring Security OAuth2 Provider plugin") {
    depends(checkVersion, configureProxy, packageApp, classpath, parseArguments)

    configure()
    createDomains()
    updateConfig()

    printMessage(SUCCESS)
}

private void configure() {
    (packageName, approvalClassName) = parseArgs()

    templateAttributes = [
            packageName: packageName,
            OAuth2ApprovalClassName: approvalClassName
    ]
}

private parseArgs() {
    def args = argsMap.params

    if(args.size() != 2) {
        errorMessage USAGE
        System.exit(1)
    }

    printMessage "Creating Approval class ${args[1]} in package ${args[0]}"
    return args
}

private void createDomains() {
    def dir = packageToDir(packageName)
    generateFile "$templateDir/OAuth2Approval.groovy.template", "$appDir/domain/${dir}${approvalClassName}.groovy"
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
        writer.writeLine "grails.plugin.springsecurity.oauthProvider.approvalLookup.className = '${packageName}.$approvalClassName'"
        writer.newLine()
    }
}

setDefaultTarget(s2InitOauth2Approval)
