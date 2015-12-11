import grails.codegen.model.Model
import groovy.transform.Field

@Field String usageMessage = """
Usage: grails s2-init-oauth2-approval <package> <approval>

Creates OAuth2 approval domain class in specified package

Example: grails s2-init-oauth2-approval com.yourapp Approval
"""

description 'Creates artifacts to support approval store for the Spring Security OAuth2 Provider plugin', {

    usage usageMessage

    argument name: 'Domain class package',  description: 'The package to use for the Approval domain class',    required: false
    argument name: 'Approval class name',   description: 'The name of the Approval class',                      required: false
}

if(args.size() != 2) {
    error 'Usage:' + usageMessage
    return false
}

String packageName = args[0]
Model approvalModel = model(packageName + '.' + args[1])

addStatus "Creating Approval class '${approvalModel.simpleName}' in package '${packageName}'"

Map templateAttributes = [
        packageName: packageName,
        OAuth2ApprovalClassName: approvalModel.simpleName
]

render template('OAuth2Approval.groovy.template'),
        file("grails-app/domain/${approvalModel.packagePath}/${approvalModel.simpleName}.groovy"),
        templateAttributes, false

file('grails-app/conf/application.groovy').withWriterAppend { BufferedWriter writer ->
    writer.newLine()
    writer.newLine()
    writer.writeLine '// Added by the Spring Security OAuth2 Provider plugin:'
    writer.writeLine "grails.plugin.springsecurity.oauthProvider.approvalLookup.className = '${packageName}.${approvalModel.simpleName}'"
    writer.newLine()
}

addStatus '''
************************************************************
* Created OAuth2 approval domain class. Your               *
* grails-app/conf/application.groovy has been updated with *
* the class name of the configured domain class;           *
* please verify that the value is correct.                 *
*                                                          *
* Don't forget to update your Config.groovy to select the  *
* user approval method you want to use!                    *
************************************************************
'''
